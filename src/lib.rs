use hex;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use worker::*;
mod utils;
use std::collections::HashMap;

// Structs and Enums
#[derive(Deserialize, Debug, Serialize)]
struct SlackApiResponse {
    hashed_secret: String,
    slack_id: String,
    eligibility: YSWSStatus,
    username: String,
}

#[derive(Deserialize, Debug, Serialize)]
struct GitHubApiResponse {
    name: String,
    id: String,
}

#[derive(Serialize)]
struct APIResponse {
    Slack: Option<SlackApiResponse>,
    GitHub: Option<GitHubApiResponse>,
    hashed_secret: String,
}

#[derive(Deserialize, Debug)]
struct APIRequest {
    slack_code: Option<String>,
    github_code: Option<String>,
}

struct SlackOauth {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

struct GithubOauth {
    client_id: String,
    client_secret: String,
    redirect_uri: Option<Url>,
}

#[derive(Deserialize, Debug, Serialize)]
pub enum YSWSStatus {
    EligibleL1,
    EligibleL2,
    Ineligible,
    Insufficient,
    SanctionedCountry,
    Testing,
    Unknown,
}

impl std::fmt::Display for YSWSStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            YSWSStatus::EligibleL1 => write!(f, "Eligible L1"),
            YSWSStatus::EligibleL2 => write!(f, "Eligible L2"),
            YSWSStatus::Ineligible => write!(f, "Ineligible"),
            YSWSStatus::Insufficient => write!(f, "Insufficient"),
            YSWSStatus::SanctionedCountry => write!(f, "Sanctioned Country"),
            YSWSStatus::Testing => write!(f, "Testing"),
            YSWSStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

fn add_cors_headers(mut response: Response) -> Result<Response> {
    response
        .headers_mut()
        .append("Access-Control-Allow-Origin", "*")?;
    response.headers_mut().append(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, OPTIONS",
    )?;
    response.headers_mut().append(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
    )?;
    Ok(response)
}

// Fetch Event Handler
#[event(fetch)]
pub async fn main(mut req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    // Set panic hook for Cloudflare
    utils::set_panic_hook();

    console_log!("Request: {:?}", req);

    let slack_oauth = SlackOauth {
        client_id: env.var("SLACK_CLIENT_ID")?.to_string(),
        client_secret: env.var("SLACK_CLIENT_SECRET")?.to_string(),
        redirect_uri: env.var("SLACK_REDIRECT_URI").unwrap().to_string(),
    };

    console_log!("slackredirecturi: {}", slack_oauth.redirect_uri);

    let github_oauth = GithubOauth {
        client_id: env.var("GITHUB_CLIENT_ID")?.to_string(),
        client_secret: env.var("GITHUB_CLIENT_SECRET")?.to_string(),
        redirect_uri: env
            .var("GITHUB_REDIRECT_URI")
            .ok()
            .and_then(|url| Url::try_from(url.to_string().as_str()).ok()),
    };

    let jasper_api = env.var("JASPER_API")?.to_string();

    if req.method() == Method::Options {
        let mut response = Response::empty()?;
        response = add_cors_headers(response)?;
        return Ok(response);
    }

    // Match request path to handle routing manually
    match req.path().as_str() {
        "/api" => {
            if req.method() == Method::Post {
                let api_request: APIRequest = match req.json().await {
                    Ok(body) => body,
                    Err(_) => return Response::error("Bad Request", 400),
                };
                return handle_api_request(api_request, slack_oauth, github_oauth).await;
            } else {
                return Response::error("Method Not Allowed", 405);
            }
        }
        "/verify_records" => {
            if req.method() != Method::Put {
                return Response::error("Method Not Allowed", 405);
            }

            console_debug!("Trying to fetch records...");

            let records = match get_records(&env).await {
                Ok(records) => records,
                Err(e) => return Response::error(format!("Error fetching records: {}", e), 500),
            };

            if !records.is_empty() {
                console_log!("Fetched {} records.", records.len());
                verify_all_hash(records, slack_oauth, github_oauth, jasper_api).await;
                return Response::ok("Records verified");
            } else {
                return Response::ok("No records to verify");
            }
        }
        _ => {
            if !(req.url().unwrap().to_string().contains("?code")) {
                return Response::error("Not Found", 404);
            }

            console_log!("Request recieved at root");
            let url = req.url().unwrap();
            let params: QueryParams =
                serde_qs::from_str(url.query().ok_or("Missing query params")?).unwrap();
            let slack_stuff = handle_slack_oauth(params.code, slack_oauth).await.unwrap();

            let mut url = Url::parse("https://forms.hackclub.com/t/9yNy4WYtrZus").unwrap();
            url.query_pairs_mut()
                .append_pair("secret", &slack_stuff.hashed_secret)
                .append_pair("slack_id", &slack_stuff.slack_id)
                .append_pair("eligibility", &slack_stuff.eligibility.to_string())
                .append_pair("slack_user", &slack_stuff.username);

            console_log!("Redirecting to {}", url);
            Response::redirect_with_status(url, 302)
        }
    }
}

#[derive(Deserialize)]
struct QueryParams {
    code: String,
    state: Option<String>,
}

// Handle API Request (Slack and GitHub)
async fn handle_api_request(
    payload: APIRequest,
    slack_oauth: SlackOauth,
    github_oauth: GithubOauth,
) -> Result<Response> {
    let mut temp_response = APIResponse {
        Slack: None,
        GitHub: None,
        hashed_secret: String::new(),
    };

    let mut slack_id = String::new();
    let mut slack_username = String::new();
    let mut github_id = String::new();
    let mut github_name = String::new();

    if let Some(slack_code) = payload.slack_code {
        match handle_slack_oauth(slack_code, slack_oauth).await {
            Ok(auth) => {
                slack_id = auth.slack_id.clone();
                slack_username = auth.username.clone();
                temp_response.Slack = Some(auth);
            }
            Err(e) => {
                console_log!("Slack OAuth Error: {}", e);
                temp_response.Slack = None;
            }
        }
    }

    if let Some(github_code) = payload.github_code {
        match handle_github_oauth(
            github_code,
            &github_oauth.client_id,
            &github_oauth.client_secret,
        )
        .await
        {
            Ok(auth) => {
                github_id = auth.id.clone();
                github_name = auth.name.clone();
                temp_response.GitHub = Some(auth);
            }
            Err(e) => {
                console_log!("GitHub OAuth Error: {}", e);
            }
        }
    }

    if !slack_id.is_empty() && !github_id.is_empty() {
        let combined_secret = format!("{}{}{}{}", slack_id, slack_username, github_id, github_name);
        temp_response.hashed_secret = hash_secret(&combined_secret);
    }

    let response = Response::from_json(&temp_response).unwrap();
    Ok(add_cors_headers(response)?)
}

async fn handle_github_oauth(
    code: String,
    client_id: &str,
    client_secret: &str,
) -> Result<GitHubApiResponse> {
    console_log!("Starting GitHub OAuth process");

    let client = Client::new();

    // Exchange code for access token
    console_log!("Exchanging code for access token");
    let token_response = client
        .post("https://github.com/login/oauth/access_token")
        .header(CONTENT_TYPE, "application/json")
        .json(&json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
        }))
        .send()
        .await
        .map_err(|e| {
            console_log!("Request error during token exchange: {}", e);
            format!("Request error: {}", e)
        })?;

    console_log!("Received token response");

    let token_text = token_response.text().await.map_err(|e| {
        console_log!("Error reading token response text: {}", e);
        format!("Error reading token response text: {}", e)
    })?;

    console_log!("Token response text: {}", token_text);

    // Parse URL-encoded response
    let token_params: HashMap<String, String> = url::form_urlencoded::parse(token_text.as_bytes())
        .into_owned()
        .collect();

    console_log!("Parsed token parameters: {:?}", token_params);

    let access_token = token_params.get("access_token").ok_or_else(|| {
        console_log!("Missing access token in response");
        "Missing access token".to_string()
    })?;

    console_log!("Access token received: {}", access_token);

    // Fetch user profile information
    console_log!("Fetching user profile information");
    let user_response = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("token {}", access_token))
        .header("User-Agent", "request")
        .send()
        .await
        .map_err(|e| {
            console_log!("Request error during user profile fetch: {}", e);
            format!("Request error: {}", e)
        })?;

    console_log!("Received user profile response");

    let user_info: serde_json::Value = user_response.json().await.map_err(|e| {
        console_log!("Parsing error during user profile response: {}", e);
        format!("Parsing error: {}", e)
    })?;

    console_log!("Parsed user profile response: {:?}", user_info);

    let username = user_info["login"]
        .as_str()
        .ok_or_else(|| {
            console_log!("Missing username in user profile response");
            "Missing username".to_string()
        })?
        .to_string();

    let name = user_info["name"]
        .as_str()
        .unwrap_or("Unknown User")
        .to_string();

    console_log!("GitHub OAuth process completed successfully");

    Ok(GitHubApiResponse { name, id: username })
}

// OAuth Slack Function
async fn handle_slack_oauth(code: String, slack_oauth: SlackOauth) -> Result<SlackApiResponse> {
    let auth = exchange_code_for_token(
        &slack_oauth.client_id,
        &slack_oauth.client_secret,
        &code,
        &slack_oauth.redirect_uri,
    )
    .await?;

    let username = user_identity(&auth.authed_user.access_token).await?;

    let ysws_status = ysws_api(&auth).await?;

    Ok(SlackApiResponse {
        hashed_secret: hash_secret(&format!(
            "{}{}{}{}",
            auth.authed_user.id, username, ysws_status, slack_oauth.client_secret
        )),
        slack_id: auth.authed_user.id,
        eligibility: ysws_status,
        username,
    })
}

// Fetch OAuth token from Slack
async fn exchange_code_for_token(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuthResponse> {
    let client = Client::new();
    let response = client
        .post("https://slack.com/api/oauth.v2.access")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;

    let auth_response: OAuthResponse = response
        .json()
        .await
        .map_err(|e| format!("Parsing error: {}", e))?;
    Ok(auth_response)
}

// YSWS API call
async fn ysws_api(user: &OAuthResponse) -> Result<YSWSStatus> {
    let client = Client::new();
    let url = "https://verify.hackclub.dev/api/status";
    let json_body = json!({ "slack_id": user.authed_user.id });
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let response = client
        .post(url)
        .headers(headers)
        .json(&json_body)
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;

    let response_text = response
        .text()
        .await
        .map_err(|e| format!("Text error: {}", e))?;

    console_log!("Response: {}", response_text);
    if response_text.contains("Eligible L1") {
        Ok(YSWSStatus::EligibleL1)
    } else if response_text.contains("Eligible L2") {
        Ok(YSWSStatus::EligibleL2)
    } else if response_text.contains("Ineligible") {
        Ok(YSWSStatus::Ineligible)
    } else if response_text.contains("Insufficient") {
        Ok(YSWSStatus::Insufficient)
    } else if response_text.contains("Sanctioned Country") {
        Ok(YSWSStatus::SanctionedCountry)
    } else if response_text.contains("Testing") {
        Ok(YSWSStatus::Testing)
    } else {
        Ok(YSWSStatus::Unknown)
    }
}

// Fetch user identity from Slack API
async fn user_identity(access_token: &str) -> Result<String> {
    let client = Client::new();
    let url = "https://slack.com/api/openid.connect.userInfo";

    let response = client
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;
    let user_info: UserInfo = response
        .json()
        .await
        .map_err(|e| format!("Parsing error: {}", e))?;

    Ok(user_info.name)
}

// Helper function to hash the secret
fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(secret);
    hex::encode(hasher.finalize())
}

// Structs and Deserializers
#[derive(Deserialize, Debug)]
struct OAuthResponse {
    ok: bool,
    access_token: Option<String>,
    authed_user: User,
}

#[derive(Deserialize, Debug)]
struct User {
    id: String,
    access_token: String,
}

#[derive(Deserialize, Debug)]
struct UserInfo {
    ok: bool,
    name: String,
    email: String,
}

struct Enviornment {
    slack_client_id: String,
    slack_client_secret: String,
    slack_redirect_uri: String,
}

async fn get_records(env: &Env) -> Result<Vec<Record>> {
    let client = Client::new();
    let url = "http://hackclub-ysws-api.jasperworkers.workers.dev/submissions";

    let jasper_api = env
        .var("JASPER_API")
        .map_err(|_| "Jasper API not set".to_string())?
        .to_string();

    let response = client
        .get(url)
        .bearer_auth(jasper_api)
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;

    let response_values: Vec<Value> = response
        .json()
        .await
        .map_err(|e| format!("Parsing error: {}", e))?;
    let mut records = Vec::new();

    for value in response_values {
        match serde_json::from_value::<Record>(value.clone()) {
            Ok(record) => records.push(record),
            Err(e) => {
                console_log!("Skipping invalid record: {}", e);
            }
        }
    }

    Ok(records)
}

#[derive(Deserialize, Debug)]
struct Record {
    id: String,
    #[serde(rename = "createdTime")]
    created_time: String,
    fields: Fields,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Fields {
    eligibility: String,
    #[serde(rename = "OTP")]
    otp: String,
    #[serde(rename = "Slack ID")]
    slack_id: String,
    #[serde(rename = "SlackUsername")]
    slack_username: String,
}

async fn verify_all_hash(
    records: Vec<Record>,
    slack_oauth: SlackOauth,
    github_oauth: GithubOauth,
    jasper_api: String,
) {
    console_log!("Looking into {} records", records.len());

    for record in records {
        let otp_secret = record.fields.otp;
        let eligibility = record.fields.eligibility;
        let slack_id = record.fields.slack_id;
        let slack_username = record.fields.slack_username;

        let secret =
            slack_id + &slack_username + &eligibility + &slack_oauth.client_secret.to_string();

        let hashed_secret = hash_secret(&secret);

        let client = Client::new();
        let url: Url =
            Url::parse("http://hackclub-ysws-api.jasperworkers.workers.dev/update").unwrap();
        let bearer_token = &jasper_api;

        if hashed_secret == otp_secret {
            let json_body = json!({
                "recordId": record.id,
                "authenticated": "true",
            });

            let response = client
                .post(url)
                .bearer_auth(bearer_token)
                .json(&json_body)
                .send()
                .await
                .unwrap();

            if response.status().is_success() {
                console_log!("Request successful");
            } else {
                console_log!("Request failed with status: {}", response.status());
            }
        } else {
            console_warn!("OTP mismatch");

            let json_body = json!({
                "recordId": record.id,
                "authenticated": "false",
            });

            let response = client
                .post(url)
                .bearer_auth(bearer_token)
                .json(&json_body)
                .send()
                .await
                .unwrap();

            if response.status().is_success() {
                console_log!("Request successful");
            } else {
                console_log!("Request failed with status: {}", response.status());
            }
        }
    }
}
