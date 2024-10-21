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

// Constants
const SLACK_OAUTH_URL: &str = "https://slack.com/api/oauth.v2.access";
const GITHUB_OAUTH_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL: &str = "https://api.github.com/user";
const YSWS_API_URL: &str = "https://verify.hackclub.dev/api/status";
const RECORDS_API_URL: &str = "http://hackclub-ysws-api.jasperworkers.workers.dev/submissions";
const UPDATE_API_URL: &str = "http://hackclub-ysws-api.jasperworkers.workers.dev/update";

// Structs and Enums
#[derive(Deserialize, Debug, Serialize)]
struct SlackApiResponse {
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
    slack: Option<SlackApiResponse>,
    github: Option<GitHubApiResponse>,
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
            YSWSStatus::EligibleL1 => write!(f, "EligibleL1"),
            YSWSStatus::EligibleL2 => write!(f, "EligibleL2"),
            YSWSStatus::Ineligible => write!(f, "Ineligible"),
            YSWSStatus::Insufficient => write!(f, "Insufficient"),
            YSWSStatus::SanctionedCountry => write!(f, "SanctionedCountry"),
            YSWSStatus::Testing => write!(f, "Testing"),
            YSWSStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

fn add_cors_headers(mut response: Response) -> Result<Response> {
    let headers = response.headers_mut();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, OPTIONS",
    )?;
    headers.set(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
    )?;
    Ok(response)
}

// Fetch Event Handler
#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    utils::set_panic_hook();
    console_log!("Received request from {}", req.url()?);

    let slack_oauth = SlackOauth {
        client_id: env.var("SLACK_CLIENT_ID")?.to_string(),
        client_secret: env.var("SLACK_CLIENT_SECRET")?.to_string(),
        redirect_uri: env.var("SLACK_REDIRECT_URI")?.to_string(),
    };

    let github_oauth = GithubOauth {
        client_id: env.var("GITHUB_CLIENT_ID")?.to_string(),
        client_secret: env.var("GITHUB_CLIENT_SECRET")?.to_string(),
        redirect_uri: env
            .var("GITHUB_REDIRECT_URI")
            .ok()
            .and_then(|url| Url::try_from(url.to_string().as_str()).ok()),
    };

    let airtable_api_key = env.var("JASPER_API")?.to_string();

    if req.method() == Method::Options {
        return add_cors_headers(Response::empty()?);
    }

    match req.path().as_str() {
        "/verify_records" => {
            process_verify_records_request(req, slack_oauth, github_oauth, airtable_api_key).await
        }
        _ => process_api_request(req, slack_oauth, github_oauth, airtable_api_key).await,
    }
}

async fn process_api_request(
    mut req: Request,
    slack_oauth: SlackOauth,
    github_oauth: GithubOauth,
    jasper_api: String,
) -> Result<Response> {
    if req.method() != Method::Post {
        return Response::error("Method Not Allowed", 405);
    }

    let api_request: APIRequest = req
        .json()
        .await
        .map_err(|e| worker::Error::from(format!("Bad Request: {}", e)))?;

    match initiate_record_verification(&jasper_api, &slack_oauth, &github_oauth).await {
        Ok(_) => console_log!("Records verification completed"),
        Err(e) => console_error!("Could not verify records: {}", e),
    }
    let response = process_api_payload(api_request, slack_oauth, github_oauth).await?;
    add_cors_headers(response)
}

async fn process_verify_records_request(
    req: Request,
    slack_oauth: SlackOauth,
    github_oauth: GithubOauth,
    jasper_api: String,
) -> Result<Response> {
    if req.method() != Method::Put {
        return Response::error("Method Not Allowed", 405);
    }

    initiate_record_verification(&jasper_api, &slack_oauth, &github_oauth).await
}

#[derive(Deserialize)]
struct QueryParams {
    code: String,
    state: Option<String>,
}

async fn initiate_record_verification(
    jasper_api: &String,
    slack_oauth: &SlackOauth,
    github_oauth: &GithubOauth,
) -> Result<Response> {
    let records = fetch_records(jasper_api.clone()).await?;
    if records.is_empty() {
        return Response::ok("No records to verify");
    }

    verify_all_records(records, slack_oauth, github_oauth, jasper_api).await;
    Response::ok("Records verified")
}

async fn process_api_payload(
    payload: APIRequest,
    slack_oauth: SlackOauth,
    github_oauth: GithubOauth,
) -> Result<Response> {
    let mut temp_response = APIResponse {
        slack: None,
        github: None,
        hashed_secret: String::new(),
    };

    if let Some(slack_code) = payload.slack_code {
        match process_slack_oauth(slack_code, &slack_oauth).await {
            Ok(auth) => temp_response.slack = Some(auth),
            Err(e) => console_log!("Slack OAuth Error: {}", e),
        }
    }

    if let Some(github_code) = payload.github_code {
        match process_github_oauth(
            github_code,
            &github_oauth.client_id,
            &github_oauth.client_secret,
        )
        .await
        {
            Ok(auth) => temp_response.github = Some(auth),
            Err(e) => console_log!("GitHub OAuth Error: {}", e),
        }
    }

    if let Some(slack) = &temp_response.slack {
        let combined_secret = format!(
            "{}{}{}{}",
            slack.slack_id, slack.username, slack.eligibility, slack_oauth.client_secret
        );

        temp_response.hashed_secret = hash_secret(&combined_secret);
    }

    // if let Some(github) = &temp_response.github {
    //     let combined_secret = format!(
    //         "{}{}{}",
    //         github.id, github.name, github_oauth.client_secret
    //     );

    //     temp_response.hashed_secret = hash_secret(&combined_secret);
    // }

    if let (Some(slack), Some(github)) = (&temp_response.slack, &temp_response.github) {
        let combined_secret = format!(
            "{}{}{}{}",
            slack.slack_id,
            slack.username,
            slack.eligibility,
            slack_oauth.client_secret // add in github later
        );

        temp_response.hashed_secret = hash_secret(&combined_secret);
    }

    let response = Response::from_json(&temp_response)?;
    add_cors_headers(response)
}

async fn process_github_oauth(
    code: String,
    client_id: &str,
    client_secret: &str,
) -> Result<GitHubApiResponse> {
    let client = Client::new();
    let token_response = client
        .post(GITHUB_OAUTH_URL)
        .header(CONTENT_TYPE, "application/json")
        .json(&json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
        }))
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;

    let token_text = token_response
        .text()
        .await
        .map_err(|e| format!("Error reading token response text: {}", e))?;
    let token_params: HashMap<String, String> = url::form_urlencoded::parse(token_text.as_bytes())
        .into_owned()
        .collect();
    let access_token = token_params
        .get("access_token")
        .ok_or("Missing access token")?;

    let user_response = client
        .get(GITHUB_USER_URL)
        .header("Authorization", format!("token {}", access_token))
        .header("User-Agent", "request")
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;

    let user_info: Value = user_response
        .json()
        .await
        .map_err(|e| format!("Parsing error: {}", e))?;
    let username = user_info["login"]
        .as_str()
        .ok_or("Missing username")?
        .to_string();
    let name = user_info["name"]
        .as_str()
        .unwrap_or("Unknown User")
        .to_string();

    Ok(GitHubApiResponse { name, id: username })
}

async fn process_slack_oauth(code: String, slack_oauth: &SlackOauth) -> Result<SlackApiResponse> {
    let auth = exchange_slack_code_for_token(
        &slack_oauth.client_id,
        &slack_oauth.client_secret,
        &code,
        &slack_oauth.redirect_uri,
    )
    .await?;

    let username = fetch_slack_user_identity(&auth.authed_user.access_token).await?;
    let ysws_status = fetch_ysws_status(&auth).await?;

    Ok(SlackApiResponse {
        slack_id: auth.authed_user.id,
        eligibility: ysws_status,
        username,
    })
}

async fn exchange_slack_code_for_token(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuthResponse> {
    let client = Client::new();
    let response = client
        .post(SLACK_OAUTH_URL)
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

async fn fetch_ysws_status(user: &OAuthResponse) -> Result<YSWSStatus> {
    let client = Client::new();
    let json_body = json!({ "slack_id": user.authed_user.id });
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let response = client
        .post(YSWS_API_URL)
        .headers(headers)
        .json(&json_body)
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;

    let response_text = response
        .text()
        .await
        .map_err(|e| format!("Text error: {}", e))?;

    match response_text.as_str() {
        text if text.contains("Eligible L1") => Ok(YSWSStatus::EligibleL1),
        text if text.contains("Eligible L2") => Ok(YSWSStatus::EligibleL2),
        text if text.contains("Ineligible") => Ok(YSWSStatus::Ineligible),
        text if text.contains("Insufficient") => Ok(YSWSStatus::Insufficient),
        text if text.contains("Sanctioned Country") => Ok(YSWSStatus::SanctionedCountry),
        text if text.contains("Testing") => Ok(YSWSStatus::Testing),
        _ => Ok(YSWSStatus::Unknown),
    }
}

async fn fetch_slack_user_identity(access_token: &str) -> Result<String> {
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

    console_log!("User info: {:?}", user_info);

    Ok(user_info.name)
}

fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(secret);
    hex::encode(hasher.finalize())
}

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

async fn fetch_records(jasper_api: String) -> Result<Vec<Record>> {
    let client = Client::new();
    let response = client
        .get(RECORDS_API_URL)
        .bearer_auth(jasper_api)
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;

    let response_values: Vec<Value> = response
        .json()
        .await
        .map_err(|e| format!("Parsing error: {}", e))?;
    let records: Vec<Record> = response_values
        .into_iter()
        .filter_map(|value| serde_json::from_value::<Record>(value).ok())
        .collect();

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

async fn verify_all_records(
    records: Vec<Record>,
    slack_oauth: &SlackOauth,
    github_oauth: &GithubOauth,
    jasper_api: &String,
) {
    for record in records {
        let otp_secret = &record.fields.otp;
        let eligibility = &record.fields.eligibility;
        let slack_id = &record.fields.slack_id;
        let slack_username = &record.fields.slack_username;

        let secret = format!(
            "{}{}{}{}",
            &slack_id, &slack_username, &eligibility, &slack_oauth.client_secret
        );

        let hashed_secret = hash_secret(&secret);

        let client = Client::new();
        let bearer_token = jasper_api;

        let json_body = json!({
            "recordId": record.id,
            "authenticated": (hashed_secret == *otp_secret).to_string(),
        });

        let response = client
            .post(UPDATE_API_URL)
            .bearer_auth(bearer_token)
            .json(&json_body)
            .send()
            .await
            .unwrap();

        if response.status().is_success() {
            console_log!(
                "Record num.{} verification successful for {}",
                record.id,
                &record.fields.slack_username
            );
        } else {
            console_log!(
                "Record {} verification failed with status: {}",
                record.id,
                response.status()
            );
        }
    }
}
