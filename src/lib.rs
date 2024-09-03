use cfg_if::cfg_if;
use log::Level;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{fmt, hash::{DefaultHasher, Hash, Hasher}};
use worker::*;

cfg_if! {
    if #[cfg(feature = "console_log")] {
        fn init_log() {
            console_log::init_with_level(Level::Trace).expect("error initializing log");
        }
    } else {
        fn init_log() {}
    }
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));
    init_log();

    let client_secret = env
        .var("SLACK_CLIENT_SECRET")
        .expect("Client secret not set")
        .to_string();

    if req.method() == Method::Get {
        console_log!("GET request received");

        let auth = match handle_oauth(req.url()?, &env).await {
            Ok(auth) => auth,
            Err(e) => return Response::error(format!("OAuth error: {}", e), 500),
        };
        console_log!("Fetched Bot and User Token");

        let username = match user_identity(&auth.authed_user.access_token).await {
            Ok(name) => name,
            Err(e) => return Response::error(format!("User identity error: {}", e), 500),
        };

        console_log!("Getting YSWS status with Slack ID: {}", auth.authed_user.id);
        let ysws_status = match ysws_api(&auth).await {
            Ok(status) => status,
            Err(e) => return Response::error(format!("YSWS API error: {}", e), 500),
        };

        let secret = format!(
            "{}{}{}{}",
            auth.authed_user.id, username, ysws_status, client_secret
        );
        let hashed_secret = hash_secret(&secret);

        let mut url = Url::parse("https://forms.hackclub.com/t/9yNy4WYtrZus").unwrap();
        url.query_pairs_mut()
            .append_pair("secret", &hashed_secret)
            .append_pair("slack_id", &auth.authed_user.id)
            .append_pair("eligibility", &ysws_status.to_string())
            .append_pair("slack_user", &username);
        console_log!("Redirecting to {}", url);

        let records = match get_records(&env).await {
            Ok(records) => records,
            Err(e) => return Response::error(format!("Error fetching records: {}", e), 500),
        };
        console_log!("Records fetched");

        if !records.is_empty() {
           verify_hash(records, env).await
        }

        Response::redirect_with_status(url, 302)
    } else {
        Response::error("Method Not Allowed", 405)
    }
}

// Handle the OAuth flow to get the access token/Slack ID
async fn handle_oauth(url: Url, env: &Env) -> Result<OAuthResponse> {
    let params: QueryParams = serde_qs::from_str(url.query().ok_or("Missing query params")?)
        .map_err(|_| "Error parsing query parameters".to_string())?;

    let client_id = env
        .var("SLACK_CLIENT_ID")
        .map_err(|_| "Client ID not set".to_string())?
        .to_string();
    let client_secret = env
        .var("SLACK_CLIENT_SECRET")
        .map_err(|_| "Client secret not set".to_string())?
        .to_string();
    let redirect_uri = env
        .var("SLACK_REDIRECT_URI")
        .map_err(|_| "Redirect URI not set".to_string())?
        .to_string();

    console_log!("Client ID: {}", client_id);
    console_log!("Code: {}", params.code);

    console_log!("Exchange code for token response...");
    exchange_code_for_token(&client_id, &client_secret, &params.code, &redirect_uri).await
}

// Hashing secret using DefaultHasher
fn hash_secret(secret: &str) -> String {
    let mut hasher = DefaultHasher::new();
    secret.hash(&mut hasher);
    hasher.finish().to_string()
}

#[derive(Deserialize)]
struct QueryParams {
    code: String,
    state: Option<String>,
}

#[derive(Deserialize, Debug)]
struct OAuthResponse {
    ok: bool,
    access_token: String, // bot access token
    authed_user: User,
}

#[derive(Deserialize, Debug)]
struct User {
    id: String,
    access_token: String, // user auth token
}

pub enum YSWSStatus {
    EligibleL1,
    EligibleL2,
    Ineligible,
    Insufficient,
    SanctionedCountry,
    Testing,
    Unknown,
}

impl fmt::Display for YSWSStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

    if response.status().is_success() {
        Ok(response
            .json::<OAuthResponse>()
            .await
            .map_err(|e| format!("Parsing error: {}", e))?)
    } else {
        Err(format!(
            "OAuth request failed with status: {}",
            response.status()
        ).into())
    }
}

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
    Ok(match response_text.as_str() {
        "Eligible L1" => YSWSStatus::EligibleL1,
        "Eligible L2" => YSWSStatus::EligibleL2,
        "Ineligible" => YSWSStatus::Ineligible,
        "Insufficient" => YSWSStatus::Insufficient,
        "Sanctioned Country" => YSWSStatus::SanctionedCountry,
        "Testing" => YSWSStatus::Testing,
        _ => YSWSStatus::Unknown,
    })
}

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

#[derive(Deserialize, Debug)]
struct UserInfo {
    ok: bool,
    name: String,
    email: String,
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

async fn verify_hash(records: Vec<Record>, env: Env) {
    console_log!("Looking into {} records", records.len());

    for record in records {
        let otp_secret = record.fields.otp;
        let eligibility = record.fields.eligibility;
        let slack_id = record.fields.slack_id;
        let slack_username = record.fields.slack_username;

        let client_secret = match env.var("SLACK_CLIENT_SECRET") {
            Ok(var) => var.to_string(),
            Err(_) => panic!("Client secret not set"),
        };

        let jasper_api = match env.var("JASPER_API") {
            Ok(var) => var.to_string(),
            Err(_) => panic!("Jasper API not set"),
        };

        let secret = slack_id + &slack_username + &eligibility + &client_secret.to_string();

        let mut hasher = DefaultHasher::new();
        secret.hash(&mut hasher);
        let hashed_secret = hasher.finish().to_string();

        let client = Client::new();
        let url: Url =
            Url::parse("http://hackclub-ysws-api.jasperworkers.workers.dev/update").unwrap();
        let bearer_token = jasper_api; // Replace with your actual Bearer token

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
