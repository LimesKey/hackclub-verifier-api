use cfg_if::cfg_if;
use log::Level; // Add this line to import the Level type
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use serde::Deserialize;
use serde_json::Value;
use serde_qs;
use std::fmt;
use totp_rs::{Algorithm, Secret, TOTP};
use wasm_timer::{SystemTime, UNIX_EPOCH};
use worker::*;

mod utils;

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

    if req.method() == Method::Get {
        console_log!("GET request received");

        let auth = handle_oauth(req, env).await;
        console_log!("Fetched Bot and User Token");

        console_log!(
            "Getting user identity with their user token, : {}",
            &auth.authed_user.access_token
        );
        let username = user_identity(&auth.authed_user.access_token).await;

        console_log!(
            "Getting YSWS status with their Slack ID, {}",
            &auth.authed_user.id
        );
        let ysws_status = ysws_api(&auth).await;

        let slack_id = auth.authed_user.id.clone();
        let slack_username = username.clone();
        let ysws_status = ysws_status.to_string().clone();

        let secret = slack_id + &slack_username + &ysws_status;

        let totp = TOTP::new(
            Algorithm::SHA256,
            6,
            1,
            300,
            Secret::Raw(secret.as_bytes().to_vec())
                .to_bytes()
                .expect("Failed to convert secret to bytes"),
            Some("hackclub-ysws-verifier".to_string()),
            slack_username.clone(),
        )
        .unwrap();

        let token = totp.generate(
            wasm_timer::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        // Redirecting to the form with the slack_id and eligibility status

        let mut url = Url::parse("https://forms.hackclub.com/t/9yNy4WYtrZus").unwrap(); // fillout form URL
        url.query_pairs_mut().append_pair("secret", &token);
        url.query_pairs_mut()
            .append_pair("slack_id", &auth.authed_user.id);
        url.query_pairs_mut()
            .append_pair("eligibility", &ysws_status.to_string());
        url.query_pairs_mut().append_pair("slack_user", &username);
        console_log!("Redirecting to {}", url);
        Response::redirect_with_status(url, 302)
    } else {
        Response::error("Method Not Allowed", 405)
    }
}

// Handle the OAuth flow to get the access token/ slack id
async fn handle_oauth(req: Request, env: Env) -> OAuthResponse {
    let url = req.url().unwrap();
    let params: QueryParams = match serde_qs::from_str(url.query().unwrap()) {
        Ok(params) => params,
        Err(_) => panic!("Error parsing query parameters"),
    };

    // Retrieve environment variables
    let client_id = match env.var("SLACK_CLIENT_ID") {
        Ok(var) => var.to_string(),
        Err(_) => panic!("Client ID not set"),
    };
    let client_secret = match env.var("SLACK_CLIENT_SECRET") {
        Ok(var) => var.to_string(),
        Err(_) => panic!("Client secret not set"),
    };
    let redirect_uri = match env.var("SLACK_REDIRECT_URI") {
        Ok(var) => var.to_string(),
        Err(_) => panic!("Redirect URI not set"),
    };

    console_log!("Client ID: {}", client_id);
    console_log!("Code: {}", params.code);

    // Exchange authorization code for an access token
    console_log!("Exchange code for token response...");
    let access_token_response =
        exchange_code_for_token(&client_id, &client_secret, &params.code, &redirect_uri).await;
    return access_token_response;
}

#[derive(Deserialize)]
pub struct QueryParams {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct OAuthResponse {
    pub ok: bool,
    pub access_token: String, // bot access token
    pub authed_user: User,
}

#[derive(Deserialize, Debug)]
pub struct User {
    pub id: String,
    pub access_token: String, // user auth token
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

pub async fn exchange_code_for_token(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> OAuthResponse {
    let client: Client = Client::new();

    let request = client.post("https://slack.com/api/oauth.v2.access").form(&[
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ]);

    let response = request.send().await.unwrap();
    let oauth_response: OAuthResponse = response.json::<OAuthResponse>().await.unwrap();
    oauth_response
}

async fn ysws_api(user: &OAuthResponse) -> YSWSStatus {
    let client = Client::new();
    let url = "https://verify.hackclub.dev/api/status";

    let json_body: Value = serde_json::json!({
        "slack_id": user.authed_user.id,
    });

    // Create headers
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    // Send the POST request
    let response = client
        .post(url)
        .headers(headers)
        .json(&json_body)
        .send()
        .await
        .unwrap();

    let response_text = response.text().await.unwrap();

    if response_text.contains("Eligible L1") {
        YSWSStatus::EligibleL1
    } else if response_text.contains("Eligible L2") {
        YSWSStatus::EligibleL2
    } else if response_text.contains("Ineligible") {
        YSWSStatus::Ineligible
    } else if response_text.contains("Insufficient") {
        YSWSStatus::Insufficient
    } else if response_text.contains("Sanctioned Country") {
        YSWSStatus::SanctionedCountry
    } else if response_text.contains("Testing") {
        YSWSStatus::Testing
    } else {
        YSWSStatus::Unknown
    }
}

async fn user_identity(access_token: &String) -> String {
    let client = Client::new();
    let url = "https://slack.com/api/openid.connect.userInfo";
    console_log!("Getting user info with access token: {}", access_token);

    let response = client
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap();
    // Parse the response as JSON
    let user_info: UserInfo = response.json::<UserInfo>().await.unwrap();

    user_info.name
}

#[derive(Deserialize, Debug)]
struct UserInfo {
    ok: bool,
    name: String,
    email: String,
}

// fn verify_airtable() {

// }

// async fn get_airtable_records() -> Vec<Record<OnBoardRecord>> {
//     let airtable = Airtable::new_from_env();
//     // Get the current records from a table.
//     let mut records: Vec<Record<OnBoardRecord>> = airtable
//         .list_records(
//             "Submissions",
//             "Pending",
//             vec!["OTP"],
//         )
//         .await
//         .unwrap();

//     // Iterate over the records.
//     for (i, record) in records.clone().iter().enumerate() {
//         println!("{} - {:?}", i, record);
//     }
//     return records;
// }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// struct OnBoardRecord {
//     OTP: String,
// }
