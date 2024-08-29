use std::fmt;

use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use serde::Deserialize;
use serde_json::Value;
use serde_qs;
use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    if req.method() == Method::Get {
        let user = handle_oauth(req, env).await.unwrap();
        let ysws_status = ysws_api(&user.authed_user).await;

        let mut url = Url::parse("https://forms.hackclub.com/t/9yNy4WYtrZus").unwrap();
        url.query_pairs_mut().append_pair("slack_id", &user.authed_user.id);
        url.query_pairs_mut().append_pair("eligibility", &ysws_status.to_string());

        Response::redirect(url)
    } else {
        Response::error("Method Not Allowed", 405)
    }
}

// Handle the OAuth flow after the user has been redirected
async fn handle_oauth(req: Request, env: Env) -> Result<OAuthResponse> {
    // Parse the query parameters from the request
    let url = req.url()?;
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
    console_log!("Redirect URI: {}", redirect_uri);
    console_log!("Code: {}", params.code);

    // Exchange authorization code for an access token
    let access_token_response=  exchange_code_for_token(
        &client_id,
        &client_secret,
        &params.code,
        &redirect_uri,
    ).await;

    return access_token_response;
}

// Define a struct to match the query parameters
#[derive(Deserialize)]
pub struct QueryParams {
    pub code: String,
    pub state: Option<String>,
}

// Define a struct for the OAuth response from Slack
// Define the struct to match the JSON data
#[derive(Deserialize, Debug)]
pub struct OAuthResponse {
    pub ok: bool,
    pub app_id: String,
    pub authed_user: AuthedUser,
    pub scope: String,
    pub token_type: String,
    pub access_token: String,
    pub bot_user_id: String,
    pub team: Team,
    pub is_enterprise_install: bool,
    pub error: Option<String>,
}

// Define the struct for the `authed_user` field
#[derive(Deserialize, Debug)]
pub struct AuthedUser {
    pub id: String,
}

#[derive(Deserialize, Debug)]
pub struct Team {
    pub id: String,
    pub name: String,
}

pub enum YSWSStatus {
    EligibleL1,
    EligibleL2,
    Ineligible,
    Insufficient,
}

impl fmt::Display for YSWSStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            YSWSStatus::EligibleL1 => write!(f, "Eligible L1"),
            YSWSStatus::EligibleL2 => write!(f, "Eligible L2"),
            YSWSStatus::Ineligible => write!(f, "Ineligible"),
            YSWSStatus::Insufficient => write!(f, "Insufficient"),
        }
    }
}


// Function to exchange authorization code for an access token
pub async fn exchange_code_for_token(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuthResponse> {
    let client = Client::new();

    // Make the request to the Slack API to exchange the code for an access token
    let request = client.post("https://slack.com/api/oauth.v2.access").form(&[
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ]);

    let response = request.send().await.unwrap();

    let oauth_response = response.json::<OAuthResponse>().await.unwrap();

    Ok(oauth_response)
}

async fn ysws_api(user_id: &AuthedUser) -> YSWSStatus {
    let client = Client::new();
    let url = "https://verify.hackclub.dev/api/status";

    let json_body: Value = serde_json::json!({
        "slack_id": user_id.id,
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

    match response.text().await.unwrap().as_str() {
        "Eligible L1" => YSWSStatus::EligibleL1,
        "Eligible L2" => YSWSStatus::EligibleL2,
        "Ineligible" => YSWSStatus::Ineligible,
        "Insufficient" => YSWSStatus::Insufficient,
        _ => YSWSStatus::Ineligible,
    }
}
