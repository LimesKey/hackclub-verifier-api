use crate::GitHubApiResponse;
use reqwest::{header::CONTENT_TYPE, Client};
use serde_json::{json, Value};
use std::collections::HashMap;

const GITHUB_OAUTH_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL: &str = "https://api.github.com/user";

pub async fn process_github_oauth(
    code: String,
    client_id: &str,
    client_secret: &str,
) -> Result<GitHubApiResponse, String> {
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
