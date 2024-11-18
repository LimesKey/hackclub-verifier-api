use crate::slack::types::*;
use crate::{console_log, HeaderValue, HeaderMap, CONTENT_TYPE};
use serde_json::json;
use reqwest::Client;

const SLACK_OAUTH_URL: &str = "https://slack.com/api/oauth.v2.access";
const YSWS_API_URL: &str = "https://verify.hackclub.dev/api/status";

pub async fn process_slack_oauth(code: String, slack_oauth: &SlackOauth) -> Result<SlackApiResponse, Box<dyn std::error::Error>> {
    let auth = exchange_slack_code_for_token(
        &slack_oauth.client_id,
        &slack_oauth.client_secret,
        &code,
        &slack_oauth.redirect_uri,
    )
    .await?;

    let (firstname, lastname, username) = fetch_slack_user_identity(&auth.authed_user.access_token).await?;    
    
    let ysws_status = fetch_ysws_status(&auth).await?;

    Ok(SlackApiResponse {
        slack_id: auth.authed_user.id,
        eligibility: ysws_status,
        first_name: firstname,
        last_name: lastname,
        username,
    })
}

pub async fn exchange_slack_code_for_token(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuthResponse, Box<dyn std::error::Error>> {
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

pub async fn fetch_ysws_status(user: &OAuthResponse) -> Result<YSWSStatus, Box<dyn std::error::Error>> {
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

pub async fn fetch_slack_user_identity(access_token: &str) -> Result<(String, Option<String>, String), Box<dyn std::error::Error>> {
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

    let mut trimmed_name = user_info.name.trim().split_whitespace().collect::<Vec<&str>>();

    let first_name;
    let mut last_name = None;
    
    if !trimmed_name.is_empty() {
        first_name = trimmed_name[0].to_string();
        trimmed_name.remove(0);
    
        if !trimmed_name.is_empty() {
            last_name = Some(trimmed_name.join(" "));
        }
    } else {
        first_name = "UnknownFirstName".to_string(); // or handle the case where the name is empty
    }


    Ok((first_name, last_name, user_info.name))
}
