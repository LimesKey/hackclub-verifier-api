use reqwest::Client;
use serde_json::json;
use std::error::Error;
use reqwest::header::{HeaderValue, AUTHORIZATION};

const AIRTABLE_BASE_ID: &str = "app4Bs8Tjwvk5qcD4";
const SUBMISSIONS_TABLE_NAME: &str = "Submissions";

pub async fn update_submission(
    airtable_key: &String,
    record_id: &str,
    authenticated: bool,
) -> Result<String, Box<dyn Error>> {
    handle_update_request(record_id, authenticated, &airtable_key).await
}

async fn handle_update_request(
    record_id: &str,
    authenticated: bool,
    airtable_key: &str,
) -> Result<String, Box<dyn Error>> {
    let fields = if authenticated {
        json!({ "Authenticated": "Verified", "OTP": "" })
    } else {
        json!({ "Authenticated": "Unverified", "OTP": "" })
    };

    let update_url = format!(
        "https://api.airtable.com/v0/{}/{}/{}",
        AIRTABLE_BASE_ID, SUBMISSIONS_TABLE_NAME, record_id
    );

    let auth_header_value = format!("Bearer {}", airtable_key.trim());
    let auth_header = HeaderValue::from_str(&auth_header_value)
        .map_err(|e| format!("Invalid header value: {}", e))?;

    let client = Client::new();
    let response = client
        .patch(&update_url)
        .header(AUTHORIZATION, auth_header)
        .header("Content-Type", "application/json")
        .json(&json!({ "fields": fields }))
        .send()
        .await?;

    if response.status().is_success() {
        Ok(format!(
            "Record updated to [{}] successfully",
            fields["Authenticated"].as_str().unwrap_or("")
        ))
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to update record",
        )))
    }
}
