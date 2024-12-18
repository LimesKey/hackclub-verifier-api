use crate::airtable::types::Record;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde_json::Value;
use std::error::Error;

const AIRTABLE_BASE_ID: &str = "app4Bs8Tjwvk5qcD4";
const SUBMISSIONS_TABLE_NAME: &str = "Submissions";

pub async fn fetch_submissions(airtable_key: &String) -> Result<Vec<Record>, Box<dyn Error>> {
    let airtable_url = format!(
        "https://api.airtable.com/v0/{}/{}?fields%5B%5D=SlackUsername&fields%5B%5D=OTP&fields%5B%5D=Slack+ID&fields%5B%5D=Eligibility&fields%5B%5D=GitHub+handle&filterByFormula=AND(%7BStatus%7D%3D'Pending'%2CNOT(%7BOTP%7D%3D''))",
        AIRTABLE_BASE_ID,
        SUBMISSIONS_TABLE_NAME
    );

    let client = Client::new();
    let auth_header_value = format!("Bearer {}", airtable_key.trim());
    let auth_header = HeaderValue::from_str(&auth_header_value)
        .map_err(|e| format!("Invalid header value: {}", e))?;

    let response = client
        .get(&airtable_url)
        .header(AUTHORIZATION, auth_header)
        .header(CONTENT_TYPE, "application/json")
        .send()
        .await?;

    let data: Value = response.json().await?;
    let records: Vec<Record> = serde_json::from_value(data["records"].clone())?;

    Ok(records)
}
