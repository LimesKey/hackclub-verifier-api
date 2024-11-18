pub mod airtable;
pub mod github;
pub mod slack;
pub mod utils;

use crate::{airtable::*, github::*, slack::*};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use worker::*;

#[derive(Serialize, Deserialize)]
struct APIResponse {
    slack: Option<SlackApiResponse>,
    github: Option<GitHubApiResponse>,
    hashed_secret: String,
}

#[derive(Deserialize, Debug)]
struct APIRequest {
    slack_code: Option<String>,
    github_code: Option<String>,
    special_secret: Option<String>,
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

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    utils::set_panic_hook();

    request_diagnostics(&req);

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

    let airtable_api_key = env.var("AIRTABLE_KEY")?.to_string();

    if req.method() == Method::Options {
        return add_cors_headers(Response::empty()?);
    }

    match req.path().as_str() {
        "/verify_records" => {
            process_verify_records_request(req, slack_oauth, airtable_api_key).await
        }
        "/verify_hash" => process_hash_verification(req, &slack_oauth).await,
        _ => process_api_request(req, slack_oauth, github_oauth, &airtable_api_key).await,
    }
}

async fn process_api_request(
    mut req: Request,
    slack_oauth: SlackOauth,
    github_oauth: GithubOauth,
    airtable_key: &String,
) -> Result<Response> {
    if req.method() != Method::Post {
        return Response::error("Method Not Allowed", 405);
    }

    let api_request: APIRequest = req
        .json()
        .await
        .map_err(|e| worker::Error::from(format!("Bad Request: {}", e)))?;

    match initiate_record_verification(airtable_key, &slack_oauth).await {
        Ok(_) => console_log!("Records verification completed"),
        Err(e) => console_error!("Could not verify records: {}", e),
    }

    let response = process_api_payload(api_request, slack_oauth, github_oauth).await?;
    console_log!("API request processed successfully");
    add_cors_headers(response)
}

async fn process_hash_verification(mut req: Request, slack_oauth: &SlackOauth) -> Result<Response> {
    if req.method() != Method::Get {
        return Response::error("Method Not Allowed", 405);
    }

    let api_request: APIResponse = match req.json().await {
        Ok(data) => data,
        Err(e) => {
            return Response::error(format!("Invalid or missing JSON information: {}", e), 400)
        }
    };

    let slack = api_request.slack.unwrap();

    let eligibility = &slack.eligibility;
    let slack_id = &slack.slack_id;
    let slack_username = &slack.username;
    let github_username = &api_request.github.unwrap().id;

    let secret = format!(
        "{}{}{}{}{}",
        &slack_id, &slack_username, &eligibility, &github_username, &slack_oauth.client_secret
    );

    let hashed_secret = hash_secret(&secret);

    match hashed_secret == api_request.hashed_secret {
        true => Response::ok("Hash Verified"),
        false => Response::error("Hash Unverified", 400),
    }
}

async fn process_api_payload(
    payload: APIRequest,
    mut slack_oauth: SlackOauth,
    github_oauth: GithubOauth,
) -> Result<Response> {
    let mut temp_response = APIResponse {
        slack: None,
        github: None,
        hashed_secret: String::new(),
    };

    if let Some(slack_code) = payload.slack_code {
        if payload.special_secret == Some("hello".to_string()) {
            slack_oauth.redirect_uri =
                String::from("https://trickortrace.hackclub.com/oauth/slack");
            console_log!("Special secret detected. Redirect URI changed to localhost");
        }

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

    if let (Some(slack), Some(github)) = (&temp_response.slack, &temp_response.github) {
        let combined_secret = format!(
            "{}{}{}{}{}",
            slack.slack_id, slack.username, slack.eligibility, github.id, slack_oauth.client_secret
        );

        temp_response.hashed_secret = hash_secret(&combined_secret);
    }

    let response = Response::from_json(&temp_response)?;
    add_cors_headers(response)
}

fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(secret);
    hex::encode(hasher.finalize())
}

fn request_diagnostics(req: &Request) {
    if let Ok(Some(ip)) = req.headers().get("cf-connecting-ip") {
        console_log!("Received request from {} at {:?}", req.url().unwrap(), ip);
    } else {
        console_log!("Received request at {:?}", req.url().unwrap());
    }

    let city = req.headers().get("cf-ipcity").ok().flatten();
    let country = req.headers().get("cf-ipcountry").ok().flatten();

    match (city, country) {
        (Some(city), Some(country)) => {
            console_log!("City: {:?}, Country: {:?}", city, country);
        }
        (Some(city), None) => {
            console_log!("City: {:?}", city);
        }
        (None, Some(country)) => {
            console_log!("Country: {:?}", country);
        }
        (None, None) => {}
    }
}
