use warp::Filter;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use worker::*;

#[tokio::main]
async fn main() {
    // Define the route for the `/` path
    let route = warp::get()
        .and(warp::query::<QueryParams>()) // Extract query parameters
        .and_then(handle_oauth);

    // Start the warp server on port 3030
    warp::serve(route)
        .run(([0, 0, 0, 0], 3030))
        .await;
}

// Define a struct to match the query parameters
#[derive(Deserialize)]
struct QueryParams {
    code: String,
    state: Option<String>,
}

// Define a struct for the OAuth response from Slack
#[derive(Deserialize)]
struct OAuthResponse {
    ok: bool,
    access_token: String,
    user_id: String,
}

// Define a struct for the User Info response from Slack
#[derive(Deserialize)]
struct UserIdentityResponse {
    ok: bool,
    user: User,
}

#[derive(Deserialize)]
struct User {
    id: String, // This is the user's UUID (Slack ID)
    name: String,
}

// Handle the OAuth flow after the user has been redirected
async fn handle_oauth(params: QueryParams) -> Result<impl warp::Reply, warp::Rejection> {
    // Set up your Slack client ID, client secret, and redirect URI
    let client_id = env::var("SLACK_CLIENT_ID").expect("SLACK_CLIENT_ID not set");
    let client_secret = env::var("SLACK_CLIENT_SECRET").expect("SLACK_CLIENT_SECRET not set");
    let redirect_uri = env::var("SLACK_REDIRECT_URI").expect("SLACK_REDIRECT_URI not set");

    // Exchange authorization code for an access token    
    let access_token_response = exchange_code_for_token(&client_id, &client_secret, &params.code, &redirect_uri).await;
    
    match access_token_response {
        Ok(oauth_response) => {
            // Use the access token to get the user's Slack UUID (Slack ID)
            let user_id = oauth_response.user_id;

            Ok(format!("Successfully retrieved user's UUID: {}", user_id))
        }
        Err(e) => {
            eprintln!("Error during OAuth: {:?}", e);
            Ok("Failed to retrieve user information.".to_string())
        }
    }
}

// Function to exchange authorization code for an access token
async fn exchange_code_for_token(client_id: &str, client_secret: &str, code: &str, redirect_uri: &str) -> Result<OAuthResponse, reqwest::Error> {
    let client = Client::new();

    // Make the request to the Slack API to exchange the code for an access token
    let response = client
        .post("https://slack.com/api/oauth.v2.access")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await?
        .json::<OAuthResponse>()
        .await?;

    Ok(response)
}
