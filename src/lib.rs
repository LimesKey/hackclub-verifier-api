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
        let response = handle_oauth(req, env).await;

        response
    } else {
        Response::error("Method Not Allowed", 405)
    }
}

// Handle the OAuth flow after the user has been redirected
async fn handle_oauth(req: Request, env: Env) -> Result<Response> {
    // Parse the query parameters from the request
    let url = req.url()?;
    let params: QueryParams = match serde_qs::from_str(url.query().unwrap_or("")) {
        Ok(params) => params,
        Err(_) => return Response::error("Invalid query parameters", 400),
    };

    // Retrieve environment variables
    let client_id = match env.var("SLACK_CLIENT_ID") {
        Ok(var) => var.to_string(),
        Err(_) => return Response::error("Client ID not set", 500),
    };
    let client_secret = match env.var("SLACK_CLIENT_SECRET") {
        Ok(var) => var.to_string(),
        Err(_) => return Response::error("Client secret not set", 500),
    };
    let redirect_uri = match env.var("SLACK_REDIRECT_URI") {
        Ok(var) => var.to_string(),
        Err(_) => return Response::error("Redirect URI not set", 500),
    };

    console_log!("Client ID: {}", client_id);
    console_log!("Redirect URI: {}", redirect_uri);
    console_log!("Code: {}", params.code);

    // Exchange authorization code for an access token
    let access_token_response = match exchange_code_for_token(
        &client_id,
        &client_secret,
        &params.code,
        &redirect_uri,
    )
    .await
    {
        Ok(response) => response,
        Err(_) => return Response::error("FailSome(AuthedUser)ed to exchange code for token", 500),
    };

    let mut user_id = String::from("");
    // Process the OAuth response
    if access_token_response.ok {
        let ysws_status = ysws_api(&access_token_response.authed_user).await;
        user_id = access_token_response.authed_user.id;

        if ysws_status == true {
            return Response::ok(format!(
                "Successfully authenticated as user {}, and you are eligable!",
                user_id
            ));
        } else {
            return Response::ok(format!(
                "Successfully authenticated as user {}, but you are not eligable!",
                user_id
            ));
        }
    } else {
        Response::ok(format!(
            "Slack returned an error: {}",
            access_token_response
                .error
                .unwrap_or_else(|| "Unknown error".to_string())
        ))
    }
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

async fn ysws_api(user_id: &AuthedUser) -> bool {
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

    if response.text().await.unwrap().contains("eligible") {
        return true;
    } else {
        return false;
    };
}
