# OnBoard Submission Verifier

This program runs as a Cloudflare Wrangler worker at [api.onboard.hackclub.com](https://api.onboard.hackclub.com). It's intended to be used by the Svelte, Rust & WebAssembly frontend at [verify.onboard.hackclub.com](https://verify.onboard.hackclub.com), also hosted by Cloudflare in a Page. 

This API is used to verify users using Slack and GitHub oAuth codes. The API accepts POST requests with optional Slack and GitHub authorization codes and returns a json struct that includes information about the Slack User and GitHub user, and also checks against the unified YSWS Verification API to see if they're eligible and have verified their ID.

### Endpoint

```
POST https://api.onboard.limeskey.com/api
```

### Request Payload

The request payload should be in JSON format and can include either or both Slack and GitHub authorization codes.

#### Example Payload
```json
{
  "slack_code": "your_slack_code_here",
  "github_code": "your_github_code_here"
}
```

- `slack_code` *(optional)*: The Slack OAuth code.
- `github_code` *(optional)*: The GitHub OAuth code.

### Response

If the request is successful, the API will return a 200 response with a URL containing verification information, which includes:

- `secret`: The hashed secret.
- `slack_id`: The Slack user ID.
- `eligibility`: The user's eligibility status from Slack.
- `slack_user`: The Slack username.
- `github_id`: The GitHub user ID.

#### Example Response

```
https://forms.hackclub.com/t/9yNy4WYtrZus?secret=5ec501bbb97b6b&slack_id=U04JGJN2B40&eligibility=EligibleL1&slack_user=Ryan+Di+Lorenzo&github_id=LimesKey
```

### Error Handling

If the request fails, the API will return an error message with the response status.

#### Example Error

```
{
  "error": "Request failed with status: 400"
}
```

### Example Usage

```rust
// Example using Fetch API in Rust using wasm_bindgen

#[derive(Serialize, Deserialize)]
struct ApiPayload {
    slack_code: Option<String>,
    github_code: Option<String>,
}

pub async fn verify_api(slack_code: Option<String>, github_code: Option<String>) -> Result<JsValue, JsValue> {
    let payload = ApiPayload { slack_code, github_code };
    let payload_json = serde_json::to_string(&payload).unwrap();

    let mut opts = RequestInit::new();
    opts.method("POST")
        .body(Some(&JsValue::from_str(&payload_json)))
        .mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init("https://api.onboard.limeskey.com/api", &opts).unwrap();
    let response_value = JsFuture::from(web_sys::window().unwrap().fetch_with_request(&request)).await?;
    let response_text = JsFuture::from(response_value.dyn_into::<web_sys::Response>()?.text()?).await?;
    
    Ok(response_text)
}
```

### Development
Build the program using `pnpm install` and run `pnpm wrangler dev` with the required enviornment variables.