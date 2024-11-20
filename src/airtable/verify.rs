use crate::{
    console_error, console_log, fetch_submissions, hash_secret, update_submission, Record, Response, Result, SlackOauth,
};

pub async fn verify_all_records(
    records: Vec<Record>,
    slack_oauth: &SlackOauth,
    airtable_key: &String,
) {
    for record in records {
        let otp_secret = &record.fields.otp;
        let eligibility = &record.fields.eligibility;
        let slack_id = &record.fields.slack_id;
        let slack_username = &record.fields.slack_username;
        let github_username = &record.fields.github_handle;

        let record_id = &record.id;

        let secret = format!(
            "{}{}{}{}{}",
            &slack_id, &slack_username, &eligibility, &github_username, &slack_oauth.client_secret
        );

        let hashed_secret = hash_secret(&secret);

        if *otp_secret == hashed_secret {
            match update_submission(airtable_key, record_id, true).await {
                Ok(_) => console_log!("Record updated to [Verified] successfully"),
                Err(e) => console_error!("Failed to update record: {}", e),
            }
        } else {
            match update_submission(airtable_key, record_id, false).await {
                Ok(_) => console_log!("Record updated to [Unverified] successfully"),
                Err(e) => console_error!("Failed to update record: {}", e),
            }
        }
    }
}

pub async fn initiate_record_verification(
    airtable_key: &String,
    slack_oauth: &SlackOauth,
) -> Result<Response> {
    let records = fetch_submissions(airtable_key).await.unwrap();
    if records.is_empty() {
        return Response::ok("No records to verify");
    }

    verify_all_records(records, slack_oauth, airtable_key).await;
    Response::ok("Records verified")
}
