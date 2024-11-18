use serde::{Deserialize, Serialize};

pub struct SlackOauth {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct SlackApiResponse {
    pub slack_id: String,
    pub eligibility: YSWSStatus,
    pub first_name: String,
    pub last_name: Option<String>,
    pub username: String,
}

#[derive(Deserialize, Debug, Serialize)]
pub enum YSWSStatus {
    EligibleL1,
    EligibleL2,
    Ineligible,
    Insufficient,
    SanctionedCountry,
    Testing,
    Unknown,
}

#[derive(Deserialize, Debug)]
pub struct OAuthResponse {
    pub ok: bool,
    pub access_token: Option<String>,
    pub authed_user: User,
}

#[derive(Deserialize, Debug)]
pub struct User {
    pub id: String,
    pub access_token: String,
}

#[derive(Deserialize, Debug)]
pub struct UserInfo {
    pub ok: bool,
    pub name: String,
    pub email: String,
}

impl std::fmt::Display for YSWSStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            YSWSStatus::EligibleL1 => write!(f, "EligibleL1"),
            YSWSStatus::EligibleL2 => write!(f, "EligibleL2"),
            YSWSStatus::Ineligible => write!(f, "Ineligible"),
            YSWSStatus::Insufficient => write!(f, "Insufficient"),
            YSWSStatus::SanctionedCountry => write!(f, "SanctionedCountry"),
            YSWSStatus::Testing => write!(f, "Testing"),
            YSWSStatus::Unknown => write!(f, "Unknown"),
        }
    }
}
