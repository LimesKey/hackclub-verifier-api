use crate::Url;
use serde::{Deserialize, Serialize};

pub struct GithubOauth {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: Option<Url>,
}

// Structs and Enums
#[derive(Deserialize, Debug, Serialize)]
pub struct GitHubApiResponse {
    pub name: String,
    pub id: String,
}
