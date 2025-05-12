use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
};

use crate::jwt::JwtClaims;

use super::{github::GithubOauthService, workos::WorkosOauthService};

use once_cell::sync::Lazy;

/// The HTTP client used to make requests to the Oauth provider.
/// Lazy loaded to avoid creating a new client for each request.
pub(crate) static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(reqwest::Client::new);

pub struct Provider {
    pub typ: OauthType,
    pub client_id: String,
    pub client_secret: String,
}

impl Provider {
    /// Get the Oauth callback URL for the given provider
    pub fn get_oauth_callback_url(&self, state: &str) -> String {
        match self.typ {
            OauthType::Github => GithubOauthService::get_oauth_callback_url(&self.client_id, state),
            OauthType::Workos => WorkosOauthService::get_oauth_callback_url(&self.client_id, state),
        }
    }

    /// Get the Oauth user from the provider using the provided code
    pub async fn get_oauth_user(&self, code: &str) -> Result<OauthUser, anyhow::Error> {
        match self.typ {
            OauthType::Github => {
                GithubOauthService::get_oauth_user(&self.client_id, &self.client_secret, code).await
            }
            OauthType::Workos => {
                WorkosOauthService::get_oauth_user(&self.client_id, &self.client_secret, code).await
            }
        }
    }
}

#[derive(Debug)]
pub struct OauthUser {
    pub email: Cow<'static, str>,
    pub team_ids: Vec<String>,
    pub organization_ids: Vec<String>,
    pub usernames: Vec<String>,
}

impl From<JwtClaims> for OauthUser {
    fn from(claims: JwtClaims) -> Self {
        Self {
            email: claims.sub,
            team_ids: claims.teams,
            organization_ids: claims.ids,
            usernames: vec![],
        }
    }
}

//
pub enum OauthType {
    Github,
    Workos,
}

impl Display for OauthType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OauthType::Github => write!(f, "github"),
            OauthType::Workos => write!(f, "workos"),
        }
    }
}
