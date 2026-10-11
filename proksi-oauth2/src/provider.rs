use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
};

use crate::jwt::JwtClaims;
use once_cell::sync::Lazy;

use super::{gitea::GiteaOauthService, github::GithubOauthService, workos::WorkosOauthService};


/// The HTTP client used to make requests to the Oauth provider.
/// Lazy loaded to avoid creating a new client for each request.
pub(crate) static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(reqwest::Client::new);

pub struct Provider {
    pub typ: OauthType,
    pub base_url: Option<String>,
    pub redirect_path: Option<String>,
    pub logout_path: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub end_session_endpoint: Option<String>,
}

impl Provider {
    /// Get the Oauth callback URL for the given provider
    pub fn get_oauth_callback_url(&self, state: &str, redirect_uri: &str) -> String {
        match self.typ {
            OauthType::Gitea => GiteaOauthService::get_oauth_callback_url(
                self.base_url.as_ref().expect("base_url is required for Gitea"),
                &self.client_id,
                &redirect_uri,
                state,
            ),
            OauthType::Github => GithubOauthService::get_oauth_callback_url(&self.client_id, state),
            OauthType::Workos => WorkosOauthService::get_oauth_callback_url(&self.client_id, state),
        }
    }

    pub fn get_relogin_uri(&self) -> String {
        if let Some(mut path) = self.redirect_path.clone() {
            let suffix_len = format!("__/oauth/{}/callback", self.typ).len();
            if path.len() > suffix_len {
                path.truncate(path.len() - suffix_len);
            }
            path
        }
        else {
            "".to_string()
        }
    }

    /// Get the Oauth user from the provider using the provided code
    pub async fn get_oauth_user(&self, code: &str) -> Result<OauthUser, anyhow::Error> {
        match self.typ {
            OauthType::Gitea => {
                GiteaOauthService::get_oauth_user(
                    self.base_url.as_ref().expect("base_url is required for Gitea"),
                    &self.client_id,
                    &self.client_secret,
                    code,
                    self.redirect_path.as_ref().expect("redirect_path is required for Gitea"),
                )
                .await
            }
            OauthType::Github => {
                GithubOauthService::get_oauth_user(&self.client_id, &self.client_secret, code).await
            }
            OauthType::Workos => {
                WorkosOauthService::get_oauth_user(&self.client_id, &self.client_secret, code).await
            }
        }
    }
}

#[derive(Debug, Clone)]
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
    Gitea,
    Github,
    Workos,
}

impl Display for OauthType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OauthType::Gitea  => write!(f, "gitea"),
            OauthType::Github => write!(f, "github"),
            OauthType::Workos => write!(f, "workos"),
        }
    }
}
