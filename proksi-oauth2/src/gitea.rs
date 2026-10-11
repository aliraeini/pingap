use std::borrow::Cow;
use tracing;
use http;

use anyhow::bail;
use serde::Deserialize;

use super::{provider::OauthUser, provider::HTTP_CLIENT};

/// Gitea `OAuth2` plugin
pub(super) struct GiteaOauthService;

impl GiteaOauthService {
    /// Get the OAuth callback URL
    /// This is used to redirect the user to the Gitea login page
    /// and then to the OAuth callback URL
    /// The state parameter is used to prevent CSRF attacks
    /// and to ensure that the callback is coming from the correct source
    ///
    /// user:email is the scope that is requested and you should update the app settings
    /// to add the scope to the app
    pub fn get_oauth_callback_url(base_url: &str, client_id: &str, redirect_uri: &str, state: &str) -> String {
        format!("{base_url}/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&state={state}&scope=user:email&response_type=code")
    }

    pub async fn get_oauth_user(
        base_url: &str,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_path: &str,
    ) -> Result<OauthUser, anyhow::Error> {
        let token = Self::get_oauth_token(base_url, client_id, client_secret, code, redirect_path).await?;

        let Some(access_token) = token.access_token else {
            bail!("Failed to get access token from Gitea: {:?}", token.error);
        };

        let user = Self::get_user_info(base_url, &access_token).await?;
        let emails = Self::get_user_emails(base_url, &access_token).await?;
        let Some(primary_email) = emails.iter().find(|e| e.primary) else {
            bail!("Gitea user {} has no primary email", user.login);
        };

        // Matched against `valid_organizations` and `valid_teams` by name:
        // an organization as `org`, a team as `org/team`
        let orgs = Self::get_paged::<GiteaOrgResponse>(base_url, &access_token, "user/orgs").await?;
        let teams = Self::get_paged::<GiteaTeamResponse>(base_url, &access_token, "user/teams").await?;

        Ok(OauthUser {
            email: Cow::Owned(primary_email.email.to_string()),
            team_ids: teams
                .iter()
                .filter_map(|t| t.organization.as_ref().map(|o| format!("{}/{}", o.name, t.name)))
                .collect(),
            organization_ids: orgs.iter().map(|o| o.name.to_string()).collect(),
            usernames: vec![user.login.to_string()],
        })
    }

    /// Get every item of a paginated Gitea API list, e.g. `user/orgs`
    async fn get_paged<T: serde::de::DeserializeOwned>(
        base_url: &str,
        token: &str,
        path: &str,
    ) -> Result<Vec<T>, anyhow::Error> {
        const LIMIT: usize = 50;
        let mut items = Vec::new();
        for page in 1.. {
            let response = HTTP_CLIENT
                .get(format!("{base_url}/api/v1/{path}?limit={LIMIT}&page={page}"))
                .bearer_auth(token)
                .header(http::header::USER_AGENT, "pingora/0.4.0")
                .send()
                .await?
                .error_for_status()?;

            let body = response.json::<Vec<T>>().await?;
            let len = body.len();
            items.extend(body);
            // Gitea may cap `limit` below what was asked, so only an empty page ends the list
            if len == 0 || page >= 100 {
                break;
            }
        }
        Ok(items)
    }

    /// Get the OAuth token
    /// Retrieves the token from the Gitea API to be used for further requests
    async fn get_oauth_token(
        base_url: &str,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_path: &str,
    ) -> Result<GiteaTokenResponse, anyhow::Error> {
        let params = &[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_path),
        ];
        let response = HTTP_CLIENT
            .post(format!("{base_url}/login/oauth/access_token"))
            .form(params) // Use .form() to send data in the body
            .header(http::header::ACCEPT, "application/json")
            .send()
            .await?;

        let body = response.json::<GiteaTokenResponse>().await?;

        Ok(body)
    }

    /// Get the user public profile information
    async fn get_user_info(base_url: &str, token: &str) -> Result<GiteaUserResponse, anyhow::Error> {
        tracing::debug!("Getting user info from Gitea");

        let response = HTTP_CLIENT
            .get(format!("{base_url}/api/v1/user"))
            .bearer_auth(token)
            .header(http::header::USER_AGENT, "pingora/0.4.0")
            .send()
            .await?;

        let body = response.json::<GiteaUserResponse>().await?;
        Ok(body)
    }

    /// Get the user emails in order to find the primary one
    async fn get_user_emails(base_url: &str, token: &str) -> Result<Vec<GiteaEmailResponse>, anyhow::Error> {
        tracing::debug!("Getting user emails from Gitea");

        let response = HTTP_CLIENT
            .get(format!("{base_url}/api/v1/user/emails"))
            .bearer_auth(token)
            .header(http::header::USER_AGENT, "pingora/0.4.0")
            .send()
            .await?;

        let body = response.json::<Vec<GiteaEmailResponse>>().await?;
        Ok(body)
    }
}

/// Response from `POST gitea-url/login/oauth/access_token`
/// Can be an error response (with an error property) or a success response
#[derive(Deserialize, Debug)]
struct GiteaTokenResponse {
    error: Option<Cow<'static, str>>,
    access_token: Option<Cow<'static, str>>,
}

/// Item Response from `gitea-url/api/v1/user/emails`
/// `{ [ {"email":"user@example.com","primary":true,"verified":true} ]  }`
#[derive(Deserialize, Debug)]
struct GiteaEmailResponse {
    email: Cow<'static, str>,
    primary: bool,
}

/// Response from `gitea-url/api/v1/user`
/// `{ "name": "John Doe", username: "johndoe" } }`
#[derive(Deserialize, Debug)]
struct GiteaUserResponse {
    login: Cow<'static, str>,
}

/// Item response from `gitea-url/api/v1/user/orgs`
#[derive(Deserialize, Debug)]
struct GiteaOrgResponse {
    name: Cow<'static, str>,
}

/// Item response from `gitea-url/api/v1/user/teams`
#[derive(Deserialize, Debug)]
struct GiteaTeamResponse {
    name: Cow<'static, str>,
    organization: Option<GiteaOrgResponse>,
}
