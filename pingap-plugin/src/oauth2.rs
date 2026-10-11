use dashmap::DashMap;
use std::borrow::Cow;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
// use std::{borrow::Cow, collections::HashMap};

use async_trait::async_trait;
use http::StatusCode;
use pingap_config::PluginConf;
use pingora::http::ResponseHeader;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use proksi_oauth2::secure_cookie::{get_jwt_cookie};
use proksi_oauth2::{jwt};
use proksi_oauth2::provider::{Provider};
use serde_json::json;
use short_crypt::ShortCrypt;
use tracing::{debug};

use crate::oauth2_utils::{apply_rewrite, filter_login_callback, get_current_timestamp, get_reg_rewrite, logout_response, parse_provider, relogin_response};

use super::{
    get_hash_key, get_str_conf,
    get_str_slice_conf, Error,
};

type Result<T, E = Error> = std::result::Result<T, E>;
// New providers can be added here



/// Configuration struct for TLS/SSL certificates
pub struct OAuth2 {
    /// Plugin step to apply this plugin
    pub plugin_step: PluginStep,
    /// Provider config, gitea/forgejo, github, etc.
    pub oauth_provider: Provider,
    pub rewrite_uri: Option<String>,
    pub jwt_secret: String,
    pub validations: serde_json::Value,
    // Generates in-memory secret for oauth2 states
    pub short_crypt: ShortCrypt,
    // Server-side session storage
    pub srvr_sessions: Arc<DashMap<String, String>>,
    // Unique identifier for plugin instance, used for caching and identification
    hash_value: String,
}

impl TryFrom<&PluginConf> for OAuth2 {
    type Error = Error;
    /// Attempts to create a OAuth2Config instance from a plugin configuration.
    ///
    /// # Arguments
    /// * `value` - The plugin configuration containing authentication settings
    ///
    /// # Returns
    /// * `Result<Self>` - A new OAuth2Config instance if configuration is valid
    ///
    /// # Errors
    /// * When neither header nor query parameter is configured
    /// * When no valid keys are provided
    /// * When header name is invalid
    /// * When plugin step is not request or proxy_upstream
    fn try_from(value: &PluginConf) -> Result<Self> {
        print!("{}", value);
        let hash_value = get_hash_key(value);
        tracing::info!(
            category = "oauth2",
            value = format!("{}", value),
            "OAuth config loading",
        );
        let validations = {
            let mut v = Vec::new();
            let validations_map = [
                ("email", "valid_emails"),
                ("team_id", "valid_teams"),
                ("org_id", "valid_organizations"),
                ("username", "valid_usernames"),
            ];

            for (validation_type, config_key) in validations_map {
                let values = get_str_slice_conf(value, config_key);
                if !values.is_empty() {
                    v.push(json!({"type": validation_type, "value": values}));
                }
            }

            serde_json::Value::Array(v)
        };

        let short_cryp = short_crypt::ShortCrypt::new(uuid::Uuid::new_v4().to_string());

        let provider = get_str_conf(value, "provider");
        let base_url = value
            .get("base_url")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        if provider == "gitea" && base_url.is_none() {
            return Err(Error::Invalid {
                category: "oauth2".to_string(),
                message: "base_url is required for gitea provider".to_string(),
            });
        }
        let redirect_path = value
            .get("redirect_path")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| format!("{}__/oauth/{}/callback", s, provider)); // sync with provider
        let rewrite_uri = value
            .get("rewrite_uri")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        let end_session_endpoint = value
            .get("end_session_endpoint")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        let logout_path = get_str_conf(value, "logout_path");

        // Create provider service
        let oauth_provider = Provider {
            base_url: base_url,
            client_id: get_str_conf(value, "client_id"),
            client_secret: get_str_conf(value, "client_secret"),
            redirect_path: redirect_path,
            logout_path: if logout_path.is_empty() { None } else { Some(logout_path) },
            end_session_endpoint,
            typ: parse_provider(&provider)?,
        };

        let params = Self {
            rewrite_uri,
            plugin_step: PluginStep::Request,
            oauth_provider,
            short_crypt: short_cryp,
            srvr_sessions: Arc::new(DashMap::new()),
            // unauthorized_resp: HttpResponse {
            //     status: StatusCode::UNAUTHORIZED,
            //     body: Bytes::from_static(b"Key auth fail"),
            //     ..Default::default()
            // },
            jwt_secret: "todo!()".to_string(),
            validations: validations,
            hash_value: hash_value,
        };

        Ok(params)
    }
}

impl OAuth2 {
    /// Creates a new OAuth2Config plugin instance from the provided configuration.
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<Self>` - A new OAuth2Config instance or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new key auth plugin");
        Self::try_from(params)
    }

    /// Redirects the user to the Oauth provider to authenticate.
    async fn redirect_to_oauth_callback(
        &self,
        session: &mut Session,
        _ctx: &mut Ctx,
        oauth_provider: &Provider,
        redirect_path: &str,
    ) -> Result<bool> {
        let current_address = session.req_header().uri.to_string();


        let state = format!("{};{}", get_current_timestamp(), current_address);
        let state = self.short_crypt.encrypt_to_url_component(&state);
        
        let mut res_headers =
            ResponseHeader::build_no_case(StatusCode::TEMPORARY_REDIRECT, Some(1))
            .map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;

        // Removes any cookie to prevent the user from being redirected
        // to the Oauth provider over and over
        // let removed_cookie = remove_secure_cookie(host);
        // res_headers.append_header(http::header::SET_COOKIE, removed_cookie.to_string())?;

        res_headers.append_header(
            http::header::LOCATION,
            oauth_provider.get_oauth_callback_url(&state, &redirect_path),
        ).map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;
        res_headers.append_header(
            http::header::CACHE_CONTROL,
            "no-store, no-cache, must-revalidate, max-age=0",
        ).map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;

        // Store the current path in the state
        session
            .write_response_header(Box::new(res_headers), true)
            .await
            .map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;

        // Finish the request, we don't want to continue processing
        // and the user has been redirected
        Ok(true)
    }

    /// Validates a given cookie and returns true if
    /// the user is authorized
    async fn validate_cookie(
        &self,
        session: &mut Session,
        jwt_secret: &str,
        validations: Option<&serde_json::Value>,
    ) -> Result<bool> {
        let _ = validations;

        let jwt_cookie = get_jwt_cookie(&session.req_header().headers);

        if jwt_cookie.is_none() {
            return Ok(false); // will redirect to oauth callback
        }

        let decoded = jwt::decode_jwt(jwt_cookie.clone().unwrap().value(), jwt_secret.as_bytes());

        // Token expired or another err
        match decoded {
            Ok(_) => { // just check if it is a valid cookie and generated by us
                if self.srvr_sessions.contains_key(jwt_cookie.clone().unwrap().value()) {
                    return Ok(true);
                }

                // let authed = Self::is_authorized(&decoded.into(), validations);

                // if !authed {
                //     return self.unauthorized_response(session).await;
                // }
            }
            Err(_) => {
                self.srvr_sessions.remove(jwt_cookie.unwrap().value());
                return Ok(false); // will redirect to oauth callback
            }
        }

        self.srvr_sessions.remove(jwt_cookie.unwrap().value());
        Ok(false)
    }

}

    // // Generates in-memory secret for oauth2 states
    // pub short_crypt: ShortCrypt,

#[async_trait]
impl Plugin for OAuth2 {
    /// Returns the unique hash key for this plugin instance.
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles authentication for incoming requests.
    ///
    /// This function performs the following steps:
    /// 1. Verifies the plugin is running at the correct step
    /// 2. Extracts authentication key from header or query parameter
    /// 3. Validates the key against configured valid keys
    /// 4. Optionally applies delay on failed attempts
    /// 5. Optionally hides credentials after successful validation
    ///
    /// # Arguments
    /// * `step` - Current plugin execution step
    /// * `session` - HTTP session containing request details
    /// * `_ctx` - Ctx context (unused in this plugin)
    ///
    /// # Returns
    /// * `pingora::Result<Option<HttpResponse>>` - None if authentication succeeds,
    ///   or Some(HttpResponse) with 401 status if authentication fails
    ///
    /// # Security Features
    /// * Configurable delay on failed attempts to prevent brute force attacks
    /// * Optional credential hiding to prevent key leakage
    /// * Distinct error responses for missing vs invalid credentials
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {

        let config = &self.oauth_provider;
        // Plugin steps are configurable to support different authentication points
        // Common steps: request (early auth) or proxy_upstream (pre-forwarding)
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Continue);
        }
        // Nothing to do if the plugin configuration is not present
        if config.client_id.is_empty() || config.client_secret.is_empty() {
            return Ok(RequestPluginResult::Skipped);
        }

        let redirect_path = config.redirect_path.clone().unwrap_or_default();
        let uri = &session.req_header().uri;

        // Handle logout
        if let Some(logout_path) = &config.logout_path {
            if uri.path() == logout_path {
                return logout_response(session, _ctx, &self.oauth_provider).await
            }
        }


        // Step 0. Check if the request is for the Oauth Callback URL
        if uri.path() == http::Uri::from_str(&redirect_path).unwrap().path() {
            return filter_login_callback(session, _ctx, &config, &self.jwt_secret, &self.validations, &self.short_crypt, &self.srvr_sessions).await;
        }

        if self.validate_cookie(session, &self.jwt_secret, Some(&self.validations)).await
        .map_err(|e| { tracing::info!( category = "oauth2", e = format!("{:?}",  e),
                res_headers = format!("{:?}",  session.req_header()), 
                "\n\n INVLIDDD validate__cookie",
            );   pingap_core::new_internal_error(500, e.to_string() )})? {

            // If the user is not authorized, return true to
            // interrupt the request

            let reg_rewrite = get_reg_rewrite(&self.rewrite_uri);
            let variables = if let Some(features) = &mut _ctx.features {
                features.variables.take()
            } else {
                None
            };
            let header = session.req_header_mut();
            apply_rewrite(&reg_rewrite, header, variables.as_ref()); // modify path/directory
            tracing::info!( category = "oauth2",
                uri = format!("{:?}",  session.req_header().uri),
                "REWROTE:",
            );  std::io::stderr().flush().unwrap();
            return Ok(RequestPluginResult::Continue);
        }

        let executed = self.redirect_to_oauth_callback(session, _ctx, &config, &redirect_path)
            .await;

        match executed {
            Ok(executed) => {
                if executed {
                    return Ok(RequestPluginResult::Continue);
                } else {
                    return Ok(RequestPluginResult::Skipped);
                }
            }
            Err(e) => {
                tracing::error!("in req__filt {:?}", e);
                return relogin_response(&self.oauth_provider, "Internal error xxx"); // TDOD or true?
            }
       };
    }
}

register_plugin!("oauth2", OAuth2);