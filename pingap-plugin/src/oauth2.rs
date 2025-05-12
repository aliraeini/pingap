use std::sync::Arc;
use std::time::SystemTime;
// use std::{borrow::Cow, collections::HashMap};

use async_trait::async_trait;
use cookie::Cookie;
use ctor::ctor;
use http::StatusCode;
use pingap_config::PluginConf;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep};
use proksi_oauth2::secure_cookie::create_secure_cookie;
use proksi_oauth2::{jwt, shared};
use proksi_oauth2::shared::validate_user_from_provider;
use proksi_oauth2::provider::{OauthType, OauthUser, Provider};
use serde_json::json;
use short_crypt::ShortCrypt;
use tracing::debug;

use bytes::Bytes;

use super::{
    get_hash_key, get_plugin_factory, get_str_conf,
    Error,
};

type Result<T, E = Error> = std::result::Result<T, E>;
// New providers can be added here

// Shared state for Oauth2 flows (should be cleaned up after fetching for the first time)
// TODO find a way to clean up/expire the state
const COOKIE_NAME: &str = "__Secure_Auth_PRK_JWT";


fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}


/// Configuration struct for TLS/SSL certificates
pub struct OAuth2 {
    /// Plugin step to apply this plugin
    pub plugin_step: PluginStep,
    /// TLS certificate in PEM format or base64 encoded
    pub provider: String,
    /// TLS certificate in PEM format or base64 encoded
    pub client_id: String,
    /// Private key in PEM format or base64 encoded
    pub client_secret: String,
    pub jwt_secret: String,
    pub validations: serde_json::Value,
    // Generates in-memory secret for oauth2 states
    pub short_crypt: ShortCrypt,
    /// HTTP response returned when the Authorization header is missing
    /// Includes WWW-Authenticate header to prompt browser's authentication dialog
    /// Body contains a user-friendly message about missing authorization
    pub miss_authorization_resp: HttpResponse,
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
        let hash_value = get_hash_key(value);

        let validations = json!([
            {
                "type": "email",
                "value": ["user@example.com", "other@example.com"]
            }
        ]);

        let short_cryp = short_crypt::ShortCrypt::new(uuid::Uuid::new_v4().to_string());

        let params = Self {
            client_id: get_str_conf(value, "client_id"),
            client_secret: get_str_conf(value, "client_secret"),
            plugin_step: PluginStep::Request,
            short_crypt: short_cryp,
            miss_authorization_resp: HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from_static(b"Key missing"),
                ..Default::default()
            },
            // unauthorized_resp: HttpResponse {
            //     status: StatusCode::UNAUTHORIZED,
            //     body: Bytes::from_static(b"Key auth fail"),
            //     ..Default::default()
            // },
            provider: get_str_conf(value, "identity_provider"),
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

    /// Checks if the user is authorized to access the protected Oauth2 resource
    /// This is part of the validation object in the oauth2 configuration.
    fn is_authorized(user: &OauthUser, validations: Option<&serde_json::Value>) -> bool {
        validate_user_from_provider(user, validations)
    }

    /// Redirects the user to the Oauth provider to authenticate.
    async fn redirect_to_oauth_callback(
        &self,
        session: &mut Session,
        oauth_provider: &Provider,
    ) -> Result<bool> {
        let current_address = session.req_header().uri.to_string();
        // let host = session.req_header().uri.host().unwrap_or_default();

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
            oauth_provider.get_oauth_callback_url(&state),
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

    /// Ends the Oauth2 flow and returns HTTP unauthorized if errors occur during the Oauth process
    async fn unauthorized_response(&self, session: &mut Session) -> Result<bool> {
        let res_headers = ResponseHeader::build_no_case(StatusCode::UNAUTHORIZED, Some(1))
            .map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;
        

        // Store the current path in the stat
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
        let cookie_header = session.req_header().headers.get_all("cookie");

        let mut secure_jwt: Option<Cookie> = None;

        for cookie in cookie_header {
            let cookie_str = cookie.to_str().unwrap();

            let Ok(ck) = Cookie::parse(cookie_str) else {
                continue;
            };

            if ck.name() == COOKIE_NAME {
                secure_jwt = Some(ck);
            }
        }

        if secure_jwt.is_none() {
            return Ok(false); // will redirect to oauth callback
        }

        let decoded = jwt::decode_jwt(secure_jwt.unwrap().value(), jwt_secret.as_bytes());

        // Token expired or another err
        match decoded {
            Ok(decoded) => {
                if !Self::is_authorized(&decoded.into(), validations) {
                    return self.unauthorized_response(session).await;
                }
            }
            Err(_) => {
                return Ok(false); // will redirect to oauth callback
            }
        }

        Ok(true)
    }

    fn parse_provider(
        provider: &String,
    ) -> Result<OauthType> { 

        match provider.as_str() {
            "github" => Ok(OauthType::Github),
            "workos" => Ok(OauthType::Workos),
            _ => panic!("Provider '{}' not found in the plugin configuration", provider),
        }
    }

    /// Oauth2 filters requests with/without the required Secure Cookie
    /// If the request has the required cookie, the request is allowed to pass through
    /// and we perform a JWT validation
    /// If the request does not have the required cookie, the request is blocked
    /// and we return a redirect to the oauth login flow (HTTP 307)
    async fn request_filter(
        &self,
        session: &mut Session,
        host: &mut String,
    ) -> Result<bool> {
        let config = self;
        // Nothing to do if the plugin configuration is not present
        if config.client_id.is_empty() || config.client_secret.is_empty() {
            return Ok(false);
        }

        let provider = Self::parse_provider(&config.provider)?;

        // Callback path based on the selected provider
        let callback_path = format!("/__/oauth/{}/callback", &config.provider);

        // Create provider service
        let oauth_provider = Provider {
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            typ: provider,
        };

        let uri = &session.req_header().uri;

        // Step 0. Check if the request is for the Oauth Callback URL
        if uri.path() == callback_path {
            let Some(query) = uri.query() else {
                return self.unauthorized_response(session).await;
            };

            let query_params = shared::from_string_to_query_params(query);

            let Some(code) = query_params.get("code") else {
                tracing::info!("missing code in the query");
                return self.unauthorized_response(session).await;
            };

            let Some(state) = query_params.get("state") else {
                tracing::info!("missing state in the query");
                return self.unauthorized_response(session).await;
            };

            // Get encrypted state and decrypt it
            let Ok(encrypted) = self.short_crypt.decrypt_url_component(state) else {
                tracing::info!("state does not exist or was removed");
                return self.unauthorized_response(session).await;
            };

            let Ok(redirect_from_state) = String::from_utf8(encrypted) else {
                tracing::info!("state is not a valid UTF-8 string");
                return self.unauthorized_response(session).await;
            };

            let (timestamp, current_address) = redirect_from_state.split_once(';').unwrap();
            let timestamp = timestamp.parse::<u64>().unwrap();
            let current_address = current_address.to_string();

            // Check if the state is still valid from the last 120 seconds (2 minutes)
            if timestamp + 120 < get_current_timestamp() {
                tracing::info!("state has expired");
                return self.unauthorized_response(session).await;
            }

            // Step 1: Exchange the code for an access token
            let user = match oauth_provider.get_oauth_user(code).await {
                Err(err) => {
                    tracing::error!(
                        "Failed to exchange code {code}, state {redirect_from_state}: {err}"
                    );
                    return self.unauthorized_response(session).await;
                }
                Ok(user) => user,
            };

            // Validate if user is authorized to access the protected resource
            if !Self::is_authorized(&user, Some(&config.validations)) {
                tracing::info!("user is not authorized {:?}", user);
                return self.unauthorized_response(session).await;
            }

            let jwt_cookie = create_secure_cookie(&user, &config.jwt_secret, &host)
                .map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;

            let mut res_headers = ResponseHeader::build_no_case(StatusCode::FOUND, Some(1))
                .map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;
            res_headers.insert_header(http::header::SET_COOKIE, jwt_cookie.to_string())
            .map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;
            res_headers.insert_header(http::header::LOCATION, current_address)
            .map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;
            res_headers.insert_header(
                http::header::CACHE_CONTROL,
                "no-store, no-cache, must-revalidate, max-age=0",
            ).map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;

            session
                .write_response_header(Box::new(res_headers), true)
                .await
                .map_err(|e| Error::Invalid { category: "oauth2".to_string(), message: e.to_string() })?;

            return Ok(true);
        }

        if self
            .validate_cookie(session, &config.jwt_secret, Some(&config.validations))
            .await?
        {
            // If the user is not authorized, return true to
            // interrupt the request
            return Ok(false);
        }

        self.redirect_to_oauth_callback(session, &oauth_provider)
            .await
    }
}

    // // Generates in-memory secret for oauth2 states
    // pub short_crypt: ShortCrypt,

#[async_trait]
impl Plugin for OAuth2 {
    /// Returns the unique hash key for this plugin instance.
    #[inline]
    fn hash_key(&self) -> String {
        self.hash_value.clone()
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
    ) -> pingora::Result<(bool, Option<HttpResponse>)> {

        let config = self;
        // Plugin steps are configurable to support different authentication points
        // Common steps: request (early auth) or proxy_upstream (pre-forwarding)
        if step != self.plugin_step {
            return Ok((false, None));
        }
        // Nothing to do if the plugin configuration is not present
        if config.client_id.is_empty() {
            return Ok((false, None));
        }
        let mut host = session.req_header().uri.host().unwrap_or_default().to_string();

        let xxx = self.request_filter(session, &mut host).await;
        match xxx {
            Ok(xxx) => {
                return Ok((xxx, None));
            }
            Err(e) => {
                tracing::error!("Error request_filter {:?}", e);
                return Ok((false, Some(self.miss_authorization_resp.clone())));
            }
       };
    }
}

#[ctor]
fn init() {
    let factory = get_plugin_factory();
    factory
        .register("oauth2", |params| Ok(Arc::new(OAuth2::new(params)?)));

}