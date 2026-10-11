
use std::time::SystemTime;
use bytes::Bytes;
use std::str::FromStr;

use dashmap::DashMap;
use http::{StatusCode};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use pingap_core::{Ctx, HttpResponse, RequestPluginResult, new_internal_error};
use proksi_oauth2::provider::{OauthType, Provider};
use proksi_oauth2::shared::{self, validate_user_from_provider};
use short_crypt::ShortCrypt;
use proksi_oauth2::secure_cookie::{create_secure_cookie, remove_secure_cookie};

// AQR
use ahash::AHashMap;
use tracing::{debug, error};
use regex::Regex;


use super::{
    Error,
};
type Result<T, E = Error> = std::result::Result<T, E>;



pub fn relogin_response(
    config: &Provider,
    msg: &str,
) -> pingora::Result<RequestPluginResult> {
        let logout_link = config.logout_path.as_deref().unwrap_or("/login");

        let logout_form = format!(r#"<form action="{}" method="post" style="display: inline-block; margin-left: 0.5rem;" onsubmit="window.open('about:blank','new_form_auth','width=500,height=300');"  target="new_form_auth">
                <button type="submit" style="background-color: #315574; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 1rem; font-family: inherit;">Sign Out</button>
            </form>"#, logout_link);
        let binding = http::Uri::from_str(&config.get_relogin_uri()).unwrap();
        let login_link = binding.path();
        let body = format!(r###"<!DOCTYPE html>
<html>
<head>
  <title>Unauthorized</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background-color: #f8f9fa; }}
    .container {{ text-align: center; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
    h1 {{ color: #dc3545; margin-bottom: 1rem; }}
    p {{ color: #6c757d; margin-bottom: 1.5rem; }}
    a {{ display: inline-block; padding: 0.5rem 1rem; background-color: #0d6efd; color: white; text-decoration: none; border-radius: 4px; transition: background-color 0.2s; }}
    a:hover {{ background-color: #0b5ed7; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Unauthorized</h1>
    {msg}
    <p>Please logout and try again a valid account.</p>
    <p>Check out browser console for more details.</p>
    <div>
      {logout_form}
      <a href="{login_link}">Try again</a>
    </div>
  </div>
</body>
</html>"###);

 Ok(RequestPluginResult::Respond(HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                body: Bytes::from(body),
                ..Default::default()
            } ))
}


/// Get the content length from http request header.
pub fn get_reg_rewrite(conf_value: &Option<String>) -> Option<(Regex, String)> {
    if let Some(value) = conf_value {
        let mut arr: Vec<&str> = value.split(' ').collect();
        if arr.len() == 1 && arr[0].contains("$") {
            arr.push(arr[0]);
            arr[0] = ".*";
        }

        let value = if arr.len() == 2 { arr[1] } else { "" };
        if let Ok(re) = Regex::new(arr[0]) {
            return Some((re, value.to_string()));
        } else {
            None
        }
    } else {
            None
    }
}

/// Applies URL rewriting rules if configured for this location.
///
/// This method performs path rewriting based on regex patterns and replacement rules.
/// It supports variable interpolation from captured values in the host matching.
///
/// # Arguments
/// * `header` - Mutable reference to the request header containing the URI to rewrite
/// * `variables` - Optional map of variables captured from host matching that can be interpolated
///   into the replacement value
///
/// # Returns
/// * `bool` - Returns true if the path was rewritten, false if no rewriting was performed
///
/// # Examples
/// ```
/// // Configuration example:
/// // rewrite: "^/users/(.*)$ /api/users/$1"
/// // This would rewrite "/users/123" to "/api/users/123"
/// ```
///
/// # Notes
/// - Preserves query parameters when rewriting the path
/// - Logs debug information about path rewrites
/// - Logs errors if the new path cannot be parsed as a valid URI
pub fn apply_rewrite(
    reg_rewrite: &Option<(Regex, String)>,
    header: &mut RequestHeader,
    variables: Option<&AHashMap<String, String>>,
) -> bool {
    if let Some((re, value)) = &reg_rewrite {
        let mut replace_value = value.to_string();
        // replace variables for rewrite value
        if let Some(variables) = variables {
            for (k, v) in variables.iter() {
                replace_value = replace_value.replace(k, v);
            }
        }
        let path = header.uri.path();
        let mut new_path = if re.to_string() == ".*" {
            replace_value
        } else {
            re.replace(path, replace_value).to_string()
        };
        if path == new_path {
            return false;
        }
        // preserve query parameters
        if let Some(query) = header.uri.query() {
            new_path = format!("{new_path}?{query}");
        }
        debug!(category = "location", new_path, "rewrite path");
        // set new uri
        if let Err(e) =
            new_path.parse::<http::Uri>().map(|uri| header.set_uri(uri))
        {
            error!(category = "location", error = %e, new_path = new_path, "new path parse fail");
        }
        return true;
    }
    false
}


pub async fn filter_login_callback(
    session: &mut Session,
    _ctx: &mut Ctx,
    config: &Provider,
    jwt_secret: &str,
    validations: &serde_json::Value,
    short_crypt: &ShortCrypt,
    srvr_sessions: &DashMap<String, String>
) -> pingora::Result<RequestPluginResult> {

    // backup host before messing up session for jwt
    let host = session.req_header().headers.get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // let host = session.req_header().uri.host().unwrap_or_default().to_string();

    let Some(query) = &session.req_header().uri.query() else {
        return relogin_response(config, "missing__query");
    };

    let query_params = shared::from_string_to_query_params(query);

    let Some(code) = query_params.get("code") else {
        tracing::info!("missing code in the query");
        return relogin_response(config, "missing__code");
    };

    let Some(state) = query_params.get("state") else {
        tracing::info!("missing state in the query");
        return relogin_response(config, "missing__state");
    };

    // Get encrypted state and decrypt it
    let Ok(encrypted) = short_crypt.decrypt_url_component(state) else {
        tracing::info!("state does not exist or was removed");
        return relogin_response(config, "state__does__not__exist");
    };

    let Ok(redirect_from_state) = String::from_utf8(encrypted) else {
        tracing::info!("state is not a valid UTF-8 string");
        return relogin_response(config, "state__is__not__valid");
    };

    let (timestamp, current_address) = redirect_from_state.split_once(';').unwrap();
    let timestamp = timestamp.parse::<u64>().unwrap();
    let current_address = current_address.to_string();

    // Check if the state is still valid from the last 120 seconds (2 minutes)
    if timestamp + 120 < get_current_timestamp() {
        tracing::info!(category = "oauth2", "state has expired");
        return relogin_response(config, "state__has__expired");
    }

    // Step 1: Exchange the code for an access token
    let user = match config.get_oauth_user(code).await {
        Err(err) => {
            tracing::error!(category = "oauth2",
                current__address = current_address.to_string(),
                code = code.to_string(),
                redirect_from_state = redirect_from_state,
                req_header = format!("{:?}",  session.req_header()),
                "Failed to exchange code {code}, state {redirect_from_state}: {err}"
            );
            return relogin_response(config, "Failed to exchange login code");
        }
        Ok(user) => user,
    };
    tracing::info!(category = "oauth2", "user: {:?}\n\n", user);

    // Validate if user is authorized to access the protected resource
    if !validate_user_from_provider(&user, Some(&validations)) {
        tracing::info!(category = "oauth2", "user is not authorized {:?}", user);
            return relogin_response(config, "not authorised");
    }
    // host = host.remove_port();
    let jwt_cookie = match create_secure_cookie(&user, &jwt_secret, &host, &current_address) {
        Ok(cookie) => cookie,
        Err(e) => {
            error!(category = "oauth2", "Failed to create secure cookie: {e}");
            return relogin_response(config, "Failed to create secure cookie");
        }
    };

    let mut res_headers = match ResponseHeader::build_no_case(StatusCode::FOUND, Some(1)) {
        Ok(headers) => headers,
        Err(e) => {
            error!(category = "oauth2", "Failed to build response headers: {e}");
            return relogin_response(config, "Failed to build response headers");
        }
    };

    let _ = res_headers.insert_header(http::header::SET_COOKIE, jwt_cookie.to_string())
        .map_err(|e| error!(category = "oauth2", "Failed to set cookie header: {e}") );
    let _ = res_headers.insert_header(http::header::LOCATION, &current_address)
        .map_err(|e| error!(category = "oauth2", "Failed to set location header: {e}") );
    let _ = res_headers.insert_header(http::header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0",)
        .map_err(|e| error!(category = "oauth2", "Failed to set cache-control header: {e}") );

    srvr_sessions.insert(jwt_cookie.value().to_string(), "valid".to_string());

    let _ = session
        .write_response_header(Box::new(res_headers), true)
        .await
        .map_err(|e| error!(category = "oauth2", "Failed to set cache-control header: {e}") );

    return Ok(RequestPluginResult::Respond(HttpResponse::redirect(&current_address)?));
}


pub async fn logout_response(
    session: &mut pingora::proxy::Session,
    _ctx: &mut pingap_core::Ctx,
    config: &Provider,
) -> pingora::Result<RequestPluginResult> {

    let host = session.req_header().headers.get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let removal_cookie = remove_secure_cookie(host); // Assuming remove_secure_cookie is synchronous

    let mut res_headers = ResponseHeader::build_no_case(StatusCode::TEMPORARY_REDIRECT, Some(2))
        .map_err(|e| new_internal_error(500, e.to_string()))?;

    res_headers.insert_header(http::header::SET_COOKIE, removal_cookie.to_string())
        .map_err(|e| new_internal_error(500, e.to_string()))?;

    if let Some(logout_url) = &config.end_session_endpoint {
        res_headers.insert_header(http::header::LOCATION, logout_url.as_str())
            .map_err(|e| new_internal_error(500, e.to_string()))?;
    } else {
        // Redirect to login page if no OIDC logout URL is provided.
        res_headers.insert_header(http::header::LOCATION, "/login")
            .map_err(|e| new_internal_error(500, e.to_string()))?;
    }

    session
        .write_response_header(Box::new(res_headers), true)
        .await
        .map_err(|e| new_internal_error(500, e.to_string()))?;

    return Ok(RequestPluginResult::Continue);
}


pub fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn parse_provider(
    provider: &String,
) -> Result<OauthType, Error> {

    match provider.as_str() {
        "gitea"  => Ok(OauthType::Gitea),
        "github" => Ok(OauthType::Github),
        "workos" => Ok(OauthType::Workos),
        _ => panic!("Provider '{}' not found in the plugin configuration", provider),
    }
}

