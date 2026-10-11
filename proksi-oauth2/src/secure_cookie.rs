use cookie::{time::OffsetDateTime, Cookie, SameSite};
use http::{HeaderMap, HeaderValue};

use crate::jwt;

use super::provider::OauthUser;

// Shared state for Oauth2 flows (should be cleaned up after fetching for the first time)
// TODO find a way to clean up/expire the state
const COOKIE_NAME: &str = "__Pingap_auth_JWT";

/// Creates a secure cookie for the user containing the JWT token
pub fn create_secure_cookie(
    user: &OauthUser,
    jwt_secret: &str,
    host: &str,
    _current_address: &str,
) -> Result<Cookie<'static>, anyhow::Error> {
    let jwt_token = jwt::encode_jwt(&user.email, jwt_secret.as_bytes(), user)?;


    let host_without_port = host.split(':').next().unwrap_or(host);
    let cookie_domain = host_without_port.to_owned(); // extract_cookie_domain(host_without_port);
    // let current_addres = current_address.to_owned();


    let expiration = OffsetDateTime::now_utc().checked_add(cookie::time::Duration::days(1));

    Ok(Cookie::build((COOKIE_NAME, jwt_token))
        .secure(true)
        .domain(cookie_domain)
        .path("/") // @Sync prefix_path
        .expires(expiration)
        .http_only(true)
        .same_site(SameSite::Lax)
        .build())
}

/// Removes the secure cookie for the user
pub fn remove_secure_cookie(host: &str) -> Cookie<'static> {
    let host_without_port = host.split(':').next().unwrap_or(host);
    let cookie_domain = host_without_port.to_owned(); // 
    let mut cookie = Cookie::build((COOKIE_NAME, ""))
        .secure(true)
        .domain(cookie_domain.clone())
        .path("/")  // @Sync prefix_path
        //.expires(OffsetDateTime::now_utc().checked_add(cookie::time::Duration::days(1)))
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
    cookie.make_removal();
    cookie
}


pub fn get_jwt_cookie(headers: &HeaderMap<HeaderValue>) -> Option<Cookie<'_>> {

    let mut secure_jwt: Option<Cookie> = None;
    let cookie_header = headers.get_all("cookie");

    for cookie in cookie_header {
        let Ok(cookie_str) = cookie.to_str() else {
            continue;
        };

        // A Cookie header holds several "name=value" pairs; Cookie::parse only reads the first
        for ck in Cookie::split_parse(cookie_str).flatten() {
            if ck.name() == COOKIE_NAME {
                secure_jwt = Some(ck);
            }
        }
    }
    return secure_jwt;
}

#[cfg(test)]
mod tests {

}
