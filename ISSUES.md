# Fork status: `main` vs `origin/main`

`main` is 7 commits ahead of `origin/main` (f803780e, upstream pingap). This
file lists what those commits change, the known defects of the `oauth2`
plugin they add, and what was changed in upstream's `oidc` plugin to replace
it.

| Commit | What |
| --- | --- |
| 492a98b1 | Add `proksi-oauth2` crate and the `oauth2` plugin |
| 7b3dd6f2 | "Improve defaults": health-check and auto-restart intervals, `make` default target |
| ef399955 | Make oauth2 work; `directory` index change |
| 1431c492 | oauth2: read the session cookie out of a multi-cookie `Cookie` header |
| c1333ed4 | Dockerfile: build web assets into `dist/`, `target` symlink |
| 46b8db3f | oauth2/Gitea: load organization and team names |
| 1b14ba0d | `oidc`: allow-lists and `end_session_url` |

`Cargo.lock` is **not committed**: without it the lockfile has no entry for
`proksi-oauth2` or its dependencies, and `cargo build --locked` fails.

## Direction

Use `oidc` for Gitea (and any other OpenID Connect provider). Keep `oauth2`
only while something still needs GitHub login, which has no OIDC; see the
last section. `oauth2` should not be relied on in production while the
defects below are open.

## `oauth2` plugin: known defects

Files: [`pingap-plugin/src/oauth2.rs`](pingap-plugin/src/oauth2.rs),
[`pingap-plugin/src/oauth2_utils.rs`](pingap-plugin/src/oauth2_utils.rs),
[`proksi-oauth2/`](proksi-oauth2/).

### Security

1. **Secrets in logs.** `try_from` prints the whole plugin config, `client_secret`
   included, with `print!` and `tracing::info!`
   ([oauth2.rs:66](pingap-plugin/src/oauth2.rs#L66),
   [oauth2.rs:70](pingap-plugin/src/oauth2.rs#L70)). A failed login logs the
   authorization code and all request headers, cookies included
   ([oauth2_utils.rs:216](pingap-plugin/src/oauth2_utils.rs#L216),
   [oauth2.rs:323](pingap-plugin/src/oauth2.rs#L323)). (The Gitea provider's
   token/secret debug logs were removed in 46b8db3f.)
2. **Login CSRF.** `state` is only an encrypted timestamp and path; it is not
   bound to the browser that started the login, and there is no PKCE or
   nonce. Within 120 s, an attacker can complete their own login in a
   victim's browser, signing the victim in as the attacker.
3. **Hard-coded JWT secret** `"todo!()"`
   ([oauth2.rs:145](pingap-plugin/src/oauth2.rs#L145)). Anyone can mint a
   valid session JWT. Only the in-memory session map (4) stops this being an
   authentication bypass; removing the map without making the secret
   configurable opens every protected site.
4. **Open redirect after login.** The return address is
   `req_header().uri.to_string()`
   ([oauth2.rs:175](pingap-plugin/src/oauth2.rs#L175)), which is a full URL
   when the request line is in absolute form. It is not limited to a path of
   this site.

### Reliability

5. **Sessions only work on one instance.** Sessions live in an in-memory
   `DashMap` ([oauth2.rs:139](pingap-plugin/src/oauth2.rs#L139)) and the
   `state` key is a random UUID per plugin instance
   ([oauth2.rs:92](pingap-plugin/src/oauth2.rs#L92)). With more than one
   replica, a login started on one fails on another, and a cookie is only
   accepted by the instance that issued it. Every restart or plugin reload
   logs everyone out. Entries are removed only when their cookie is
   presented again, so the map grows without bound.
6. **Panics.**
   - `redirect_path` unset: `Uri::from_str("").unwrap()` panics on every
     request ([oauth2.rs:317](pingap-plugin/src/oauth2.rs#L317)).
   - Unknown `provider`: `panic!` at config load instead of a config error
     ([oauth2_utils.rs:318](pingap-plugin/src/oauth2_utils.rs#L318)).
   - `unwrap`s on decrypted state
     ([oauth2_utils.rs:201](pingap-plugin/src/oauth2_utils.rs#L201)) and on
     the GitHub user's primary email
     ([github.rs](proksi-oauth2/src/github.rs)).
7. **Non-browser requests are redirected.** `fetch`/XHR calls and form posts
   without a session get a `307` to the provider; a `307` makes the browser
   re-POST the form to Gitea. `oidc` sends `401` to anything that is not a
   page navigation.
8. **No timeouts and no status checks on provider calls.** The shared
   `reqwest::Client` has no timeout, and the token response's HTTP status is
   not checked, so a slow or failing provider hangs or yields a parse error.

### Missing or fixed behavior

9. **No identity for the upstream.** Nothing like `claims_to_headers`; the app
   behind the proxy cannot tell who the user is.
10. **Fixed cookie settings** ([secure_cookie.rs](proksi-oauth2/src/secure_cookie.rs)):
    - Session length is always 24 h.
    - The cookie name is always `__Pingap_auth_JWT`, so two `oauth2` plugins on
      one host share the same cookie.
    - The cookie is always `Secure`, so it is never stored over plain http.
    - The `Domain` attribute is set, so subdomains also receive the cookie.
11. **Group membership is checked only at login** and then trusted for the
    cookie's 24 h. This is the same model as `oidc` (bounded by
    `session_ttl`).
12. **Bare `$NAME` config values are not resolved.** `client_id =
    "$GITEA_CLIENT_ID"` is sent as that literal text; pingap only resolves
    `$ENV:NAME` and `$FILE:/path`.
13. **Breaks `make lint` (a CI gate), and undocumented.** `cargo clippy -p
    pingap-plugin -p proksi-oauth2` reports 10 `unwrap()` errors (denied by
    the workspace lints) and ~17 warnings, nearly all in `oauth2.rs` and
    `oauth2_utils.rs`. There is also leftover debug code, no `pingap-plugin/docs/oauth2.md` or
    `docs/zh/plugins/oauth2.md`, and the web admin only gained the category
    and three placeholder strings.

## `oidc` plugin changes (1b14ba0d)

Upstream `oidc` already does what `oauth2` gets wrong:
- Encrypted cookie sessions shared through `cookie_secret`, so any number of
  instances and restarts work.
- `state`, PKCE and nonce bound to a per-login cookie.
- Return only to a path of this site.
- `401` for non-navigation requests, with timeouts and checked responses on
  provider calls.
- `claims_to_headers` with anti-spoofing.
- Masked secrets.

The fork adds what was missing for the Gitea setup, in
[`pingap-plugin/src/oidc.rs`](pingap-plugin/src/oidc.rs):

| Key | Checked against | Replaces (`oauth2`) |
| --- | --- | --- |
| `allowed_emails` | `email` claim, case-insensitive; ignored when `email_verified` is `false` | `valid_emails` |
| `allowed_usernames` | `preferred_username` claim | `valid_usernames` |
| `allowed_groups` | `groups` claim (list or single string). Gitea sends `org` and `org:team` | `valid_organizations`, `valid_teams` |
| `end_session_url` | Logout target, used in place of the discovery `end_session_endpoint` (Gitea advertises none) | `end_session_url` |

- With no allow-list set, behavior is unchanged: anyone the provider logs in
  may enter. With any set, one match in one list is required; others get
  `403 Login refused: this account is not allowed here`, logged as
  `oidc login not allowed` with the `sub`
  ([oidc.rs:764](pingap-plugin/src/oidc.rs#L764),
  [`is_allowed`, oidc.rs:840](pingap-plugin/src/oidc.rs#L840)).
- Checked once at login, like everything else in the session.
- Tests: `test_oidc_allow_lists`, `test_oidc_callback_refuses_who_is_not_allowed`,
  `test_oidc_end_session_url`, plus an `end_session_url` case in
  `test_oidc_params`. All 16 `oidc` tests pass.
- Docs: [`pingap-plugin/docs/oidc.md`](pingap-plugin/docs/oidc.md) and
  [`docs/zh/plugins/oidc.md`](docs/zh/plugins/oidc.md) — the new keys, a
  "Who may log in" section, and how several plugins with the same `issuer`,
  `client_id`, `cookie_secret` and `cookie_name` share one session while
  each keeps its own `redirect_path` and `logout_path`.
- Generic: works with any provider that sends these claims, and could be
  offered upstream.

The deployment config (`infra/compose/pingap_config.toml`) was migrated to
`oidc` and needs `PINGAP_OIDC_COOKIE_SECRET` set; pingap refuses to start
without it.

## Other differences from `origin/main`

| Change | Where | Note |
| --- | --- | --- |
| Directory index for folders when `autoindex` is off | [directory.rs](pingap-plugin/src/directory.rs) (ef399955) | **Should be dropped.** Upstream now does this itself, and the fork's version runs first, skipping two upstream checks: the redirect from `/dir` to `/dir/` (without it, relative links break) and the `escapes_root` check on the index file (an `index.html` symlinked outside the root is served). |
| Upstream health-check interval 10 s → 30 s | [src/main.rs](src/main.rs) (7b3dd6f2) | Dead backends are noticed up to 3× later. |
| Auto-restart polling unit 10 s → 30 s | [auto_restart.rs](src/process/auto_restart.rs) (7b3dd6f2) | Config changes are picked up more slowly. |
| `make` with no target builds `release-full` | [Makefile](Makefile) | Was `lint`. |
| "upstream not found" error lists known upstreams | [pingap-config/src/common.rs](pingap-config/src/common.rs) | |
| `OAuth2` plugin category | `common.rs`, `web/src/constants.ts`, `web/src/i18n/*.ts` | Needed for the admin UI to accept `oauth2`. |
| `form` feature on `reqwest`; `short-crypt` dependency | `Cargo.toml`, `pingap-plugin/Cargo.toml` | Only for `oauth2`. |
| Leftover commented `pingora` path dependency | [Cargo.toml](Cargo.toml) | Remove. |
| `.dockerignore`, `target` in `.gitignore` | | Out-of-source build via a `target` symlink. |
| Dockerfile builds web assets into `dist/` in a node stage | [Dockerfile](Dockerfile) | Toolchain pins follow upstream (`rust:1.98.1-trixie`, `node:24-alpine`). |
| README title and links | [README.md](README.md) | Says "not yet tested in production". |

## GitHub login

GitHub offers OAuth2 but not OIDC, so `oidc` cannot use it directly. Options:
- Keep `oauth2` for GitHub only, after fixing at least defects 1, 3, 5 and 6.
- Run [Dex](https://dexidp.io) as an OIDC front end for GitHub and point
  `oidc` at it. Dex passes GitHub orgs and teams as `groups` in the same
  `org` / `org:team` form, so `allowed_groups` works unchanged. With that,
  `oauth2` and `proksi-oauth2` can be removed.
