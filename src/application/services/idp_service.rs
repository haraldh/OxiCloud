//! OxiCloud as an OpenID Provider (authorization-code flow + PKCE).
//!
//! Lets other self-hosted services — first of all the bundled Matrix
//! homeserver (`docs/plan/chat-matrix.md` § seam 1) — sign users in with
//! their OxiCloud account, so there is one login and one place to disable it.
//!
//! # Flow
//!
//! 1. `GET /oidc/authorize` → [`IdpService::authorize`] validates the client
//!    and redirect URI and parks the request under an unguessable id. The
//!    handler sends the browser to the SPA consent page. A top-level
//!    navigation cannot carry the DPoP proof a bound session needs, so the
//!    decision is made by the SPA over a normal authenticated API call
//!    instead of by this GET.
//! 2. The SPA calls [`IdpService::consent_info`] and then
//!    [`IdpService::decide`] as the signed-in user. Approval mints a
//!    single-use code and returns the client redirect.
//! 3. The client exchanges the code at `POST /oidc/token`
//!    ([`IdpService::exchange_code`]) and reads claims from
//!    `/oidc/userinfo`.
//!
//! # Who may sign in
//!
//! Internal, active users only. Externals (invited guests, OCM shadows)
//! are refused — a scope question about the principal kind, decided here
//! because the provider is the one door to every relying party. Eligibility
//! is checked at approval AND again at code exchange, so a user disabled in
//! between does not get tokens.
//!
//! # State
//!
//! Pending requests, codes and access tokens live in process memory with
//! short TTLs (same trade-off as `rt_ticket_store`): a restart invalidates
//! in-flight logins, which is the safe failure. Only the frozen
//! `preferred_username` bindings are persisted.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use moka::sync::Cache;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::application::ports::idp_ports::{
    BindOutcome, IdpSubjectBindingPort, IdpTokenSignerPort, IdpUserDirectoryPort, IdpUserView,
};
use crate::common::errors::DomainError;
use crate::common::idp_config::{IdpClientConfig, IdpConfig};

const REQUEST_TTL: Duration = Duration::from_secs(600);
const CODE_TTL: Duration = Duration::from_secs(60);
pub const ACCESS_TOKEN_TTL_SECS: u64 = 300;
const ID_TOKEN_TTL_SECS: i64 = 300;
const MAX_HANDLE_ATTEMPTS: u32 = 50;
const HANDLE_BASE_MAX: usize = 56;

pub const SUPPORTED_SCOPES: &[&str] = &["openid", "profile", "email"];

// ── Inputs / outputs ────────────────────────────────────────────────

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct AuthorizeParams {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub response_type: String,
    #[serde(default)]
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthorizeError {
    /// The client or redirect URI cannot be trusted: show an error page and
    /// never redirect (RFC 6749 §4.1.2.1 — redirecting would make us an
    /// open redirector).
    Untrusted(&'static str),
    /// The client is known; report the error back to it.
    Redirect(String),
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ConsentInfoDto {
    pub request_id: Uuid,
    pub client_id: String,
    /// Operator-configured display name of the relying party.
    pub client_name: String,
    pub scopes: Vec<String>,
    /// First-party client: the SPA approves without prompting.
    pub skip_consent: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecideError {
    /// Unknown, expired or already decided request.
    NotFound,
    /// The caller may not sign in to other services.
    Forbidden(&'static str),
    Internal(String),
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct TokenRequest {
    #[serde(default)]
    pub grant_type: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct RevokeRequest {
    #[serde(default)]
    pub token: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub id_token: String,
    pub scope: String,
}

/// RFC 6749 §5.2 error. `status` is the HTTP status to answer with.
#[derive(Debug, PartialEq, Eq)]
pub struct OAuthError {
    pub status: u16,
    pub error: &'static str,
    pub description: &'static str,
}

impl OAuthError {
    const fn new(status: u16, error: &'static str, description: &'static str) -> Self {
        Self {
            status,
            error,
            description,
        }
    }
}

// ── In-memory state ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct PendingRequest {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: String,
}

#[derive(Debug, Clone)]
struct IssuedCode {
    client_id: String,
    redirect_uri: String,
    user_id: Uuid,
    scopes: Vec<String>,
    nonce: Option<String>,
    code_challenge: String,
}

#[derive(Debug, Clone)]
struct IssuedAccessToken {
    client_id: String,
    user_id: Uuid,
    scopes: Vec<String>,
}

// ── Service ─────────────────────────────────────────────────────────

pub struct IdpService {
    config: IdpConfig,
    issuer: String,
    users: Arc<dyn IdpUserDirectoryPort>,
    bindings: Arc<dyn IdpSubjectBindingPort>,
    signer: Arc<dyn IdpTokenSignerPort>,
    requests: Cache<Uuid, PendingRequest>,
    codes: Cache<String, IssuedCode>,
    access_tokens: Cache<String, IssuedAccessToken>,
}

impl IdpService {
    pub fn new(
        config: IdpConfig,
        issuer: String,
        users: Arc<dyn IdpUserDirectoryPort>,
        bindings: Arc<dyn IdpSubjectBindingPort>,
        signer: Arc<dyn IdpTokenSignerPort>,
    ) -> Self {
        Self {
            config,
            issuer: issuer.trim_end_matches('/').to_string(),
            users,
            bindings,
            signer,
            // Bounded so an unauthenticated flood of /authorize calls cannot
            // grow memory without limit; eviction only cancels logins.
            requests: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(REQUEST_TTL)
                .build(),
            codes: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(CODE_TTL)
                .build(),
            access_tokens: Cache::builder()
                .max_capacity(50_000)
                .time_to_live(Duration::from_secs(ACCESS_TOKEN_TTL_SECS))
                .build(),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    // ── 1. authorize ────────────────────────────────────────────────

    pub fn authorize(&self, p: &AuthorizeParams) -> Result<Uuid, AuthorizeError> {
        let Some(client) = self.config.client(&p.client_id) else {
            audit_rejected("unknown_client", &p.client_id, None);
            return Err(AuthorizeError::Untrusted("unknown client"));
        };
        if !client.redirect_uris.iter().any(|u| u == &p.redirect_uri) {
            audit_rejected("redirect_uri_mismatch", &client.id, None);
            return Err(AuthorizeError::Untrusted("redirect_uri is not registered"));
        }

        let bounce = |error: &'static str, reason: &'static str| {
            audit_rejected(reason, &client.id, None);
            AuthorizeError::Redirect(error_redirect(
                &p.redirect_uri,
                error,
                p.state.as_deref(),
                &self.issuer,
            ))
        };

        if p.response_type != "code" {
            return Err(bounce(
                "unsupported_response_type",
                "unsupported_response_type",
            ));
        }
        let scopes: Vec<String> = p
            .scope
            .split_ascii_whitespace()
            .filter(|s| SUPPORTED_SCOPES.contains(s))
            .map(str::to_string)
            .collect();
        if !scopes.iter().any(|s| s == "openid") {
            return Err(bounce("invalid_scope", "missing_openid_scope"));
        }
        // PKCE is mandatory (OAuth 2.1); `plain` defeats its purpose.
        let challenge = match (&p.code_challenge, p.code_challenge_method.as_deref()) {
            (Some(c), Some("S256")) if is_valid_s256_challenge(c) => c.clone(),
            _ => return Err(bounce("invalid_request", "pkce_required")),
        };
        // We cannot authenticate silently: the decision needs the SPA.
        if p.prompt
            .as_deref()
            .is_some_and(|v| v.split_ascii_whitespace().any(|x| x == "none"))
        {
            return Err(bounce("login_required", "prompt_none"));
        }

        let id = Uuid::new_v4();
        self.requests.insert(
            id,
            PendingRequest {
                client_id: client.id.clone(),
                redirect_uri: p.redirect_uri.clone(),
                scopes,
                state: p.state.clone(),
                nonce: p.nonce.clone(),
                code_challenge: challenge,
            },
        );
        Ok(id)
    }

    // ── 2. consent ──────────────────────────────────────────────────

    pub fn consent_info(&self, request_id: Uuid) -> Option<ConsentInfoDto> {
        let req = self.requests.get(&request_id)?;
        let client = self.config.client(&req.client_id)?;
        Some(ConsentInfoDto {
            request_id,
            client_id: client.id.clone(),
            client_name: client.name.clone(),
            scopes: req.scopes.clone(),
            skip_consent: client.skip_consent,
        })
    }

    /// Record the signed-in caller's decision. Consumes the request either
    /// way, so it cannot be decided twice. Returns the client redirect.
    pub async fn decide(
        &self,
        request_id: Uuid,
        caller_id: Uuid,
        approve: bool,
    ) -> Result<String, DecideError> {
        let req = self
            .requests
            .remove(&request_id)
            .ok_or(DecideError::NotFound)?;
        let client = self
            .config
            .client(&req.client_id)
            .ok_or(DecideError::NotFound)?;

        if !approve {
            tracing::info!(
                target: "audit",
                event = "idp.consent_denied",
                client_id = %client.id,
                caller_id = %caller_id,
                "👮🏻‍♂️ user declined sign-in to {}",
                client.id
            );
            return Ok(error_redirect(
                &req.redirect_uri,
                "access_denied",
                req.state.as_deref(),
                &self.issuer,
            ));
        }

        let user = self
            .eligible_user(caller_id, &client.id)
            .await
            .map_err(|e| match e {
                Ineligible::Refused(reason) => DecideError::Forbidden(reason),
                Ineligible::Internal(m) => DecideError::Internal(m),
            })?;
        // Reserve the handle now, while the user is looking at the screen:
        // a failure here is reported to them instead of surfacing later as
        // an opaque token-endpoint error inside the relying party.
        self.preferred_username(client, &user)
            .await
            .map_err(|e| DecideError::Internal(e.to_string()))?;

        let code = random_token();
        self.codes.insert(
            code.clone(),
            IssuedCode {
                client_id: client.id.clone(),
                redirect_uri: req.redirect_uri.clone(),
                user_id: user.id,
                scopes: req.scopes.clone(),
                nonce: req.nonce.clone(),
                code_challenge: req.code_challenge.clone(),
            },
        );
        tracing::info!(
            target: "audit",
            event = "idp.authorized",
            client_id = %client.id,
            caller_id = %caller_id,
            "👮🏻‍♂️ user signed in to {}",
            client.id
        );

        let mut url = url::Url::parse(&req.redirect_uri)
            .map_err(|e| DecideError::Internal(format!("redirect_uri: {e}")))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("code", &code);
            if let Some(s) = &req.state {
                q.append_pair("state", s);
            }
            q.append_pair("iss", &self.issuer);
        }
        Ok(url.into())
    }

    // ── 3. token endpoint ───────────────────────────────────────────

    pub async fn exchange_code(
        &self,
        req: &TokenRequest,
        basic: Option<(String, String)>,
    ) -> Result<TokenResponse, OAuthError> {
        let client = self.authenticate_client(
            req.client_id.as_deref(),
            req.client_secret.as_deref(),
            basic,
        )?;

        if req.grant_type != "authorization_code" {
            return Err(OAuthError::new(
                400,
                "unsupported_grant_type",
                "only authorization_code is supported",
            ));
        }

        let invalid_grant = |reason: &'static str| {
            audit_rejected(reason, &client.id, None);
            OAuthError::new(
                400,
                "invalid_grant",
                "invalid, expired or already used code",
            )
        };

        // `remove` is the single-use guarantee: of two concurrent
        // exchanges, exactly one gets the code.
        let code = self
            .codes
            .remove(&req.code)
            .ok_or_else(|| invalid_grant("code_unknown"))?;
        if code.client_id != client.id {
            return Err(invalid_grant("code_client_mismatch"));
        }
        if code.redirect_uri != req.redirect_uri {
            return Err(invalid_grant("code_redirect_mismatch"));
        }
        let verifier = req.code_verifier.as_deref().unwrap_or_default();
        if !pkce_matches(verifier, &code.code_challenge) {
            return Err(invalid_grant("pkce_mismatch"));
        }

        let user = self
            .eligible_user(code.user_id, &client.id)
            .await
            .map_err(|e| match e {
                Ineligible::Refused(_) => {
                    OAuthError::new(400, "invalid_grant", "the user can no longer sign in")
                }
                Ineligible::Internal(_) => {
                    OAuthError::new(500, "server_error", "user lookup failed")
                }
            })?;
        let preferred_username = self
            .preferred_username(client, &user)
            .await
            .map_err(|_| OAuthError::new(500, "server_error", "handle allocation failed"))?;

        let now = chrono::Utc::now().timestamp();
        let mut claims = serde_json::json!({
            "iss": self.issuer,
            "sub": user.id.to_string(),
            "aud": client.id,
            "azp": client.id,
            "iat": now,
            "exp": now + ID_TOKEN_TTL_SECS,
        });
        if let Some(n) = &code.nonce {
            claims["nonce"] = serde_json::Value::String(n.clone());
        }
        merge(
            &mut claims,
            scoped_claims(&user, &preferred_username, &code.scopes),
        );
        let id_token = self
            .signer
            .sign(&claims)
            .map_err(|_| OAuthError::new(500, "server_error", "token signing failed"))?;

        let access_token = random_token();
        self.access_tokens.insert(
            access_token.clone(),
            IssuedAccessToken {
                client_id: client.id.clone(),
                user_id: user.id,
                scopes: code.scopes.clone(),
            },
        );

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: ACCESS_TOKEN_TTL_SECS,
            id_token,
            scope: code.scopes.join(" "),
        })
    }

    // ── 4. userinfo ─────────────────────────────────────────────────

    pub async fn userinfo(&self, bearer: &str) -> Result<serde_json::Value, OAuthError> {
        let invalid = || OAuthError::new(401, "invalid_token", "unknown or expired access token");
        let token = self.access_tokens.get(bearer).ok_or_else(|| {
            audit_rejected("access_token_unknown", "-", None);
            invalid()
        })?;
        let client = self.config.client(&token.client_id).ok_or_else(invalid)?;
        let user = self
            .eligible_user(token.user_id, &client.id)
            .await
            .map_err(|_| {
                self.access_tokens.invalidate(bearer);
                invalid()
            })?;
        let preferred_username = self
            .preferred_username(client, &user)
            .await
            .map_err(|_| OAuthError::new(500, "server_error", "handle lookup failed"))?;

        let mut out = serde_json::json!({ "sub": user.id.to_string() });
        merge(
            &mut out,
            scoped_claims(&user, &preferred_username, &token.scopes),
        );
        Ok(out)
    }

    // ── 5. revocation (RFC 7009) ────────────────────────────────────

    pub fn revoke(
        &self,
        req: &RevokeRequest,
        basic: Option<(String, String)>,
    ) -> Result<(), OAuthError> {
        let client = self.authenticate_client(
            req.client_id.as_deref(),
            req.client_secret.as_deref(),
            basic,
        )?;
        // RFC 7009 §2.2: unknown tokens are not an error. A client may only
        // revoke its own tokens.
        if self
            .access_tokens
            .get(&req.token)
            .is_some_and(|t| t.client_id == client.id)
        {
            self.access_tokens.invalidate(&req.token);
        }
        Ok(())
    }

    // ── Discovery ───────────────────────────────────────────────────

    pub fn discovery_document(&self) -> serde_json::Value {
        let ep = |p: &str| format!("{}{}", self.issuer, p);
        serde_json::json!({
            "issuer": self.issuer,
            "authorization_endpoint": ep("/oidc/authorize"),
            "token_endpoint": ep("/oidc/token"),
            "userinfo_endpoint": ep("/oidc/userinfo"),
            "revocation_endpoint": ep("/oidc/revoke"),
            "jwks_uri": ep("/oidc/jwks"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [self.signer.algorithm()],
            "scopes_supported": SUPPORTED_SCOPES,
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "revocation_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "nonce",
                "preferred_username", "name", "given_name", "family_name",
                "email", "email_verified"
            ],
            "authorization_response_iss_parameter_supported": true,
        })
    }

    pub fn jwks(&self) -> serde_json::Value {
        self.signer.jwks()
    }

    // ── Internals ───────────────────────────────────────────────────

    fn authenticate_client(
        &self,
        form_id: Option<&str>,
        form_secret: Option<&str>,
        basic: Option<(String, String)>,
    ) -> Result<&IdpClientConfig, OAuthError> {
        let invalid = |reason: &'static str, id: &str| {
            audit_rejected(reason, id, None);
            OAuthError::new(401, "invalid_client", "client authentication failed")
        };
        let (id, secret) = match (basic, form_id, form_secret) {
            // RFC 6749 §2.3: a client MUST NOT use more than one method.
            (Some(_), _, Some(_)) => return Err(invalid("multiple_client_auth_methods", "-")),
            (Some((id, secret)), _, None) => (id, secret),
            (None, Some(id), Some(secret)) => (id.to_string(), secret.to_string()),
            _ => return Err(invalid("client_auth_missing", "-")),
        };
        let client = self
            .config
            .client(&id)
            .ok_or_else(|| invalid("unknown_client", &id))?;
        if !bool::from(client.secret.as_bytes().ct_eq(secret.as_bytes())) {
            return Err(invalid("bad_client_secret", &client.id));
        }
        Ok(client)
    }

    async fn eligible_user(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> Result<IdpUserView, Ineligible> {
        let user = self
            .users
            .find_user(user_id)
            .await
            .map_err(|e| Ineligible::Internal(e.to_string()))?;
        let refuse = |reason: &'static str| {
            audit_rejected(reason, client_id, Some(user_id));
            Ineligible::Refused(reason)
        };
        let user = user.ok_or_else(|| refuse("user_not_found"))?;
        if user.is_external {
            return Err(refuse("external_user"));
        }
        if !user.is_active {
            return Err(refuse("account_inactive"));
        }
        Ok(user)
    }

    async fn preferred_username(
        &self,
        client: &IdpClientConfig,
        user: &IdpUserView,
    ) -> Result<String, DomainError> {
        if let Some(h) = self.bindings.get_binding(&client.id, user.id).await? {
            return Ok(h);
        }
        let base = handle_base(user);
        for attempt in 1..=MAX_HANDLE_ATTEMPTS + 1 {
            let candidate = match attempt {
                1 => base.clone(),
                n if n <= MAX_HANDLE_ATTEMPTS => format!("{base}-{n}"),
                // Pathological namespace crowding: fall back to a random
                // suffix rather than refusing the login.
                _ => format!("{base}-{:08x}", OsRng.next_u32()),
            };
            match self
                .bindings
                .try_bind(&client.id, user.id, &candidate)
                .await?
            {
                BindOutcome::Bound(h) => return Ok(h),
                BindOutcome::HandleTaken => continue,
            }
        }
        Err(DomainError::internal_error(
            "IdpSubjectBinding",
            "could not allocate a preferred_username",
        ))
    }
}

enum Ineligible {
    Refused(&'static str),
    Internal(String),
}

// ── Pure helpers ────────────────────────────────────────────────────

fn audit_rejected(reason: &'static str, client_id: &str, user_id: Option<Uuid>) {
    tracing::info!(
        target: "audit",
        event = "idp.rejected",
        reason = reason,
        client_id = %client_id,
        caller_id = ?user_id,
        "👮🏻‍♂️ OpenID provider refused request: {reason}"
    );
}

fn error_redirect(redirect_uri: &str, error: &str, state: Option<&str>, issuer: &str) -> String {
    // `redirect_uri` was validated against the allowlist and at config
    // load, so it parses; fall back to the bare URI defensively.
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return redirect_uri.to_string();
    };
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("error", error);
        if let Some(s) = state {
            q.append_pair("state", s);
        }
        q.append_pair("iss", issuer);
    }
    url.into()
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

/// RFC 7636: an S256 challenge is base64url(SHA-256) — exactly 43 chars.
fn is_valid_s256_challenge(c: &str) -> bool {
    c.len() == 43
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    // RFC 7636 §4.1: 43–128 unreserved characters.
    let ok_len = (43..=128).contains(&verifier.len());
    let ok_chars = verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    if !ok_len || !ok_chars {
        return false;
    }
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    bool::from(computed.as_bytes().ct_eq(challenge.as_bytes()))
}

/// Handle grammar shared with the DB CHECK constraint and the Matrix
/// localpart grammar (`[a-z0-9._=/+-]`, narrowed).
fn is_valid_handle(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 64
        && h.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// First-choice handle: the immutable username when there is one, else the
/// email local part folded into the handle grammar.
fn handle_base(user: &IdpUserView) -> String {
    if let Some(u) = user.username.as_deref() {
        let u = u.to_ascii_lowercase();
        if is_valid_handle(&u) && u.len() <= HANDLE_BASE_MAX {
            return u;
        }
    }
    let local = user.email.split('@').next().unwrap_or_default();
    let folded: String = local
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(HANDLE_BASE_MAX)
        .collect();
    let trimmed = folded.trim_matches(|c| c == '.' || c == '_' || c == '-');
    if trimmed.is_empty() {
        "user".to_string()
    } else {
        trimmed.to_string()
    }
}

fn display_name(user: &IdpUserView) -> String {
    let parts: Vec<&str> = [user.given_name.as_deref(), user.family_name.as_deref()]
        .into_iter()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .collect();
    if !parts.is_empty() {
        return parts.join(" ");
    }
    user.username
        .clone()
        .unwrap_or_else(|| user.email.split('@').next().unwrap_or_default().to_string())
}

fn scoped_claims(
    user: &IdpUserView,
    preferred_username: &str,
    scopes: &[String],
) -> serde_json::Value {
    let mut c = serde_json::Map::new();
    if scopes.iter().any(|s| s == "profile") {
        c.insert("preferred_username".into(), preferred_username.into());
        c.insert("name".into(), display_name(user).into());
        if let Some(g) = &user.given_name {
            c.insert("given_name".into(), g.clone().into());
        }
        if let Some(f) = &user.family_name {
            c.insert("family_name".into(), f.clone().into());
        }
    }
    if scopes.iter().any(|s| s == "email") {
        c.insert("email".into(), user.email.clone().into());
        c.insert("email_verified".into(), user.email_verified.into());
    }
    serde_json::Value::Object(c)
}

fn merge(into: &mut serde_json::Value, from: serde_json::Value) {
    if let (Some(a), serde_json::Value::Object(b)) = (into.as_object_mut(), from) {
        a.extend(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const REDIRECT: &str = "https://chat.example.org/cb";
    // RFC 7636 Appendix B test vector.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[derive(Default)]
    struct FakeUsers(Mutex<HashMap<Uuid, IdpUserView>>);
    #[async_trait::async_trait]
    impl IdpUserDirectoryPort for FakeUsers {
        async fn find_user(&self, id: Uuid) -> Result<Option<IdpUserView>, DomainError> {
            Ok(self.0.lock().unwrap().get(&id).cloned())
        }
    }

    #[derive(Default)]
    struct FakeBindings(Mutex<HashMap<(String, Uuid), String>>);
    #[async_trait::async_trait]
    impl IdpSubjectBindingPort for FakeBindings {
        async fn get_binding(&self, c: &str, u: Uuid) -> Result<Option<String>, DomainError> {
            Ok(self.0.lock().unwrap().get(&(c.to_string(), u)).cloned())
        }
        async fn try_bind(&self, c: &str, u: Uuid, h: &str) -> Result<BindOutcome, DomainError> {
            let mut m = self.0.lock().unwrap();
            if let Some(existing) = m.get(&(c.to_string(), u)) {
                return Ok(BindOutcome::Bound(existing.clone()));
            }
            if m.iter().any(|((cc, _), hh)| cc == c && hh == h) {
                return Ok(BindOutcome::HandleTaken);
            }
            m.insert((c.to_string(), u), h.to_string());
            Ok(BindOutcome::Bound(h.to_string()))
        }
    }

    struct FakeSigner;
    impl IdpTokenSignerPort for FakeSigner {
        fn sign(&self, claims: &serde_json::Value) -> Result<String, DomainError> {
            Ok(format!("signed:{claims}"))
        }
        fn jwks(&self) -> serde_json::Value {
            serde_json::json!({ "keys": [] })
        }
        fn algorithm(&self) -> &'static str {
            "ES256"
        }
    }

    struct Fixture {
        svc: IdpService,
        users: Arc<FakeUsers>,
        bindings: Arc<FakeBindings>,
    }

    fn user(username: Option<&str>, email: &str) -> IdpUserView {
        IdpUserView {
            id: Uuid::new_v4(),
            email: email.to_string(),
            email_verified: true,
            username: username.map(str::to_string),
            given_name: Some("Alice".into()),
            family_name: None,
            is_active: true,
            is_external: false,
        }
    }

    fn fixture() -> Fixture {
        let cfg = IdpConfig {
            clients: vec![IdpClientConfig {
                id: "chat".into(),
                name: "Chat".into(),
                secret: SECRET.into(),
                redirect_uris: vec![REDIRECT.into()],
                skip_consent: true,
            }],
        };
        let users = Arc::new(FakeUsers::default());
        let bindings = Arc::new(FakeBindings::default());
        let svc = IdpService::new(
            cfg,
            "https://cloud.example.org/".into(),
            users.clone(),
            bindings.clone(),
            Arc::new(FakeSigner),
        );
        Fixture {
            svc,
            users,
            bindings,
        }
    }

    impl Fixture {
        fn add(&self, u: IdpUserView) -> Uuid {
            let id = u.id;
            self.users.0.lock().unwrap().insert(id, u);
            id
        }

        /// The guard is dropped before returning, so callers never hold it
        /// across an await.
        async fn handle(&self, id: Uuid) -> String {
            let u = self.users.0.lock().unwrap()[&id].clone();
            self.svc
                .preferred_username(self.svc.config.client("chat").unwrap(), &u)
                .await
                .unwrap()
        }
    }

    fn params() -> AuthorizeParams {
        AuthorizeParams {
            client_id: "chat".into(),
            redirect_uri: REDIRECT.into(),
            response_type: "code".into(),
            scope: "openid profile email offline_access".into(),
            state: Some("st".into()),
            nonce: Some("n0".into()),
            code_challenge: Some(CHALLENGE.into()),
            code_challenge_method: Some("S256".into()),
            prompt: None,
        }
    }

    fn code_of(redirect: &str) -> String {
        url::Url::parse(redirect)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned()
    }

    fn token_req(code: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".into(),
            code: code.into(),
            redirect_uri: REDIRECT.into(),
            code_verifier: Some(VERIFIER.into()),
            client_id: Some("chat".into()),
            client_secret: Some(SECRET.into()),
        }
    }

    #[test]
    fn rfc7636_vector_matches() {
        assert!(pkce_matches(VERIFIER, CHALLENGE));
        assert!(!pkce_matches("x".repeat(43).as_str(), CHALLENGE));
    }

    #[test]
    fn untrusted_client_or_redirect_never_redirects() {
        let f = fixture();
        let mut p = params();
        p.client_id = "nope".into();
        assert!(matches!(
            f.svc.authorize(&p),
            Err(AuthorizeError::Untrusted(_))
        ));
        let mut p = params();
        p.redirect_uri = "https://chat.example.org/cb/evil".into();
        assert!(matches!(
            f.svc.authorize(&p),
            Err(AuthorizeError::Untrusted(_))
        ));
    }

    #[test]
    fn protocol_errors_redirect_back_with_state() {
        let f = fixture();
        for mutate in [
            (|p: &mut AuthorizeParams| p.response_type = "token".into())
                as fn(&mut AuthorizeParams),
            |p| p.scope = "profile".into(),
            |p| p.code_challenge = None,
            |p| p.code_challenge_method = Some("plain".into()),
            |p| p.prompt = Some("none".into()),
        ] {
            let mut p = params();
            mutate(&mut p);
            match f.svc.authorize(&p) {
                Err(AuthorizeError::Redirect(u)) => {
                    assert!(u.starts_with(REDIRECT), "{u}");
                    assert!(u.contains("error="), "{u}");
                    assert!(u.contains("state=st"), "{u}");
                }
                other => panic!("expected redirect, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn happy_path_issues_tokens_and_userinfo() {
        let f = fixture();
        let uid = f.add(user(Some("Alice"), "alice@example.org"));
        let rid = f.svc.authorize(&params()).unwrap();
        let info = f.svc.consent_info(rid).unwrap();
        assert!(info.skip_consent);
        assert_eq!(info.scopes, vec!["openid", "profile", "email"]);

        let redirect = f.svc.decide(rid, uid, true).await.unwrap();
        assert!(redirect.contains("state=st"));
        assert!(redirect.contains("iss=https%3A%2F%2Fcloud.example.org"));
        let tok = f
            .svc
            .exchange_code(&token_req(&code_of(&redirect)), None)
            .await
            .unwrap();
        assert!(tok.id_token.contains("\"nonce\":\"n0\""));
        assert!(tok.id_token.contains(&format!("\"sub\":\"{uid}\"")));

        let ui = f.svc.userinfo(&tok.access_token).await.unwrap();
        assert_eq!(ui["sub"], uid.to_string());
        assert_eq!(ui["preferred_username"], "alice");
        assert_eq!(ui["email"], "alice@example.org");
    }

    #[tokio::test]
    async fn request_and_code_are_single_use() {
        let f = fixture();
        let uid = f.add(user(Some("bob"), "bob@example.org"));
        let rid = f.svc.authorize(&params()).unwrap();
        let redirect = f.svc.decide(rid, uid, true).await.unwrap();
        assert_eq!(
            f.svc.decide(rid, uid, true).await,
            Err(DecideError::NotFound)
        );
        let code = code_of(&redirect);
        assert!(f.svc.exchange_code(&token_req(&code), None).await.is_ok());
        let again = f
            .svc
            .exchange_code(&token_req(&code), None)
            .await
            .unwrap_err();
        assert_eq!(again.error, "invalid_grant");
    }

    #[tokio::test]
    async fn token_exchange_checks_secret_pkce_and_redirect() {
        let f = fixture();
        let uid = f.add(user(Some("carol"), "carol@example.org"));

        for (mutate, expected) in [
            (
                (|r: &mut TokenRequest| {
                    r.client_secret = Some("wrong-secret-wrong-secret-wrong!".into())
                }) as fn(&mut TokenRequest),
                "invalid_client",
            ),
            (|r| r.code_verifier = Some("a".repeat(43)), "invalid_grant"),
            (
                |r| r.redirect_uri = "https://chat.example.org/other".into(),
                "invalid_grant",
            ),
            (
                |r| r.grant_type = "refresh_token".into(),
                "unsupported_grant_type",
            ),
        ] {
            let rid = f.svc.authorize(&params()).unwrap();
            let code = code_of(&f.svc.decide(rid, uid, true).await.unwrap());
            let mut r = token_req(&code);
            mutate(&mut r);
            assert_eq!(
                f.svc.exchange_code(&r, None).await.unwrap_err().error,
                expected
            );
        }

        // client_secret_basic works; mixing methods does not.
        let rid = f.svc.authorize(&params()).unwrap();
        let code = code_of(&f.svc.decide(rid, uid, true).await.unwrap());
        let mut r = token_req(&code);
        r.client_secret = None;
        assert!(
            f.svc
                .exchange_code(&r, Some(("chat".into(), SECRET.into())))
                .await
                .is_ok()
        );
        let rid = f.svc.authorize(&params()).unwrap();
        let code = code_of(&f.svc.decide(rid, uid, true).await.unwrap());
        assert_eq!(
            f.svc
                .exchange_code(&token_req(&code), Some(("chat".into(), SECRET.into())))
                .await
                .unwrap_err()
                .error,
            "invalid_client"
        );
    }

    #[tokio::test]
    async fn external_and_inactive_users_are_refused() {
        let f = fixture();
        let mut ext = user(None, "guest@elsewhere.org");
        ext.is_external = true;
        let ext_id = f.add(ext);
        let rid = f.svc.authorize(&params()).unwrap();
        assert_eq!(
            f.svc.decide(rid, ext_id, true).await,
            Err(DecideError::Forbidden("external_user"))
        );

        // Disabled between approval and code exchange: no tokens.
        let uid = f.add(user(Some("dave"), "dave@example.org"));
        let rid = f.svc.authorize(&params()).unwrap();
        let code = code_of(&f.svc.decide(rid, uid, true).await.unwrap());
        f.users.0.lock().unwrap().get_mut(&uid).unwrap().is_active = false;
        assert_eq!(
            f.svc
                .exchange_code(&token_req(&code), None)
                .await
                .unwrap_err()
                .error,
            "invalid_grant"
        );
    }

    #[tokio::test]
    async fn deny_redirects_with_access_denied() {
        let f = fixture();
        let uid = f.add(user(Some("erin"), "erin@example.org"));
        let rid = f.svc.authorize(&params()).unwrap();
        let r = f.svc.decide(rid, uid, false).await.unwrap();
        assert!(r.contains("error=access_denied"));
        assert!(!r.contains("code="));
    }

    /// The regression this pins: the handle a relying party saw first must
    /// not follow later account changes, or a Matrix homeserver would mint
    /// a second account for the same person.
    #[tokio::test]
    async fn handles_are_frozen_and_deduplicated() {
        let f = fixture();
        let a = user(None, "Jo.Smith+tag@example.org");
        let a_id = f.add(a);
        let b_id = f.add(user(Some("jo.smith_tag"), "other@example.org"));

        let ha = f.handle(a_id).await;
        assert_eq!(ha, "jo.smith_tag");
        let hb = f.handle(b_id).await;
        assert_eq!(hb, "jo.smith_tag-2");

        // A later username claim does not move the frozen handle.
        f.users.0.lock().unwrap().get_mut(&a_id).unwrap().username = Some("jsmith".into());
        let again = f.handle(a_id).await;
        assert_eq!(again, "jo.smith_tag");
        assert_eq!(f.bindings.0.lock().unwrap().len(), 2);
    }

    #[test]
    fn handle_base_folding() {
        let mut u = user(None, "--@example.org");
        assert_eq!(handle_base(&u), "user");
        u.email = "ÄÖ.x@example.org".into();
        assert_eq!(handle_base(&u), "x");
        u.username = Some("Mixed.Case-1".into());
        assert_eq!(handle_base(&u), "mixed.case-1");
        assert!(is_valid_handle(&handle_base(&u)));
    }

    #[test]
    fn discovery_lists_endpoints_under_issuer() {
        let f = fixture();
        let d = f.svc.discovery_document();
        assert_eq!(d["issuer"], "https://cloud.example.org");
        assert_eq!(d["token_endpoint"], "https://cloud.example.org/oidc/token");
        assert_eq!(d["code_challenge_methods_supported"][0], "S256");
    }

    #[test]
    fn revoke_only_affects_own_tokens_and_ignores_unknown() {
        let f = fixture();
        f.svc.access_tokens.insert(
            "t".into(),
            IssuedAccessToken {
                client_id: "chat".into(),
                user_id: Uuid::new_v4(),
                scopes: vec![],
            },
        );
        let req = |t: &str| RevokeRequest {
            token: t.into(),
            client_id: Some("chat".into()),
            client_secret: Some(SECRET.into()),
        };
        assert!(f.svc.revoke(&req("unknown"), None).is_ok());
        assert!(f.svc.revoke(&req("t"), None).is_ok());
        assert!(f.svc.access_tokens.get("t").is_none());
    }
}
