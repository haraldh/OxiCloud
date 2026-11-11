//! HTTP surface of OxiCloud's OpenID Provider.
//!
//! Protocol endpoints (public, mounted at the root under the base path):
//!   GET  /.well-known/openid-configuration
//!   GET  /oidc/authorize   → 302 to the SPA consent page, or back to the client
//!   POST /oidc/token       → code exchange (client_secret_post / _basic)
//!   GET  /oidc/userinfo    (also POST, RFC-allowed)
//!   GET  /oidc/jwks
//!   POST /oidc/revoke
//!
//! SPA endpoints (authenticated, CSRF + DPoP like every other /api route):
//!   GET  /api/idp/requests/{id}
//!   POST /api/idp/requests/{id}/decision
//!
//! The handlers only translate HTTP; eligibility and every other decision
//! live in [`IdpService`].

use std::sync::Arc;

use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use uuid::Uuid;

use crate::application::services::idp_service::{
    AuthorizeError, AuthorizeParams, ConsentInfoDto, DecideError, IdpService, OAuthError,
    RevokeRequest, TokenRequest,
};
use crate::common::di::AppState;
use crate::interfaces::errors::AppError;
use crate::interfaces::middleware::auth::AuthUser;

pub fn idp_public_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/oidc/authorize", get(authorize))
        .route("/oidc/token", post(token))
        .route("/oidc/userinfo", get(userinfo).post(userinfo))
        .route("/oidc/jwks", get(jwks))
        .route("/oidc/revoke", post(revoke))
}

pub fn idp_protected_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/requests/{id}", get(idp_consent_info))
        .route("/requests/{id}/decision", post(idp_decide))
}

fn service(state: &AppState) -> Result<&Arc<IdpService>, Response> {
    state
        .idp_service
        .as_ref()
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())
}

// ── Protocol endpoints ──────────────────────────────────────────────

async fn discovery(State(state): State<Arc<AppState>>) -> Response {
    match service(&state) {
        Ok(svc) => (
            [(header::CACHE_CONTROL, "public, max-age=300")],
            Json(svc.discovery_document()),
        )
            .into_response(),
        Err(r) => r,
    }
}

async fn jwks(State(state): State<Arc<AppState>>) -> Response {
    match service(&state) {
        Ok(svc) => (
            [(header::CACHE_CONTROL, "public, max-age=300")],
            Json(svc.jwks()),
        )
            .into_response(),
        Err(r) => r,
    }
}

async fn authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let svc = match service(&state) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match svc.authorize(&params) {
        Ok(id) => found(
            &state
                .core
                .config
                .prefixed_path(&format!("/oauth/consent/{id}")),
        ),
        Err(AuthorizeError::Redirect(url)) => found(&url),
        // Never redirect to an unverified target; tell the human instead.
        Err(AuthorizeError::Untrusted(why)) => (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("Sign-in request rejected: {why}.\n"),
        )
            .into_response(),
    }
}

async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Response {
    let svc = match service(&state) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match svc.exchange_code(&req, basic_credentials(&headers)).await {
        Ok(tok) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(tok),
        )
            .into_response(),
        Err(e) => oauth_error(e),
    }
}

async fn userinfo(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let svc = match service(&state) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(bearer) = bearer_token(&headers) else {
        return oauth_error(OAuthError {
            status: 401,
            error: "invalid_token",
            description: "missing bearer token",
        });
    };
    match svc.userinfo(bearer).await {
        Ok(claims) => ([(header::CACHE_CONTROL, "no-store")], Json(claims)).into_response(),
        Err(e) => oauth_error(e),
    }
}

async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(req): Form<RevokeRequest>,
) -> Response {
    let svc = match service(&state) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match svc.revoke(&req, basic_credentials(&headers)) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => oauth_error(e),
    }
}

/// `302 Found` — what OAuth clients and the RFC 6749 examples use for the
/// authorization response. `Redirect::to` would send 303.
fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(v) => (StatusCode::FOUND, [(header::LOCATION, v)]).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn oauth_error(e: OAuthError) -> Response {
    let status = StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST);
    let mut resp = (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "error": e.error,
            "error_description": e.description,
        })),
    )
        .into_response();
    let challenge = match e.error {
        "invalid_client" => Some(r#"Basic realm="oxicloud""#.to_string()),
        "invalid_token" => Some(format!(r#"Bearer error="{}""#, e.error)),
        _ => None,
    };
    if let Some(c) = challenge.and_then(|c| HeaderValue::from_str(&c).ok()) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, c);
    }
    resp
}

/// RFC 6749 §2.3.1: id and secret are form-urlencoded before Basic encoding.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let unescape = |s: &str| -> String {
        url::form_urlencoded::parse(format!("v={s}").as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    Some((unescape(id), unescape(secret)))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

// ── SPA endpoints ───────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct IdpDecisionRequestDto {
    /// `true` to sign in to the relying party, `false` to decline.
    pub approve: bool,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct IdpDecisionResponseDto {
    /// Where the browser must go next (the relying party's redirect URI
    /// carrying either `code` or `error`).
    pub redirect_to: String,
}

#[utoipa::path(
    get,
    path = "/api/idp/requests/{id}",
    params(("id" = Uuid, Path, description = "Pending sign-in request id from the consent URL")),
    responses(
        (status = 200, description = "The pending sign-in request", body = ConsentInfoDto),
        (status = 401, description = "Not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 404, description = "Unknown, expired or already decided request — or the provider is disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "idp"
)]
pub async fn idp_consent_info(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ConsentInfoDto>, AppError> {
    let svc = state
        .idp_service
        .as_ref()
        .ok_or_else(|| AppError::not_found("OpenID provider is disabled"))?;
    svc.consent_info(id)
        .map(Json)
        .ok_or_else(|| AppError::not_found("Sign-in request not found or expired"))
}

#[utoipa::path(
    post,
    path = "/api/idp/requests/{id}/decision",
    params(("id" = Uuid, Path, description = "Pending sign-in request id from the consent URL")),
    request_body = IdpDecisionRequestDto,
    responses(
        (status = 200, description = "Decision recorded; navigate to `redirect_to`", body = IdpDecisionResponseDto),
        (status = 401, description = "Not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 403, description = "This account may not sign in to other services (external/guest or inactive)", body = crate::interfaces::errors::ApiErrorBody),
        (status = 404, description = "Unknown, expired or already decided request", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "idp"
)]
pub async fn idp_decide(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<IdpDecisionRequestDto>,
) -> Result<Json<IdpDecisionResponseDto>, AppError> {
    let svc = state
        .idp_service
        .as_ref()
        .ok_or_else(|| AppError::not_found("OpenID provider is disabled"))?;
    match svc.decide(id, user.id, body.approve).await {
        Ok(redirect_to) => Ok(Json(IdpDecisionResponseDto { redirect_to })),
        Err(DecideError::NotFound) => {
            Err(AppError::not_found("Sign-in request not found or expired"))
        }
        Err(DecideError::Forbidden(_)) => Err(AppError::forbidden(
            "This account cannot be used to sign in to other services",
        )),
        Err(DecideError::Internal(m)) => {
            tracing::error!("IdP decision failed: {m}");
            Err(AppError::internal_error("Sign-in failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_credentials_are_form_decoded() {
        let mut h = HeaderMap::new();
        let enc = base64::engine::general_purpose::STANDARD.encode("my%20client:s%3Acret");
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {enc}").parse().unwrap(),
        );
        assert_eq!(
            basic_credentials(&h),
            Some(("my client".into(), "s:cret".into()))
        );
    }

    #[test]
    fn bearer_extraction() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(bearer_token(&h), Some("abc"));
        h.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(bearer_token(&h), None);
    }
}
