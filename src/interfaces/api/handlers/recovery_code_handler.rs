//! Recovery codes — `docs/plan/passkeys.md`, Phase 2a.
//!
//! - `/api/auth/recovery-codes` (signed in): how many are left; make a new
//!   set (step-up, it replaces a way into the account).
//! - `/api/auth/recovery/login` (public, login rate limiter): sign in with
//!   a code. The new session is freshly authenticated, so the user can add
//!   a passkey right away.
//!
//! Authorization and audit live in `RecoveryCodeService`.

use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::application::services::recovery_code_service::{RecoveryCodeService, RecoveryError};
use crate::common::di::AppState;
use crate::domain::entities::session::SessionOrigin;
use crate::interfaces::api::cookie_auth;
use crate::interfaces::errors::AppError;
use crate::interfaces::middleware::auth::CurrentUserId;

/// Signed-in routes. Mount under `/api/auth/recovery-codes`.
pub fn recovery_code_manage_routes(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new().route(
        "/",
        get(status).merge(
            post(generate).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::interfaces::middleware::user::require_recent_auth_layer,
            )),
        ),
    )
}

/// Public sign-in. Mount under `/api/auth/recovery`.
pub fn recovery_login_routes() -> Router<Arc<AppState>> {
    Router::new().route("/login", post(login))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryCodeStatusDto {
    /// Unused codes left.
    pub remaining: u32,
    /// When the current set was made; absent when there is none.
    pub generated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryCodesDto {
    /// The new codes, shown once. Each signs in once.
    pub codes: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RecoveryLoginDto {
    pub username: String,
    pub code: String,
    /// DPoP key thumbprint to bind the new session to, as on the other
    /// login endpoints.
    #[serde(rename = "dpopJkt", default)]
    pub dpop_jkt: Option<String>,
}

fn service(state: &AppState) -> Result<&Arc<RecoveryCodeService>, AppError> {
    state.recovery_code_service.as_ref().ok_or_else(|| {
        AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Recovery codes need passkeys, which are not enabled on this server",
            "RecoveryCodesDisabled",
        )
    })
}

fn manage_error(e: RecoveryError) -> AppError {
    match e {
        RecoveryError::ExternalUser | RecoveryError::AccountInactive => AppError::new(
            StatusCode::FORBIDDEN,
            "This account cannot have recovery codes",
            "RecoveryCodesNotAllowed",
        ),
        RecoveryError::Rejected => cookie_auth::invalid_credentials(),
        RecoveryError::Internal(d) => AppError::from(d),
    }
}

#[utoipa::path(
    get,
    path = "/api/auth/recovery-codes",
    operation_id = "recovery_codes_status",
    responses(
        (status = 200, description = "How many codes are left", body = RecoveryCodeStatusDto),
        (status = 401, description = "Not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Passkeys (and so recovery codes) disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn status(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
) -> Result<Json<RecoveryCodeStatusDto>, AppError> {
    let s = service(&state)?
        .status(caller)
        .await
        .map_err(manage_error)?;
    Ok(Json(RecoveryCodeStatusDto {
        remaining: s.remaining,
        generated_at: s.generated_at,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/recovery-codes",
    operation_id = "recovery_codes_generate",
    responses(
        (status = 200, description = "A new set; the old one no longer works", body = RecoveryCodesDto),
        (status = 401, description = "Not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 403, description = "Confirm it's you first (`ReauthRequired`), or a guest account", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Passkeys (and so recovery codes) disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn generate(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
) -> Result<Json<RecoveryCodesDto>, AppError> {
    let codes = service(&state)?
        .generate(caller)
        .await
        .map_err(manage_error)?;
    Ok(Json(RecoveryCodesDto { codes }))
}

#[utoipa::path(
    post,
    path = "/api/auth/recovery/login",
    operation_id = "recovery_login",
    request_body = RecoveryLoginDto,
    responses(
        (status = 200, description = "Signed in; same body and cookies as a password login", body = crate::application::dtos::user_dto::AuthResponseDto),
        (status = 401, description = "Unknown user, wrong or used code", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Passkeys (and so recovery codes) disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(dto): Json<RecoveryLoginDto>,
) -> Result<Response, AppError> {
    let user_id = service(&state)?
        .redeem(&dto.username, &dto.code)
        .await
        .map_err(|e| match e {
            RecoveryError::Internal(d) => AppError::from(d),
            _ => cookie_auth::invalid_credentials(),
        })?;
    cookie_auth::signed_in_response(
        &state,
        peer,
        &headers,
        user_id,
        dto.dpop_jkt,
        SessionOrigin::Recovery,
    )
    .await
}
