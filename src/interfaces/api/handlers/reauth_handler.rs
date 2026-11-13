//! Step-up re-authentication ("confirm it's you") —
//! `docs/plan/passkeys.md`, Phase 2a.
//!
//! Sensitive account changes sit behind `require_recent_auth_layer`, which
//! answers 403 `ReauthRequired` when the session's last sign-in is older
//! than the step-up window. These routes let the signed-in user prove who
//! they are again, with their password or one of their passkeys, which
//! stamps the current session. Mount under `/api/auth/reauth` with the
//! auth, CSRF, DPoP and no-pending-password-change layers, behind the login
//! rate limiter (the password route is a password oracle otherwise).

use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse};

use crate::application::services::auth_application_service::STEP_UP_WINDOW_MINUTES;
use crate::application::services::passkey_service::PasskeyError;
use crate::common::di::AppState;
use crate::common::errors::ErrorKind;
use crate::interfaces::errors::AppError;
use crate::interfaces::middleware::auth::{AuthSessionId, CurrentUserId};

pub fn reauth_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(methods))
        .route("/password", post(with_password))
        .route("/passkey/start", post(passkey_start))
        .route("/passkey/finish", post(passkey_finish))
}

/// What the caller can confirm with.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReauthMethods {
    /// The account has a password to check against.
    pub password: bool,
    /// The account has at least one passkey and passkeys are enabled.
    pub passkey: bool,
    /// How long a confirmation lasts, in minutes.
    pub window_minutes: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReauthPasswordDto {
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReauthPasskeyStartResponse {
    #[serde(rename = "ceremonyId")]
    pub ceremony_id: Uuid,
    /// `PublicKeyCredentialRequestOptions` wrapped as `{ publicKey }`,
    /// allowing only the caller's own passkeys.
    #[schema(value_type = Object)]
    pub options: RequestChallengeResponse,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReauthPasskeyFinishDto {
    #[serde(rename = "ceremonyId")]
    pub ceremony_id: Uuid,
    #[schema(value_type = Object)]
    pub credential: PublicKeyCredential,
}

fn auth_app(
    state: &AppState,
) -> Result<&crate::application::services::auth_application_service::AuthApplicationService, AppError>
{
    state
        .auth_service
        .as_ref()
        .map(|s| &*s.auth_application_service)
        .ok_or_else(|| {
            AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Authentication is disabled",
                "AuthDisabled",
            )
        })
}

/// The session to stamp. App-password and `sid`-less tokens have none and
/// can never confirm: the same 403 the gate gives them.
fn session(sid: Option<Extension<AuthSessionId>>) -> Result<Uuid, AppError> {
    sid.map(|Extension(AuthSessionId(id))| id).ok_or_else(|| {
        AppError::new(
            StatusCode::FORBIDDEN,
            "This kind of sign-in cannot confirm; sign in through the web page",
            "ReauthUnavailable",
        )
    })
}

/// Every refusal answers like a wrong password; the reason is in the
/// audit log (`auth.reauth_rejected`).
fn rejected() -> AppError {
    AppError::new(
        StatusCode::UNAUTHORIZED,
        "Could not confirm it's you",
        "InvalidCredentials",
    )
}

#[utoipa::path(
    get,
    path = "/api/auth/reauth",
    operation_id = "reauth_methods",
    responses(
        (status = 200, description = "How the caller can confirm it's them", body = ReauthMethods),
        (status = 401, description = "Not signed in", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn methods(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
) -> Result<Json<ReauthMethods>, AppError> {
    let password = auth_app(&state)?
        .can_reauth_with_password(caller)
        .await
        .map_err(AppError::from)?;
    let passkey = match state.passkey_service.as_ref() {
        Some(svc) => svc.has_passkeys(caller).await.map_err(passkey_error)?,
        None => false,
    };
    Ok(Json(ReauthMethods {
        password,
        passkey,
        window_minutes: STEP_UP_WINDOW_MINUTES,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/reauth/password",
    operation_id = "reauth_password",
    request_body = ReauthPasswordDto,
    responses(
        (status = 204, description = "Confirmed; sensitive actions are open for the step-up window"),
        (status = 401, description = "Wrong password, no password, or not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 403, description = "This session cannot confirm (app password)", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn with_password(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
    sid: Option<Extension<AuthSessionId>>,
    Json(dto): Json<ReauthPasswordDto>,
) -> Result<StatusCode, AppError> {
    let session_id = session(sid)?;
    match auth_app(&state)?
        .reauth_with_password(caller, session_id, &dto.password)
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) if e.kind == ErrorKind::AccessDenied => Err(rejected()),
        Err(e) => Err(AppError::from(e)),
    }
}

#[utoipa::path(
    post,
    path = "/api/auth/reauth/passkey/start",
    operation_id = "reauth_passkey_start",
    responses(
        (status = 200, description = "Request options for navigator.credentials.get()", body = ReauthPasskeyStartResponse),
        (status = 401, description = "No passkey to confirm with, or not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Passkeys disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn passkey_start(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
) -> Result<Json<ReauthPasskeyStartResponse>, AppError> {
    let (ceremony_id, options) = super::passkey_handler::service(&state)?
        .start_reauth(caller)
        .await
        .map_err(passkey_error)?;
    Ok(Json(ReauthPasskeyStartResponse {
        ceremony_id,
        options,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/reauth/passkey/finish",
    operation_id = "reauth_passkey_finish",
    request_body = ReauthPasskeyFinishDto,
    responses(
        (status = 204, description = "Confirmed; sensitive actions are open for the step-up window"),
        (status = 401, description = "Did not verify, or not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 403, description = "This session cannot confirm (app password)", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Passkeys disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn passkey_finish(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
    sid: Option<Extension<AuthSessionId>>,
    Json(dto): Json<ReauthPasskeyFinishDto>,
) -> Result<StatusCode, AppError> {
    let session_id = session(sid)?;
    super::passkey_handler::service(&state)?
        .finish_reauth(caller, dto.ceremony_id, &dto.credential)
        .await
        .map_err(passkey_error)?;
    match auth_app(&state)?
        .mark_reauthenticated(caller, session_id, "passkey")
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) if e.kind == ErrorKind::AccessDenied => Err(rejected()),
        Err(e) => Err(AppError::from(e)),
    }
}

/// Refusals are already audited by the service; they answer as a plain
/// 401 like a wrong password.
fn passkey_error(e: PasskeyError) -> AppError {
    match e {
        PasskeyError::Internal(d) => AppError::from(d),
        _ => rejected(),
    }
}
