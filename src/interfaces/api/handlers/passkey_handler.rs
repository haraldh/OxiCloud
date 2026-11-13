//! Passkey (WebAuthn) endpoints — `docs/plan/passkeys.md`, Phase 1.
//!
//! Two mounts with distinct prefixes (see `opaque_register_routes` on why
//! the prefixes must differ):
//! - `/api/auth/passkeys` — the signed-in user's own passkeys (auth, CSRF,
//!   DPoP layers in `main.rs`);
//! - `/api/auth/passkey/login` — public sign-in, behind the login rate
//!   limiter.
//!
//! The WebAuthn option and credential objects are passed through as the
//! JSON webauthn-rs defines (binary fields base64url); the SPA hands them
//! to `navigator.credentials`. Authorization and audit live in
//! `PasskeyService`.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::application::dtos::user_dto::AuthResponseDto;
use crate::application::services::passkey_service::{PasskeyError, PasskeyInfo, PasskeyService};
use crate::common::di::AppState;
use crate::domain::entities::session::SessionOrigin;
use crate::interfaces::api::cookie_auth;
use crate::interfaces::errors::AppError;
use crate::interfaces::middleware::auth::CurrentUserId;

/// Signed-in management routes. Mount under `/api/auth/passkeys`.
pub fn passkey_manage_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", axum::routing::get(list))
        .route("/register/start", post(register_start))
        .route("/register/finish", post(register_finish))
        .route("/{id}", patch(rename).delete(remove))
}

/// Public sign-in routes. Mount under `/api/auth/passkey/login`.
pub fn passkey_login_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/start", post(login_start))
        .route("/finish", post(login_finish))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyRegisterStartResponse {
    #[serde(rename = "ceremonyId")]
    pub ceremony_id: Uuid,
    /// `PublicKeyCredentialCreationOptions` wrapped as `{ publicKey }`,
    /// binary fields base64url.
    #[schema(value_type = Object)]
    pub options: CreationChallengeResponse,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PasskeyRegisterFinishDto {
    #[serde(rename = "ceremonyId")]
    pub ceremony_id: Uuid,
    /// What the user calls this passkey ("Laptop", "Phone"), 1–64 chars.
    pub name: String,
    /// The `PublicKeyCredential` from `navigator.credentials.create()`.
    #[schema(value_type = Object)]
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyLoginStartResponse {
    #[serde(rename = "ceremonyId")]
    pub ceremony_id: Uuid,
    /// `PublicKeyCredentialRequestOptions` wrapped as `{ publicKey }`,
    /// binary fields base64url. Empty allow list: the browser offers the
    /// user's passkeys for this site.
    #[schema(value_type = Object)]
    pub options: RequestChallengeResponse,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PasskeyLoginFinishDto {
    #[serde(rename = "ceremonyId")]
    pub ceremony_id: Uuid,
    /// The `PublicKeyCredential` from `navigator.credentials.get()`.
    #[schema(value_type = Object)]
    pub credential: PublicKeyCredential,
    /// DPoP key thumbprint to bind the new session to, as on the other
    /// login endpoints.
    #[serde(rename = "dpopJkt", default)]
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PasskeyRenameDto {
    pub name: String,
}

fn service(state: &AppState) -> Result<&Arc<PasskeyService>, AppError> {
    state.passkey_service.as_ref().ok_or_else(|| {
        AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Passkey sign-in is not enabled on this server",
            "PasskeysDisabled",
        )
    })
}

/// Management errors. NotFound covers "someone else's passkey" too, so ids
/// can't be probed.
fn manage_error(e: PasskeyError) -> AppError {
    match e {
        PasskeyError::NotFound => AppError::not_found("Passkey not found"),
        PasskeyError::InvalidName => AppError::new(
            StatusCode::BAD_REQUEST,
            "Name must be 1 to 64 characters",
            "PasskeyInvalidName",
        ),
        PasskeyError::LastFactor => AppError::new(
            StatusCode::CONFLICT,
            "This is your only way to sign in; add another passkey or a password first",
            "PasskeyLastFactor",
        ),
        PasskeyError::DuplicateCredential => AppError::new(
            StatusCode::CONFLICT,
            "This passkey is already registered",
            "PasskeyDuplicate",
        ),
        PasskeyError::ExternalUser | PasskeyError::AccountInactive => AppError::new(
            StatusCode::FORBIDDEN,
            "This account cannot add passkeys",
            "PasskeyNotAllowed",
        ),
        PasskeyError::CeremonyExpired | PasskeyError::VerificationFailed => AppError::new(
            StatusCode::BAD_REQUEST,
            "The passkey could not be verified; please try again",
            "PasskeyVerificationFailed",
        ),
        PasskeyError::UnknownCredential => AppError::not_found("Passkey not found"),
        PasskeyError::Internal(d) => AppError::from(d),
    }
}

#[utoipa::path(
    get,
    path = "/api/auth/passkeys",
    operation_id = "passkey_list",
    responses(
        (status = 200, description = "The caller's passkeys", body = [PasskeyInfo]),
        (status = 401, description = "Not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Passkeys disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
) -> Result<Json<Vec<PasskeyInfo>>, AppError> {
    Ok(Json(
        service(&state)?.list(caller).await.map_err(manage_error)?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/auth/passkeys/register/start",
    operation_id = "passkey_register_start",
    responses(
        (status = 200, description = "Creation options for navigator.credentials.create()", body = PasskeyRegisterStartResponse),
        (status = 401, description = "Not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 403, description = "External or inactive account", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Passkeys disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn register_start(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
) -> Result<Json<PasskeyRegisterStartResponse>, AppError> {
    let (ceremony_id, options) = service(&state)?
        .start_registration(caller)
        .await
        .map_err(manage_error)?;
    Ok(Json(PasskeyRegisterStartResponse {
        ceremony_id,
        options,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/passkeys/register/finish",
    operation_id = "passkey_register_finish",
    request_body = PasskeyRegisterFinishDto,
    responses(
        (status = 201, description = "Passkey registered", body = PasskeyInfo),
        (status = 400, description = "Expired ceremony, unverifiable credential, or bad name", body = crate::interfaces::errors::ApiErrorBody),
        (status = 401, description = "Not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 409, description = "Credential already registered", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Passkeys disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
    Json(dto): Json<PasskeyRegisterFinishDto>,
) -> Result<(StatusCode, Json<PasskeyInfo>), AppError> {
    let info = service(&state)?
        .finish_registration(caller, dto.ceremony_id, &dto.credential, &dto.name)
        .await
        .map_err(manage_error)?;
    Ok((StatusCode::CREATED, Json(info)))
}

#[utoipa::path(
    patch,
    path = "/api/auth/passkeys/{id}",
    operation_id = "passkey_rename",
    params(("id" = Uuid, Path, description = "Passkey id")),
    request_body = PasskeyRenameDto,
    responses(
        (status = 204, description = "Renamed"),
        (status = 400, description = "Bad name", body = crate::interfaces::errors::ApiErrorBody),
        (status = 404, description = "No such passkey of the caller's", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn rename(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
    Path(id): Path<Uuid>,
    Json(dto): Json<PasskeyRenameDto>,
) -> Result<StatusCode, AppError> {
    service(&state)?
        .rename(caller, id, &dto.name)
        .await
        .map_err(manage_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/api/auth/passkeys/{id}",
    operation_id = "passkey_remove",
    params(("id" = Uuid, Path, description = "Passkey id")),
    responses(
        (status = 204, description = "Removed"),
        (status = 404, description = "No such passkey of the caller's", body = crate::interfaces::errors::ApiErrorBody),
        (status = 409, description = "It is the account's only way to sign in", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    service(&state)?
        .delete(caller, id)
        .await
        .map_err(manage_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/auth/passkey/login/start",
    operation_id = "passkey_login_start",
    responses(
        (status = 200, description = "Request options for navigator.credentials.get()", body = PasskeyLoginStartResponse),
        (status = 503, description = "Passkeys disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn login_start(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PasskeyLoginStartResponse>, AppError> {
    let (ceremony_id, options) = service(&state)?.start_login().map_err(manage_error)?;
    Ok(Json(PasskeyLoginStartResponse {
        ceremony_id,
        options,
    }))
}

/// Same shape for every refusal, as the password login: the reason is in
/// the audit log, not the response.
fn invalid_credentials() -> AppError {
    AppError::new(
        StatusCode::UNAUTHORIZED,
        "Invalid credentials",
        "InvalidCredentials",
    )
}

#[utoipa::path(
    post,
    path = "/api/auth/passkey/login/finish",
    operation_id = "passkey_login_finish",
    request_body = PasskeyLoginFinishDto,
    responses(
        (status = 200, description = "Session issued", body = AuthResponseDto),
        (status = 401, description = "Sign-in refused", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Passkeys disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn login_finish(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(dto): Json<PasskeyLoginFinishDto>,
) -> Result<Response, AppError> {
    let svc = service(&state)?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or_else(|| AppError::service_unavailable("Authentication is not enabled"))?;

    let user_id = svc
        .finish_login(dto.ceremony_id, &dto.credential)
        .await
        .map_err(|e| match e {
            PasskeyError::Internal(d) => AppError::from(d),
            _ => invalid_credentials(),
        })?;
    let user = auth
        .auth_application_service
        .get_user_entity(user_id)
        .await
        .map_err(|_| invalid_credentials())?;

    let client_ip = crate::interfaces::middleware::trusted_proxy::client_ip_from_parts(
        &headers,
        Some(peer),
        false,
    );
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let session = auth
        .auth_application_service
        .mint_session_for_authenticated_user(
            user,
            dto.dpop_jkt,
            Some(client_ip),
            user_agent,
            SessionOrigin::Passkey,
        )
        .await
        .map_err(AppError::from)?;
    tracing::info!(
        target: "audit",
        event = "passkey.login_ok",
        user_id = %user_id,
        "passkey sign-in completed"
    );

    let mut response = (StatusCode::OK, Json(&session)).into_response();
    cookie_auth::append_login_cookies(response.headers_mut(), &state, &session);
    Ok(response)
}
