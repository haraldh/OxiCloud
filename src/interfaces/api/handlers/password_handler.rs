//! Removing the account password — `docs/plan/passkeys.md`, Phase 2a
//! step 4. Mount under `/api/auth/password` with the signed-in stack; the
//! step-up gate is on the route. Rules and audit live in
//! `PasswordRemovalService`.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;

use crate::application::services::password_removal_service::PasswordRemovalError;
use crate::common::di::AppState;
use crate::interfaces::errors::AppError;
use crate::interfaces::middleware::auth::CurrentUserId;

pub fn password_routes(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new().route(
        "/",
        axum::routing::delete(remove).route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::interfaces::middleware::user::require_recent_auth_layer,
        )),
    )
}

#[utoipa::path(
    delete,
    path = "/api/auth/password",
    operation_id = "password_remove",
    responses(
        (status = 204, description = "Password removed; the account signs in with passkeys"),
        (status = 401, description = "Not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 403, description = "Confirm it's you first (`ReauthRequired`), or a guest / SSO account (`PasswordRemovalNotAllowed`)", body = crate::interfaces::errors::ApiErrorBody),
        (status = 409, description = "No password (`NoPassword`), or not enough to fall back on (`PasswordRemovalNeedsBackup`)", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Passkeys disabled", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "auth"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    CurrentUserId(caller): CurrentUserId,
) -> Result<StatusCode, AppError> {
    let svc = state.password_removal_service.as_ref().ok_or_else(|| {
        AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Removing the password needs passkeys, which are not enabled on this server",
            "PasskeysDisabled",
        )
    })?;
    svc.remove_password(caller).await.map_err(|e| match e {
        PasswordRemovalError::NotAllowed | PasswordRemovalError::Federated => AppError::new(
            StatusCode::FORBIDDEN,
            "This account's password cannot be removed",
            "PasswordRemovalNotAllowed",
        ),
        PasswordRemovalError::NoPassword => AppError::new(
            StatusCode::CONFLICT,
            "This account has no password",
            "NoPassword",
        ),
        PasswordRemovalError::NeedsBackup => AppError::new(
            StatusCode::CONFLICT,
            "Add a second passkey or create recovery codes first",
            "PasswordRemovalNeedsBackup",
        ),
        PasswordRemovalError::Internal(d) => AppError::from(d),
    })?;
    Ok(StatusCode::NO_CONTENT)
}
