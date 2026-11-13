use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Json, Redirect, Response},
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use crate::application::ports::folder_ports::FolderUseCase;
use crate::common::di::AppState;
use crate::common::errors::DomainError;
use crate::interfaces::middleware::auth::CurrentUser;

/// Drive option rendered on the picker page. `name` is the folder's
/// display name; `id` is the folder UUID that becomes the `~{marker}`
/// half of the composite Basic-Auth username if the user picks
/// anything other than the first (home) row.
struct DriveOption {
    id: String,
    name: String,
}

#[derive(Template)]
#[template(path = "nextcloud/drive_picker.html")]
struct DrivePickerTemplate {
    /// Deployment base path for the shared asset links; `""` at the root.
    base: String,
    form_action: String,
    drives: Vec<DriveOption>,
}

// Home identification is via `position_of_user_home_root_folder` from
// `domain::repositories::drive_repository` — a generic helper that
// keys off `drives.default_for_user == user_id` rather than folder
// name, so user renames of the home folder don't silently break the
// picker UX.

pub async fn handle_login_initiate(State(state): State<Arc<AppState>>) -> Response {
    let nextcloud = match state.nextcloud.as_ref() {
        Some(nextcloud) => nextcloud,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let base_url = state.core.config.base_url();
    let flow = match nextcloud.login_flow.initiate(&base_url) {
        Ok(flow) => flow,
        Err(_) => {
            tracing::warn!("Login Flow v2: too many pending flows, rejecting");
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    };

    tracing::info!(
        base_url = %base_url,
        login_url = %flow.login_url,
        poll_endpoint = %flow.poll_endpoint,
        "Login Flow v2 initiated"
    );

    Json(json!({
        "poll": {
            "token": flow.poll_token,
            "endpoint": flow.poll_endpoint,
        },
        "login": flow.login_url,
    }))
    .into_response()
}

pub async fn handle_login_poll(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: String,
) -> Response {
    let nextcloud = match state.nextcloud.as_ref() {
        Some(nextcloud) => nextcloud,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");

    tracing::debug!(
        body = %body,
        content_type = %content_type,
        query_has_token = query.contains_key("token"),
        "Login Flow v2 poll request"
    );

    // Try to extract token from multiple sources:
    // 1. Form-encoded body (token=xxx)
    // 2. JSON body ({"token": "xxx"})
    // 3. Query parameter (?token=xxx)
    let token = parse_form_value(&body, "token")
        .or_else(|| {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("token")?.as_str().map(String::from))
        })
        .or_else(|| query.get("token").cloned());

    let token = match token {
        Some(token) => token,
        None => {
            tracing::warn!(
                body = %body,
                content_type = %content_type,
                "Login Flow v2 poll: could not extract token from body, JSON, or query"
            );
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    match nextcloud.login_flow.poll(&token) {
        Some(result) => {
            tracing::info!(
                login_name = %result.login_name,
                server = %result.server,
                "Login Flow v2 poll: returning completed credentials"
            );
            Json(json!({
                "server": result.server,
                "loginName": result.login_name,
                "appPassword": result.app_password,
            }))
            .into_response()
        }
        None => {
            tracing::debug!("Login Flow v2 poll: not yet completed");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

pub async fn handle_login_page(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    let nextcloud = match state.nextcloud.as_ref() {
        Some(nextcloud) => nextcloud,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    if !nextcloud.login_flow.flow_exists(&token) {
        return StatusCode::NOT_FOUND.into_response();
    }

    // The grant-access page is now owned by the SvelteKit SPA at
    // /nextcloud/login; redirect the client's browser there with the flow
    // token. The page POSTs back to /login/v2/flow/{token} (handle_login_submit).
    Redirect::to(&format!(
        "{}/nextcloud/login?token={token}",
        crate::common::config::server_base_path()
    ))
    .into_response()
}

pub async fn handle_login_submit(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    body: String,
) -> Response {
    let nextcloud = match state.nextcloud.as_ref() {
        Some(nextcloud) => nextcloud,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let params = parse_form(&body);
    let username = match params.get("user") {
        Some(value) if !value.is_empty() => value,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let password = match params.get("password") {
        Some(value) if !value.is_empty() => value,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };

    let auth = match state.auth_service.as_ref() {
        Some(auth) => auth,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let current_user = match auth
        .auth_application_service
        .verify_credentials(username, password)
        .await
    {
        Ok(user) => user,
        Err(e) => return login_failed_response(e),
    };

    // ── Multi-drive fork ─────────────────────────────────────────────
    // List the user's root folders. By convention the first row is the
    // user's home; additional rows are extra drives (POC seeded by
    // direct DB insert until a drive admin surface exists). With 0 or
    // 1 drive we go straight to the legacy one-shot completion path so
    // the common case stays one click. With ≥2 drives we pause the
    // flow, stash the user_id, and render the picker — drive selection
    // resumes the flow via `handle_drive_pick`.
    let drives = match state
        .applications
        .folder_service
        .list_folders_with_perms(None, current_user.id)
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, user = %current_user.username, "Login Flow v2: failed to list drives");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    resolve_drive_or_complete(
        &state,
        nextcloud,
        &token,
        &current_user,
        "Nextcloud",
        drives,
    )
    .await
}

/// Shared "multi-drive fork" step used by both the password path
/// (`handle_login_submit`) and the OIDC path
/// (`handle_oidc_login_completion`).
///
/// - `label` is the app-password label persisted when `complete_flow`
///   creates the credential. Callers pass a channel-identifying string
///   (`"Nextcloud"` for password, `"Nextcloud (OIDC)"` for OIDC) so the
///   audit trail can distinguish provenance without another column.
/// - `drives` is the caller's pre-fetched drive list — the two callers
///   already list drives before invoking us (the password path lists
///   after `verify_credentials`, the OIDC path lists after
///   `get_user_by_id`), so re-listing here would be a wasted query.
async fn resolve_drive_or_complete(
    state: &Arc<AppState>,
    nextcloud: &crate::common::di::NextcloudServices,
    token: &str,
    current_user: &CurrentUser,
    label: &'static str,
    drives: Vec<crate::application::dtos::folder_dto::FolderDto>,
) -> Response {
    flow_next_html(
        token,
        advance_flow(state, nextcloud, token, current_user, label, drives).await,
    )
}

/// Where an authenticated Login Flow v2 goes next. Shared by the browser
/// (HTML) paths and the signed-in SPA path (`handle_session_grant`, JSON),
/// so all of them pick drives and mint the app password the same way.
enum FlowNext {
    /// Done (success page) or the flow vanished (error page).
    Redirect(String),
    /// Two or more drives: the user picks one. Home is first.
    PickDrive(Vec<crate::application::dtos::folder_dto::FolderDto>),
}

fn flow_next_html(token: &str, next: Result<FlowNext, StatusCode>) -> Response {
    match next {
        Ok(FlowNext::Redirect(url)) => axum::response::Redirect::to(&url).into_response(),
        Ok(FlowNext::PickDrive(drives)) => render_drive_picker(token, &drives),
        Err(status) => status.into_response(),
    }
}

fn session_expired_url() -> String {
    format!(
        "{}/nextcloud/error?type=session-expired",
        crate::common::config::server_base_path()
    )
}

async fn advance_flow(
    state: &Arc<AppState>,
    nextcloud: &crate::common::di::NextcloudServices,
    token: &str,
    current_user: &CurrentUser,
    label: &'static str,
    mut drives: Vec<crate::application::dtos::folder_dto::FolderDto>,
) -> Result<FlowNext, StatusCode> {
    if drives.len() >= 2 {
        // Reorder so home is at index 0. The picker template ties
        // both the default-checked radio and the "Home" badge to
        // `loop.first`, so placing home first is the single point
        // that makes the picker UI line up with the home convention.
        // Other drives keep their original alphabetical order.
        if let Some(idx) =
            crate::domain::repositories::drive_repository::position_of_user_home_root_folder(
                state.drive_repo.as_ref(),
                current_user.id,
                &drives,
                |f| uuid::Uuid::parse_str(&f.id).ok(),
            )
            .await
            && idx != 0
        {
            let home = drives.remove(idx);
            drives.insert(0, home);
        }
        // If no home matched the convention, we fall through with the
        // raw alphabetical order. The picker will still work but the
        // first row gets the badge by default — slightly wrong UX but
        // never breaks the auth flow (`handle_drive_pick` re-runs
        // `find_home_index` independently).

        if !nextcloud
            .login_flow
            .mark_awaiting_drive(token, current_user.id)
        {
            // Flow token vanished (TTL?) between auth and here —
            // extremely unlikely but treat the same as any
            // session-expired case.
            return Ok(FlowNext::Redirect(session_expired_url()));
        }
        // Persist the label so `handle_drive_pick` can pass the correct
        // provenance string when it later calls `complete_flow`. Set
        // even for the password path (where label == "Nextcloud") so
        // the read-back is uniform.
        nextcloud
            .login_flow
            .set_pending_app_password_label(token, label);
        return Ok(FlowNext::PickDrive(drives));
    }

    complete_flow_target(
        state,
        &nextcloud.login_flow,
        token,
        current_user,
        None,
        label,
    )
    .await
    .map(FlowNext::Redirect)
}

/// Complete an OIDC-authenticated NC Login Flow v2.
///
/// Called from the OIDC callback (`auth_handler::oidc_callback`) when
/// the state carried an `nc_flow_token`. Mirrors the password path's
/// multi-drive fork exactly — the browser lands on the drive picker
/// when the user has ≥ 2 drives, or on the success page when they
/// have one. NC clients pick up credentials via the poll endpoint in
/// both cases (backchannel), so no `nc://` frontchannel URL is emitted.
///
/// Prior to this refactor the OIDC callback minted the app password
/// inline and completed the flow with the bare username (no `~<uuid>`
/// marker) — customers with multiple drives had no way to pick a
/// non-home drive under SSO. Routing through `resolve_drive_or_complete`
/// fixes that and dedups the branching logic against the password path.
pub async fn handle_oidc_login_completion(
    state: &Arc<AppState>,
    token: &str,
    user_id: uuid::Uuid,
    username: &str,
) -> Response {
    let nextcloud = match state.nextcloud.as_ref() {
        Some(nc) => nc,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let auth = match state.auth_service.as_ref() {
        Some(a) => a,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    // Full user record — needed to build the `CurrentUser` the shared
    // helpers expect (email + role in particular). We already have the
    // username from the OIDC claims, but not the rest.
    let user_dto = match auth.auth_application_service.get_user_by_id(user_id).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, %user_id, user = %username, "OIDC+NC: failed to fetch user by id");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let current_user = CurrentUser {
        id: user_id,
        username: std::sync::Arc::from(username),
        email: std::sync::Arc::from(user_dto.email.as_str()),
        role: smol_str::SmolStr::new(user_dto.role.as_str()),
        // NC login-flow-v2 mints an app password — no browser, no
        // WebCrypto, always unbound. DPoP middleware exempts.
        dpop_jkt: None,
    };

    let drives = match state
        .applications
        .folder_service
        .list_folders_with_perms(None, current_user.id)
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, user = %current_user.username, "OIDC+NC: failed to list drives");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    resolve_drive_or_complete(
        state,
        nextcloud,
        token,
        &current_user,
        "Nextcloud (OIDC)",
        drives,
    )
    .await
}

/// Render the drive picker page. The form posts to
/// `/login/v2/flow/{token}/drive`, carrying only the chosen folder
/// UUID — the authenticated user id is read from the flow's
/// `pending_user_id` slot (consumed by `take_pending_user`).
fn render_drive_picker(
    token: &str,
    drives: &[crate::application::dtos::folder_dto::FolderDto],
) -> Response {
    let template = DrivePickerTemplate {
        base: crate::common::config::server_base_path().to_string(),
        form_action: format!(
            "{}/login/v2/flow/{}/drive",
            crate::common::config::server_base_path(),
            token
        ),
        drives: drives
            .iter()
            .map(|f| DriveOption {
                id: f.id.clone(),
                name: f.name.clone(),
            })
            .collect(),
    };

    match template.render() {
        Ok(html) => (
            [(
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'",
            )],
            Html(html),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Login Flow v2: drive picker template render failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Mint an app password, complete the flow, and emit the `nc://` deep
/// link. Shared by the single-drive path (called from
/// `handle_login_submit`) and the post-picker path (called from
/// `handle_drive_pick`).
///
/// `drive_id` is `None` for the single-drive shortcut and for the
/// home-drive choice on the picker; `Some(uuid)` for any other drive,
/// in which case the NC login name carries the `~{uuid}` marker.
async fn complete_flow_target(
    state: &Arc<AppState>,
    login_flow: &crate::application::services::nextcloud_login_flow_service::NextcloudLoginFlowService,
    token: &str,
    user: &CurrentUser,
    drive_id: Option<&str>,
    // Persisted verbatim as `auth.app_passwords.label`. Callers pass
    // `"Nextcloud"` for the password path, `"Nextcloud (OIDC)"` for the
    // OIDC path and `"Nextcloud (session)"` for the signed-in path so
    // operators can distinguish provenance from the audit log alone.
    label: &str,
) -> Result<String, StatusCode> {
    let nextcloud = state
        .nextcloud
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let app_password = match nextcloud.app_passwords.create_nc(user.id, label).await {
        Ok((_id, password)) => password,
        Err(e) => {
            tracing::error!(error = %e, user = %user.username, "Login Flow v2: failed to create app password");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let login_name = match drive_id {
        Some(uuid) => format!("{}~{}", user.username, uuid),
        None => user.username.to_string(),
    };

    let base_url = state.core.config.base_url();
    let completed = login_flow.complete(token, &login_name, &base_url, &app_password);

    if completed {
        tracing::info!(
            user = %user.username,
            login_name = %login_name,
            base_url = %base_url,
            "Login Flow v2: flow completed successfully"
        );
        // Redirect the browser to a visible success page. NC clients
        // that use the LFv2 poll endpoint (the standard pattern) have
        // already received the credentials server-to-server through
        // `login_flow.complete()` above — they don't need any browser
        // hand-off.
        //
        // We deliberately do NOT redirect to `nc://login/…` here:
        //   1. Plain browsers can't follow it → the tab looks stuck
        //      on the picker → user clicks Continue again → second
        //      click hits an already-consumed flow token → ends up
        //      on `/nextcloud/error?type=session-expired`.
        //   2. NC desktop clients that pick it up while their poll
        //      has already succeeded try to complete the flow a
        //      second time, which fails validation ("Impossible de
        //      valider la requête") — the poll session is fine, the
        //      dialog is spurious noise.
        //
        // If a client ever needs a frontchannel `nc://` handoff
        // (older NC releases, mobile), reintroduce the URL as a
        // client-side-only fragment (`#target=…`) and add a manual
        // "Open Nextcloud" fallback on the success page. Keep the
        // credentials out of the query string either way — the query
        // string reaches server access logs.
        Ok(format!(
            "{}/nextcloud/success",
            crate::common::config::server_base_path()
        ))
    } else {
        tracing::error!(
            user = %user.username,
            "Login Flow v2: complete() returned false — flow token not found"
        );
        Ok(session_expired_url())
    }
}

/// POST `/login/v2/flow/{token}/drive` — finalise a paused login flow
/// after the user picks a drive on the picker page.
///
/// Auth model: the route is **public** (no Basic Auth — this is the
/// browser-side leg of Login Flow v2, before the app password is
/// issued). The proof of authentication is the single-use
/// `pending_user_id` slot on the flow, set by `handle_login_submit`
/// after password verification and consumed here. Replay is naturally
/// blocked: a second POST finds nothing to consume.
pub async fn handle_drive_pick(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    body: String,
) -> Response {
    let nextcloud = match state.nextcloud.as_ref() {
        Some(nc) => nc,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let drive_id = match parse_form_value(&body, "drive") {
        Some(v) if !v.is_empty() => v,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };

    let user_id = match nextcloud.login_flow.take_pending_user(&token) {
        Some(uid) => uid,
        None => {
            tracing::warn!(
                target: "audit",
                event = "nc_login_flow.drive_pick_rejected",
                reason = "no_pending_user",
                "👮🏻‍♂️ NC drive pick rejected: flow has no pending user (replay or unknown token)"
            );
            return axum::response::Redirect::to(&format!(
                "{}/nextcloud/error?type=session-expired",
                crate::common::config::server_base_path()
            ))
            .into_response();
        }
    };

    // Resolve user (for username) and validate drive ownership in one
    // service call each. `get_folder_with_perms` enforces that the
    // caller can read the folder — covers "drive doesn't exist" and
    // "drive belongs to someone else" with the same 404 to defeat
    // enumeration. We additionally need to differentiate home vs.
    // non-home so the NC login name carries `~{uuid}` only for
    // non-home choices.
    let auth = match state.auth_service.as_ref() {
        Some(a) => a,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let user_dto = match auth.auth_application_service.get_user_by_id(user_id).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, %user_id, "Login Flow v2: failed to fetch user for drive pick");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // Username must be present — only password-login users reach this
    // branch, and password login requires a claimed username. Defensive
    // check anyway: a username-less user here means an upstream invariant
    // broke, not something to silently paper over.
    let Some(username) = user_dto.username.clone() else {
        tracing::error!(%user_id, "Login Flow v2: pending user has no username — invariant violated");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let user = CurrentUser {
        id: user_id,
        username: std::sync::Arc::from(username.as_str()),
        email: std::sync::Arc::from(user_dto.email.as_str()),
        role: smol_str::SmolStr::new(user_dto.role.as_str()),
        // NC login-flow-v2 mints an app password — no browser, no
        // WebCrypto, always unbound. DPoP middleware exempts.
        dpop_jkt: None,
    };

    let _folder = match state
        .applications
        .folder_service
        .get_folder_with_perms(
            &drive_id,
            crate::domain::services::authorization::Subject::User(user_id),
        )
        .await
    {
        Ok(f) => f,
        Err(_) => {
            tracing::warn!(
                target: "audit",
                event = "nc_login_flow.drive_pick_rejected",
                reason = "drive_not_owned_or_missing",
                %user_id,
                drive_id = %drive_id,
                "👮🏻‍♂️ NC drive pick rejected: folder missing or caller has no read access"
            );
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    // Determine if the pick is home. The previous "first row of
    // list_folders_with_perms" heuristic was wrong: the underlying
    // repo query orders by `name`, so any drive named alphabetically
    // before "My Folder - {username}" stole the first slot and was
    // mis-classified as home — `login_name` then dropped the `~uuid`
    // marker and NC desktop rooted at the home folder regardless of
    // the user's pick. `find_home_index` keys off the registered
    // home-folder name, which extra drives (POC SQL-seeded) don't
    // share, so it disambiguates cleanly.
    let drives = match state
        .applications
        .folder_service
        .list_folders_with_perms(None, user_id)
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, %user_id, "Login Flow v2: failed to list drives for home detection");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let home_id = crate::domain::repositories::drive_repository::position_of_user_home_root_folder(
        state.drive_repo.as_ref(),
        user.id,
        &drives,
        |f| uuid::Uuid::parse_str(&f.id).ok(),
    )
    .await
    .map(|i| drives[i].id.as_str());
    let is_home = home_id == Some(drive_id.as_str());
    let drive_marker = if is_home {
        None
    } else {
        Some(drive_id.as_str())
    };

    // Preserved label from the auth step ("Nextcloud" for password
    // flow, "Nextcloud (OIDC)" for OIDC). Stashed by
    // `resolve_drive_or_complete` when the picker was rendered; falls
    // back to `"Nextcloud"` if the stash is missing (defensive — should
    // never happen post-refactor, but keeps behaviour identical to the
    // pre-refactor hardcoded label if some future path forgets to set).
    let label = nextcloud
        .login_flow
        .take_pending_app_password_label(&token)
        .unwrap_or_else(|| "Nextcloud".to_string());

    flow_next_html(
        &token,
        complete_flow_target(
            &state,
            &nextcloud.login_flow,
            &token,
            &user,
            drive_marker,
            &label,
        )
        .await
        .map(FlowNext::Redirect),
    )
}

/// GET /login/v2/flow/{token}/oidc — Start an OIDC authorization flow that is
/// tied to a Nextcloud Login Flow v2 session.  After successful IdP
/// authentication the regular `/api/auth/oidc/callback` endpoint will detect
/// the NC flow token and complete the Nextcloud login instead of issuing
/// internal JWTs.
pub async fn handle_login_oidc(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    // Verify Nextcloud services are configured
    let nextcloud = match state.nextcloud.as_ref() {
        Some(nc) => nc,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    // Verify the NC login flow token exists
    if !nextcloud.login_flow.flow_exists(&token) {
        return axum::response::Redirect::to(&format!(
            "{}/nextcloud/error?type=session-expired",
            crate::common::config::server_base_path()
        ))
        .into_response();
    }

    // Verify auth + OIDC are configured and enabled
    let auth = match state.auth_service.as_ref() {
        Some(auth) => auth,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    if !auth.auth_application_service.oidc_enabled() {
        tracing::warn!("OIDC login requested on NC login page but OIDC is not enabled");
        return StatusCode::NOT_FOUND.into_response();
    }

    // Prepare an OIDC authorize flow that carries the NC flow token
    match auth
        .auth_application_service
        .prepare_oidc_authorize_for_nextcloud(&token)
        .await
    {
        Ok(authorize_url) => {
            tracing::info!("OIDC authorize redirect for Nextcloud Login Flow v2");
            axum::response::Redirect::temporary(&authorize_url).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to prepare OIDC authorize for NC login");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn login_failed_response(_err: DomainError) -> Response {
    axum::response::Redirect::to(&format!(
        "{}/nextcloud/error?type=invalid-credentials",
        crate::common::config::server_base_path()
    ))
    .into_response()
}

fn parse_form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            let key = urlencoding::decode(key).ok()?.to_string();
            let value = urlencoding::decode(value).ok()?.to_string();
            Some((key, value))
        })
        .collect()
}

fn parse_form_value(body: &str, key: &str) -> Option<String> {
    parse_form(body).remove(key)
}

// ── Grant with the current session (docs/plan/passkeys.md, Phase 2a) ──

/// Signed-in SPA routes for Login Flow v2. Mount under
/// `/api/nextcloud/login-flow` with the auth, CSRF, DPoP, internal-user and
/// no-pending-password-change layers. The grant mints a long-lived app
/// password, so it also needs a recent sign-in (`require_recent_auth_layer`).
pub fn login_flow_session_routes(state: &Arc<AppState>) -> axum::Router<Arc<AppState>> {
    axum::Router::new().route(
        "/{token}/grant",
        axum::routing::post(handle_session_grant).route_layer(
            axum::middleware::from_fn_with_state(
                state.clone(),
                crate::interfaces::middleware::user::require_recent_auth_layer,
            ),
        ),
    )
}

/// One drive the user can link the client to. The first is home.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct LoginFlowDrive {
    pub id: String,
    pub name: String,
}

/// What the page does next: follow `redirect`, or let the user pick one of
/// `drives` and post the choice (form field `drive`) to `pick_action`.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct LoginFlowGrantResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drives: Option<Vec<LoginFlowDrive>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pick_action: Option<String>,
}

fn grant_error(status: StatusCode, message: &str, error_type: &'static str) -> Response {
    crate::interfaces::errors::AppError::new(status, message, error_type).into_response()
}

/// POST `/api/nextcloud/login-flow/{token}/grant` — link the Nextcloud
/// client that started flow `{token}` to the signed-in account, without a
/// password. This is how a passkey-only account connects a desktop client.
///
/// Always a deliberate click on the grant page: the flow token comes from
/// whoever started the flow, so granting it hands that client an app
/// password for this account.
#[utoipa::path(
    post,
    path = "/api/nextcloud/login-flow/{token}/grant",
    operation_id = "nextcloud_login_flow_grant",
    params(("token" = String, Path, description = "Login Flow v2 token from the client's browser URL")),
    responses(
        (status = 200, description = "Linked (`redirect`), or a drive must be picked (`drives`)", body = LoginFlowGrantResponse),
        (status = 401, description = "Not signed in", body = crate::interfaces::errors::ApiErrorBody),
        (status = 403, description = "Confirm it's you first (`ReauthRequired`), or an external account", body = crate::interfaces::errors::ApiErrorBody),
        (status = 404, description = "No such flow (expired or already used)", body = crate::interfaces::errors::ApiErrorBody),
        (status = 409, description = "The account has no username to sign the client in with", body = crate::interfaces::errors::ApiErrorBody),
        (status = 503, description = "Nextcloud compatibility is off", body = crate::interfaces::errors::ApiErrorBody),
    ),
    tag = "nextcloud"
)]
pub async fn handle_session_grant(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    crate::interfaces::middleware::auth::AuthUser(user): crate::interfaces::middleware::auth::AuthUser,
) -> Response {
    let Some(nextcloud) = state.nextcloud.as_ref() else {
        return grant_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Nextcloud compatibility is not enabled",
            "NextcloudDisabled",
        );
    };
    if !nextcloud.login_flow.flow_exists(&token) {
        tracing::info!(
            target: "audit",
            event = "nc_login_flow.session_grant_rejected",
            reason = "unknown_flow",
            user_id = %user.id,
            "👮🏻‍♂️ NC session grant refused: no such login flow"
        );
        return grant_error(
            StatusCode::NOT_FOUND,
            "This sign-in request has expired or was already used",
            "LoginFlowNotFound",
        );
    }
    // The client signs in as `username[~drive]`; an account without one
    // (email-only) cannot be expressed. Same invariant the drive pick
    // checks.
    if user.username.is_empty() {
        tracing::info!(
            target: "audit",
            event = "nc_login_flow.session_grant_rejected",
            reason = "no_username",
            user_id = %user.id,
            "👮🏻‍♂️ NC session grant refused: account has no username"
        );
        return grant_error(
            StatusCode::CONFLICT,
            "Set a username in your profile before linking a Nextcloud client",
            "UsernameRequired",
        );
    }
    let drives = match state
        .applications
        .folder_service
        .list_folders_with_perms(None, user.id)
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, user = %user.username, "Login Flow v2: failed to list drives");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // Same principal shape the password path builds: an app password is
    // never DPoP-bound.
    let principal = CurrentUser {
        dpop_jkt: None,
        ..(*user).clone()
    };
    let next = advance_flow(
        &state,
        nextcloud,
        &token,
        &principal,
        "Nextcloud (session)",
        drives,
    )
    .await;
    match next {
        Ok(FlowNext::Redirect(url)) => {
            tracing::info!(
                target: "audit",
                event = "nc_login_flow.session_granted",
                user_id = %user.id,
                "🔑 Nextcloud client linked with the signed-in session"
            );
            Json(LoginFlowGrantResponse {
                redirect: Some(url),
                drives: None,
                pick_action: None,
            })
            .into_response()
        }
        Ok(FlowNext::PickDrive(drives)) => Json(LoginFlowGrantResponse {
            redirect: None,
            drives: Some(
                drives
                    .into_iter()
                    .map(|f| LoginFlowDrive {
                        id: f.id,
                        name: f.name,
                    })
                    .collect(),
            ),
            pick_action: Some(format!(
                "{}/login/v2/flow/{}/drive",
                crate::common::config::server_base_path(),
                token
            )),
        })
        .into_response(),
        Err(status) => status.into_response(),
    }
}
