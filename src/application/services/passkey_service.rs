//! Passkey (WebAuthn) registration and sign-in — `docs/plan/passkeys.md`,
//! Phase 1: a passkey is an alternative to the password, not a second
//! factor yet.
//!
//! Ceremonies are two calls each (start → browser → finish). The state in
//! between lives in memory for [`CEREMONY_TTL`], keyed by a random id the
//! browser echoes back, and is consumed on the first finish: a ceremony
//! cannot be replayed, and a restart only means starting over.
//!
//! Sign-in is username-less (discoverable credentials): the browser picks
//! the account, the credential's user handle is the OxiCloud user id, and
//! the credential id must belong to that user. The caller (the handler)
//! mints the session for the returned user id.
//!
//! Authorization is the caller's own id, checked here: every management
//! call takes `caller_id` and only ever touches that user's rows.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use moka::sync::Cache;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableAuthentication, Passkey, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};
use webauthn_rs_proto::ResidentKeyRequirement;

use crate::application::ports::passkey_ports::{
    PasskeyStorePort, PasskeyUserPort, PasskeyUserView, StoredPasskey,
};
use crate::common::errors::{DomainError, ErrorKind};

/// How long the browser has between start and finish. Covers a user
/// fumbling for a security key; the browser's own prompt times out at a
/// similar mark.
pub const CEREMONY_TTL: Duration = Duration::from_secs(300);
/// Bounds memory if start is spammed without finishing.
const MAX_INFLIGHT: u64 = 10_000;
pub const NAME_MAX_CHARS: usize = 64;

/// A passkey as the owner sees it in their profile.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PasskeyInfo {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<&StoredPasskey> for PasskeyInfo {
    fn from(p: &StoredPasskey) -> Self {
        Self {
            id: p.id,
            name: p.name.clone(),
            created_at: p.created_at,
            last_used_at: p.last_used_at,
        }
    }
}

/// Why a passkey operation was refused. `reason()` is the stable audit key.
#[derive(Debug)]
pub enum PasskeyError {
    /// Unknown, expired, replayed, or someone else's ceremony id.
    CeremonyExpired,
    /// The authenticator's response did not verify.
    VerificationFailed,
    /// Sign-in with a credential no user has.
    UnknownCredential,
    /// Sign-in or registration by a deactivated account.
    AccountInactive,
    /// Registration by an external (guest) user.
    ExternalUser,
    DuplicateCredential,
    InvalidName,
    NotFound,
    /// Removing it would leave the account with no way to sign in.
    LastFactor,
    Internal(DomainError),
}

impl PasskeyError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::CeremonyExpired => "ceremony_expired",
            Self::VerificationFailed => "verification_failed",
            Self::UnknownCredential => "unknown_credential",
            Self::AccountInactive => "account_inactive",
            Self::ExternalUser => "external_user",
            Self::DuplicateCredential => "duplicate_credential",
            Self::InvalidName => "invalid_name",
            Self::NotFound => "not_found",
            Self::LastFactor => "last_factor",
            Self::Internal(_) => "internal",
        }
    }
}

impl From<DomainError> for PasskeyError {
    fn from(e: DomainError) -> Self {
        Self::Internal(e)
    }
}

struct PendingRegistration {
    user_id: Uuid,
    state: PasskeyRegistration,
}

pub struct PasskeyService {
    webauthn: Webauthn,
    store: Arc<dyn PasskeyStorePort>,
    users: Arc<dyn PasskeyUserPort>,
    registrations: Cache<Uuid, Arc<PendingRegistration>>,
    /// `Mutex<Option<_>>` so finish can move the state out: moka may still
    /// hold a reference to a just-removed entry, so `Arc::try_unwrap` on
    /// the removed value is not reliable (same pattern as
    /// `OpaqueLoginExchange`).
    logins: Cache<Uuid, Arc<std::sync::Mutex<Option<DiscoverableAuthentication>>>>,
}

impl PasskeyService {
    /// Build the relying party from the deployment's public URL. The RP ID
    /// is its host: passkeys registered under one host do not work under
    /// another, so this must be the final public URL.
    pub fn new(
        public_url: &str,
        store: Arc<dyn PasskeyStorePort>,
        users: Arc<dyn PasskeyUserPort>,
    ) -> Result<Self, String> {
        let origin =
            Url::parse(public_url).map_err(|e| format!("public URL {public_url:?}: {e}"))?;
        let rp_id = origin
            .host_str()
            .ok_or_else(|| format!("public URL {public_url:?} has no host"))?
            .to_string();
        let webauthn = WebauthnBuilder::new(&rp_id, &origin)
            .map_err(|e| format!("passkey relying party for {rp_id:?}: {e}"))?
            .rp_name("OxiCloud")
            .build()
            .map_err(|e| format!("passkey relying party for {rp_id:?}: {e}"))?;
        Ok(Self {
            webauthn,
            store,
            users,
            registrations: Cache::builder()
                .time_to_live(CEREMONY_TTL)
                .max_capacity(MAX_INFLIGHT)
                .build(),
            logins: Cache::builder()
                .time_to_live(CEREMONY_TTL)
                .max_capacity(MAX_INFLIGHT)
                .build(),
        })
    }

    // ── registration (signed in) ─────────────────────────────────────

    pub async fn start_registration(
        &self,
        caller_id: Uuid,
    ) -> Result<(Uuid, CreationChallengeResponse), PasskeyError> {
        let user = self.user(caller_id).await?;
        if !user.is_active {
            return Err(self.reject_registration(caller_id, PasskeyError::AccountInactive));
        }
        // Externals sign in by magic link and own nothing; a passkey would
        // be a second, unaudited door for them.
        if user.is_external {
            return Err(self.reject_registration(caller_id, PasskeyError::ExternalUser));
        }
        let existing = self.store.list_for_user(caller_id).await?;
        let exclude = existing
            .iter()
            .filter_map(|p| decode(&p.passkey).map(|k| k.cred_id().clone()))
            .collect::<Vec<_>>();
        let (mut ccr, state) = self
            .webauthn
            .start_passkey_registration(
                caller_id,
                &user.account_name,
                &user.display_name,
                (!exclude.is_empty()).then_some(exclude),
            )
            .map_err(|e| {
                PasskeyError::Internal(DomainError::internal_error("Passkey", e.to_string()))
            })?;
        // Ask for a discoverable credential so sign-in needs no username.
        // webauthn-rs leaves this unset to spare hardware keys' few slots;
        // "preferred" lets a full key decline and still register.
        if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
            sel.resident_key = Some(ResidentKeyRequirement::Preferred);
        }
        let id = Uuid::new_v4();
        self.registrations.insert(
            id,
            Arc::new(PendingRegistration {
                user_id: caller_id,
                state,
            }),
        );
        Ok((id, ccr))
    }

    pub async fn finish_registration(
        &self,
        caller_id: Uuid,
        ceremony_id: Uuid,
        credential: &RegisterPublicKeyCredential,
        name: &str,
    ) -> Result<PasskeyInfo, PasskeyError> {
        let name = valid_name(name).ok_or(PasskeyError::InvalidName)?;
        // Consume first: one finish per ceremony, whatever happens next.
        let pending = self
            .registrations
            .remove(&ceremony_id)
            .filter(|p| p.user_id == caller_id)
            .ok_or_else(|| self.reject_registration(caller_id, PasskeyError::CeremonyExpired))?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &pending.state)
            .map_err(|e| {
                tracing::debug!(target: "oxicloud::passkey", error = %e, "registration did not verify");
                self.reject_registration(caller_id, PasskeyError::VerificationFailed)
            })?;
        let json = encode(&passkey)?;
        let stored = match self
            .store
            .insert(caller_id, passkey.cred_id().as_ref(), &json, &name)
            .await
        {
            Ok(s) => s,
            Err(e) if e.kind == ErrorKind::AlreadyExists => {
                return Err(self.reject_registration(caller_id, PasskeyError::DuplicateCredential));
            }
            Err(e) => return Err(e.into()),
        };
        tracing::info!(
            target: "audit",
            event = "passkey.registered",
            user_id = %caller_id,
            passkey_id = %stored.id,
            "passkey registered"
        );
        Ok((&stored).into())
    }

    // ── management (signed in) ───────────────────────────────────────

    pub async fn list(&self, caller_id: Uuid) -> Result<Vec<PasskeyInfo>, PasskeyError> {
        let rows = self.store.list_for_user(caller_id).await?;
        Ok(rows.iter().map(Into::into).collect())
    }

    pub async fn rename(&self, caller_id: Uuid, id: Uuid, name: &str) -> Result<(), PasskeyError> {
        let name = valid_name(name).ok_or(PasskeyError::InvalidName)?;
        if self.store.rename(caller_id, id, &name).await? {
            Ok(())
        } else {
            Err(PasskeyError::NotFound)
        }
    }

    /// Remove one of the caller's passkeys, unless it is their only way in.
    pub async fn delete(&self, caller_id: Uuid, id: Uuid) -> Result<(), PasskeyError> {
        let rows = self.store.list_for_user(caller_id).await?;
        if !rows.iter().any(|p| p.id == id) {
            return Err(PasskeyError::NotFound);
        }
        if rows.len() == 1 && !self.user(caller_id).await?.has_other_login {
            tracing::info!(
                target: "audit",
                event = "passkey.removal_rejected",
                reason = PasskeyError::LastFactor.reason(),
                user_id = %caller_id,
                passkey_id = %id,
                "👮🏻‍♂️ passkey removal refused: it is the account's last way to sign in"
            );
            return Err(PasskeyError::LastFactor);
        }
        if !self.store.delete(caller_id, id).await? {
            return Err(PasskeyError::NotFound);
        }
        tracing::info!(
            target: "audit",
            event = "passkey.removed",
            user_id = %caller_id,
            passkey_id = %id,
            "passkey removed"
        );
        Ok(())
    }

    // ── sign-in (public) ─────────────────────────────────────────────

    pub fn start_login(&self) -> Result<(Uuid, RequestChallengeResponse), PasskeyError> {
        let (rcr, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|e| {
                PasskeyError::Internal(DomainError::internal_error("Passkey", e.to_string()))
            })?;
        let id = Uuid::new_v4();
        self.logins
            .insert(id, Arc::new(std::sync::Mutex::new(Some(state))));
        Ok((id, rcr))
    }

    /// Verify a sign-in. On success the caller mints the session for the
    /// returned user id. Every refusal is audited here with its reason;
    /// the handler answers all of them with the same 401.
    pub async fn finish_login(
        &self,
        ceremony_id: Uuid,
        credential: &PublicKeyCredential,
    ) -> Result<Uuid, PasskeyError> {
        let state = self
            .logins
            .remove(&ceremony_id)
            .and_then(|s| s.lock().ok()?.take())
            .ok_or_else(|| self.reject_login(None, PasskeyError::CeremonyExpired))?;

        let (user_id, cred_id) = self
            .webauthn
            .identify_discoverable_authentication(credential)
            .map_err(|_| self.reject_login(None, PasskeyError::UnknownCredential))?;
        let stored = self
            .store
            .find_by_credential_id(cred_id)
            .await?
            // The user handle is the browser's claim; the credential id must
            // belong to that same user.
            .filter(|p| p.user_id == user_id)
            .ok_or_else(|| self.reject_login(Some(user_id), PasskeyError::UnknownCredential))?;
        let mut passkey = decode(&stored.passkey).ok_or_else(|| {
            PasskeyError::Internal(DomainError::internal_error(
                "Passkey",
                format!("stored passkey {} does not deserialize", stored.id),
            ))
        })?;

        let result = self
            .webauthn
            .finish_discoverable_authentication_v2(credential, state, &passkey)
            .map_err(|e| {
                tracing::debug!(target: "oxicloud::passkey", error = %e, "sign-in did not verify");
                self.reject_login(Some(user_id), PasskeyError::VerificationFailed)
            })?;

        let Some(user) = self.users.find_user(user_id).await? else {
            return Err(self.reject_login(Some(user_id), PasskeyError::UnknownCredential));
        };
        if !user.is_active {
            return Err(self.reject_login(Some(user_id), PasskeyError::AccountInactive));
        }

        // Keep the signature counter and backup state current. A failed
        // write fails the sign-in: a stale counter would weaken the clone
        // check on the next one.
        passkey.update_credential(&result);
        self.store.record_use(stored.id, &encode(&passkey)?).await?;
        tracing::debug!(
            target: "oxicloud::passkey",
            user_id = %user_id,
            passkey_id = %stored.id,
            "passkey sign-in verified"
        );
        Ok(user_id)
    }

    // ── helpers ──────────────────────────────────────────────────────

    /// The signed-in caller's own row; absence means the session outlived
    /// the account.
    async fn user(&self, id: Uuid) -> Result<PasskeyUserView, PasskeyError> {
        self.users
            .find_user(id)
            .await?
            .ok_or_else(|| PasskeyError::Internal(DomainError::not_found("User", id.to_string())))
    }

    fn reject_registration(&self, user_id: Uuid, e: PasskeyError) -> PasskeyError {
        tracing::info!(
            target: "audit",
            event = "passkey.registration_rejected",
            reason = e.reason(),
            user_id = %user_id,
            "👮🏻‍♂️ passkey registration rejected"
        );
        e
    }

    fn reject_login(&self, user_id: Option<Uuid>, e: PasskeyError) -> PasskeyError {
        tracing::info!(
            target: "audit",
            event = "passkey.login_rejected",
            reason = e.reason(),
            user_id = user_id.map(tracing::field::display),
            "👮🏻‍♂️ passkey sign-in rejected"
        );
        e
    }
}

fn valid_name(name: &str) -> Option<String> {
    let n = name.trim();
    (!n.is_empty() && n.chars().count() <= NAME_MAX_CHARS && !n.chars().any(char::is_control))
        .then(|| n.to_string())
}

fn encode(p: &Passkey) -> Result<serde_json::Value, PasskeyError> {
    serde_json::to_value(p)
        .map_err(|e| PasskeyError::Internal(DomainError::internal_error("Passkey", e.to_string())))
}

fn decode(v: &serde_json::Value) -> Option<Passkey> {
    serde_json::from_value(v.clone()).ok()
}

#[cfg(test)]
#[path = "passkey_service_test.rs"]
mod tests;
