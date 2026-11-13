//! Removing the account password — `docs/plan/passkeys.md`, Phase 2a
//! step 4. After this the account signs in with passkeys (and recovery
//! codes when they are gone).
//!
//! Refused unless the account keeps a way back: two passkeys (one can be
//! lost), or one passkey plus unused recovery codes. Federated (OIDC)
//! accounts are refused: their provider owns the login. An admin password
//! reset gives the password back. The step-up gate sits on the route.

use std::sync::Arc;

use uuid::Uuid;

use crate::application::ports::passkey_ports::{
    PasskeyStorePort, PasskeyUserPort, PasswordCredentialPort,
};
use crate::application::ports::recovery_code_ports::RecoveryCodeStorePort;
use crate::common::errors::DomainError;

#[derive(Debug)]
pub enum PasswordRemovalError {
    /// Guest or deactivated account.
    NotAllowed,
    /// Linked to an external OIDC identity.
    Federated,
    /// There is no password to remove.
    NoPassword,
    /// Removing it would leave too little: add a second passkey, or
    /// recovery codes, first.
    NeedsBackup,
    Internal(DomainError),
}

impl PasswordRemovalError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotAllowed => "not_allowed",
            Self::Federated => "federated",
            Self::NoPassword => "no_password",
            Self::NeedsBackup => "no_backup",
            Self::Internal(_) => "internal",
        }
    }
}

impl From<DomainError> for PasswordRemovalError {
    fn from(e: DomainError) -> Self {
        Self::Internal(e)
    }
}

pub struct PasswordRemovalService {
    users: Arc<dyn PasskeyUserPort>,
    passkeys: Arc<dyn PasskeyStorePort>,
    recovery: Arc<dyn RecoveryCodeStorePort>,
    credentials: Arc<dyn PasswordCredentialPort>,
}

impl PasswordRemovalService {
    pub fn new(
        users: Arc<dyn PasskeyUserPort>,
        passkeys: Arc<dyn PasskeyStorePort>,
        recovery: Arc<dyn RecoveryCodeStorePort>,
        credentials: Arc<dyn PasswordCredentialPort>,
    ) -> Self {
        Self {
            users,
            passkeys,
            recovery,
            credentials,
        }
    }

    pub async fn remove_password(&self, caller_id: Uuid) -> Result<(), PasswordRemovalError> {
        let result = self.check_and_remove(caller_id).await;
        if let Err(e) = &result
            && !matches!(e, PasswordRemovalError::Internal(_))
        {
            tracing::info!(
                target: "audit",
                event = "auth.password_removal_rejected",
                reason = e.reason(),
                user_id = %caller_id,
                "👮🏻‍♂️ password removal refused"
            );
        }
        result
    }

    async fn check_and_remove(&self, caller_id: Uuid) -> Result<(), PasswordRemovalError> {
        let user = self
            .users
            .find_user(caller_id)
            .await?
            .ok_or(PasswordRemovalError::NotAllowed)?;
        if !user.is_active || user.is_external {
            return Err(PasswordRemovalError::NotAllowed);
        }
        if user.is_federated {
            return Err(PasswordRemovalError::Federated);
        }
        if !user.has_password {
            return Err(PasswordRemovalError::NoPassword);
        }
        let passkeys = self.passkeys.list_for_user(caller_id).await?.len();
        let codes = self.recovery.status(caller_id).await?.remaining;
        if !(passkeys >= 2 || (passkeys >= 1 && codes >= 1)) {
            return Err(PasswordRemovalError::NeedsBackup);
        }
        if !self.credentials.remove_password(caller_id).await? {
            // Became federated (or vanished) since the check.
            return Err(PasswordRemovalError::Federated);
        }
        tracing::info!(
            target: "audit",
            event = "auth.password_removed",
            user_id = %caller_id,
            passkeys,
            recovery_codes = codes,
            "password removed; the account signs in with passkeys"
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "password_removal_service_test.rs"]
mod tests;
