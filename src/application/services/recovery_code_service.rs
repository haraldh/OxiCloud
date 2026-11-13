//! Single-use recovery codes — `docs/plan/passkeys.md`, Phase 2a.
//!
//! The way back into an account whose passkeys are all gone. A user makes
//! a set of [`CODE_COUNT`] codes (shown once), and each signs in exactly
//! once. Making a new set retires the old one.
//!
//! A code is 80 random bits written as 16 base32 characters in groups of
//! four (`ABCD-EFGH-IJKL-MNOP`). Input is normalised (case, dashes, spaces)
//! before hashing, so a code typed from paper still matches.

use std::sync::Arc;

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::application::ports::passkey_ports::PasskeyUserPort;
use crate::application::ports::recovery_code_ports::{RecoveryCodeStatus, RecoveryCodeStorePort};
use crate::common::errors::DomainError;

pub const CODE_COUNT: usize = 10;
const CODE_BYTES: usize = 10; // 80 bits → 16 base32 characters
const CODE_CHARS: usize = 16;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug)]
pub enum RecoveryError {
    /// External (guest) accounts sign in by magic link and get no codes.
    ExternalUser,
    AccountInactive,
    /// Sign-in refused: unknown user, malformed, wrong or used code. One
    /// variant so the caller cannot tell them apart; the audit log can.
    Rejected,
    Internal(DomainError),
}

impl From<DomainError> for RecoveryError {
    fn from(e: DomainError) -> Self {
        Self::Internal(e)
    }
}

pub struct RecoveryCodeService {
    store: Arc<dyn RecoveryCodeStorePort>,
    users: Arc<dyn PasskeyUserPort>,
}

impl RecoveryCodeService {
    pub fn new(store: Arc<dyn RecoveryCodeStorePort>, users: Arc<dyn PasskeyUserPort>) -> Self {
        Self { store, users }
    }

    pub async fn status(&self, caller_id: Uuid) -> Result<RecoveryCodeStatus, RecoveryError> {
        Ok(self.store.status(caller_id).await?)
    }

    /// Make a fresh set for the caller and return it in clear text, the
    /// only time it exists outside the user's hands.
    pub async fn generate(&self, caller_id: Uuid) -> Result<Vec<String>, RecoveryError> {
        let user = self
            .users
            .find_user(caller_id)
            .await?
            .ok_or_else(|| DomainError::not_found("User", caller_id.to_string()))?;
        let refuse = |e: RecoveryError, reason: &'static str| {
            tracing::info!(
                target: "audit",
                event = "recovery_codes.generation_rejected",
                reason,
                user_id = %caller_id,
                "👮🏻‍♂️ recovery codes refused"
            );
            e
        };
        if !user.is_active {
            return Err(refuse(RecoveryError::AccountInactive, "account_inactive"));
        }
        if user.is_external {
            return Err(refuse(RecoveryError::ExternalUser, "external_user"));
        }
        let codes: Vec<String> = (0..CODE_COUNT).map(|_| new_code()).collect();
        let hashes: Vec<[u8; 32]> = codes
            .iter()
            .map(|c| hash(&normalize(c).expect("generated codes are well-formed")))
            .collect();
        self.store.replace_for_user(caller_id, &hashes).await?;
        tracing::info!(
            target: "audit",
            event = "recovery_codes.generated",
            user_id = %caller_id,
            count = CODE_COUNT,
            "recovery codes generated (previous set retired)"
        );
        Ok(codes)
    }

    /// Sign in with a code: on `Ok` the caller mints the session for the
    /// returned user id. The code is used up whatever happens next.
    pub async fn redeem(&self, login_name: &str, code: &str) -> Result<Uuid, RecoveryError> {
        let reject = |reason: &'static str, user_id: Option<Uuid>| {
            tracing::info!(
                target: "audit",
                event = "recovery_code.login_rejected",
                reason,
                user_id = user_id.map(tracing::field::display),
                "👮🏻‍♂️ recovery-code sign-in refused"
            );
            RecoveryError::Rejected
        };
        let Some(normalized) = normalize(code) else {
            return Err(reject("malformed_code", None));
        };
        let Some(user) = self.users.find_user_by_name(login_name.trim()).await? else {
            return Err(reject("unknown_user", None));
        };
        if !user.is_active {
            return Err(reject("account_inactive", Some(user.id)));
        }
        if user.is_external {
            return Err(reject("external_user", Some(user.id)));
        }
        if !self.store.consume(user.id, &hash(&normalized)).await? {
            return Err(reject("invalid_code", Some(user.id)));
        }
        let remaining = self.store.status(user.id).await?.remaining;
        tracing::info!(
            target: "audit",
            event = "recovery_code.used",
            user_id = %user.id,
            remaining,
            "recovery code used to sign in"
        );
        Ok(user.id)
    }
}

fn new_code() -> String {
    let mut bytes = [0u8; CODE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let raw = base32(&bytes);
    raw.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

/// RFC 4648 base32 without padding; `bytes` is a multiple of 5 long.
fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5);
    for chunk in bytes.chunks(5) {
        let n = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        for i in (0..8).rev() {
            out.push(ALPHABET[((n >> (i * 5)) & 31) as usize] as char);
        }
    }
    out
}

/// Upper-case, drop dashes and whitespace; `None` unless the result is a
/// well-formed code.
fn normalize(input: &str) -> Option<String> {
    let s: String = input
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (s.len() == CODE_CHARS && s.bytes().all(|b| ALPHABET.contains(&b))).then_some(s)
}

fn hash(normalized: &str) -> [u8; 32] {
    Sha256::digest(normalized.as_bytes()).into()
}

#[cfg(test)]
#[path = "recovery_code_service_test.rs"]
mod tests;
