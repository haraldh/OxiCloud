use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;

use super::*;
use crate::application::ports::passkey_ports::{PasskeyUserView, StoredPasskey};
use crate::application::ports::recovery_code_ports::RecoveryCodeStatus;

/// One user; the knobs each test turns.
struct World {
    user: Mutex<PasskeyUserView>,
    passkeys: usize,
    codes: u32,
    removed: Mutex<bool>,
}

struct Users(Arc<World>);
struct Keys(Arc<World>);
struct Codes(Arc<World>);
struct Creds(Arc<World>);

#[async_trait]
impl PasskeyUserPort for Users {
    async fn find_user(&self, id: Uuid) -> Result<Option<PasskeyUserView>, DomainError> {
        let u = self.0.user.lock().unwrap().clone();
        Ok((u.id == id).then_some(u))
    }
    async fn find_user_by_name(&self, _: &str) -> Result<Option<PasskeyUserView>, DomainError> {
        unreachable!()
    }
}

#[async_trait]
impl PasskeyStorePort for Keys {
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, DomainError> {
        Ok((0..self.0.passkeys)
            .map(|i| StoredPasskey {
                id: Uuid::new_v4(),
                user_id,
                credential_id: vec![i as u8],
                passkey: serde_json::Value::Null,
                name: format!("key {i}"),
                created_at: Utc::now(),
                last_used_at: None,
            })
            .collect())
    }
    async fn find_by_credential_id(&self, _: &[u8]) -> Result<Option<StoredPasskey>, DomainError> {
        unreachable!()
    }
    async fn insert(
        &self,
        _: Uuid,
        _: &[u8],
        _: &serde_json::Value,
        _: &str,
    ) -> Result<StoredPasskey, DomainError> {
        unreachable!()
    }
    async fn record_use(&self, _: Uuid, _: &serde_json::Value) -> Result<(), DomainError> {
        unreachable!()
    }
    async fn rename(&self, _: Uuid, _: Uuid, _: &str) -> Result<bool, DomainError> {
        unreachable!()
    }
    async fn delete(&self, _: Uuid, _: Uuid) -> Result<bool, DomainError> {
        unreachable!()
    }
}

#[async_trait]
impl RecoveryCodeStorePort for Codes {
    async fn replace_for_user(&self, _: Uuid, _: &[[u8; 32]]) -> Result<(), DomainError> {
        unreachable!()
    }
    async fn status(&self, _: Uuid) -> Result<RecoveryCodeStatus, DomainError> {
        Ok(RecoveryCodeStatus {
            remaining: self.0.codes,
            generated_at: None,
        })
    }
    async fn consume(&self, _: Uuid, _: &[u8; 32]) -> Result<bool, DomainError> {
        unreachable!()
    }
}

#[async_trait]
impl PasswordCredentialPort for Creds {
    async fn remove_password(&self, _: Uuid) -> Result<bool, DomainError> {
        *self.0.removed.lock().unwrap() = true;
        Ok(true)
    }
}

fn world(passkeys: usize, codes: u32, f: impl FnOnce(&mut PasskeyUserView)) -> (Arc<World>, Uuid) {
    let id = Uuid::new_v4();
    let mut user = PasskeyUserView {
        id,
        account_name: "alice".into(),
        display_name: "Alice".into(),
        is_active: true,
        is_external: false,
        has_other_login: true,
        is_federated: false,
        has_password: true,
    };
    f(&mut user);
    (
        Arc::new(World {
            user: Mutex::new(user),
            passkeys,
            codes,
            removed: Mutex::new(false),
        }),
        id,
    )
}

async fn remove(w: &Arc<World>, id: Uuid) -> Result<(), PasswordRemovalError> {
    PasswordRemovalService::new(
        Arc::new(Users(w.clone())),
        Arc::new(Keys(w.clone())),
        Arc::new(Codes(w.clone())),
        Arc::new(Creds(w.clone())),
    )
    .remove_password(id)
    .await
}

#[tokio::test]
async fn two_passkeys_are_enough() {
    let (w, id) = world(2, 0, |_| {});
    remove(&w, id).await.unwrap();
    assert!(*w.removed.lock().unwrap());
}

#[tokio::test]
async fn one_passkey_needs_recovery_codes() {
    let (w, id) = world(1, 0, |_| {});
    assert!(matches!(
        remove(&w, id).await,
        Err(PasswordRemovalError::NeedsBackup)
    ));
    assert!(!*w.removed.lock().unwrap());

    let (w, id) = world(1, 3, |_| {});
    remove(&w, id).await.unwrap();
    assert!(*w.removed.lock().unwrap());
}

#[tokio::test]
async fn recovery_codes_alone_are_not_enough() {
    let (w, id) = world(0, 10, |_| {});
    assert!(matches!(
        remove(&w, id).await,
        Err(PasswordRemovalError::NeedsBackup)
    ));
}

#[tokio::test]
async fn federated_guest_and_passwordless_accounts_are_refused() {
    let (w, id) = world(2, 10, |u| u.is_federated = true);
    assert!(matches!(
        remove(&w, id).await,
        Err(PasswordRemovalError::Federated)
    ));
    let (w, id) = world(2, 10, |u| u.is_external = true);
    assert!(matches!(
        remove(&w, id).await,
        Err(PasswordRemovalError::NotAllowed)
    ));
    let (w, id) = world(2, 10, |u| u.has_password = false);
    assert!(matches!(
        remove(&w, id).await,
        Err(PasswordRemovalError::NoPassword)
    ));
    assert!(!*w.removed.lock().unwrap());
}
