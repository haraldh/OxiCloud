use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;

use super::*;
use crate::application::ports::passkey_ports::PasskeyUserView;

/// Per user: (code hash, used).
type CodeSet = Vec<([u8; 32], bool)>;

#[derive(Default)]
struct MemStore(Mutex<HashMap<Uuid, CodeSet>>);

#[async_trait]
impl RecoveryCodeStorePort for MemStore {
    async fn replace_for_user(
        &self,
        user_id: Uuid,
        hashes: &[[u8; 32]],
    ) -> Result<(), DomainError> {
        self.0
            .lock()
            .unwrap()
            .insert(user_id, hashes.iter().map(|h| (*h, false)).collect());
        Ok(())
    }
    async fn status(&self, user_id: Uuid) -> Result<RecoveryCodeStatus, DomainError> {
        let m = self.0.lock().unwrap();
        let set = m.get(&user_id);
        Ok(RecoveryCodeStatus {
            remaining: set.map_or(0, |s| s.iter().filter(|(_, used)| !used).count() as u32),
            generated_at: set.map(|_| Utc::now()),
        })
    }
    async fn consume(&self, user_id: Uuid, hash: &[u8; 32]) -> Result<bool, DomainError> {
        let mut m = self.0.lock().unwrap();
        let Some(set) = m.get_mut(&user_id) else {
            return Ok(false);
        };
        match set.iter_mut().find(|(h, used)| h == hash && !used) {
            Some(entry) => {
                entry.1 = true;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[derive(Default)]
struct MemUsers(Mutex<HashMap<Uuid, PasskeyUserView>>);

impl MemUsers {
    fn add(&self, name: &str, f: impl FnOnce(&mut PasskeyUserView)) -> Uuid {
        let id = Uuid::new_v4();
        let mut v = PasskeyUserView {
            id,
            account_name: name.into(),
            display_name: name.into(),
            is_active: true,
            is_external: false,
            has_other_login: false,
            is_federated: false,
            has_password: false,
        };
        f(&mut v);
        self.0.lock().unwrap().insert(id, v);
        id
    }
}

#[async_trait]
impl PasskeyUserPort for MemUsers {
    async fn find_user(&self, id: Uuid) -> Result<Option<PasskeyUserView>, DomainError> {
        Ok(self.0.lock().unwrap().get(&id).cloned())
    }
    async fn find_user_by_name(&self, name: &str) -> Result<Option<PasskeyUserView>, DomainError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .values()
            .find(|u| u.account_name == name)
            .cloned())
    }
}

fn service() -> (RecoveryCodeService, Arc<MemUsers>) {
    let users = Arc::new(MemUsers::default());
    (
        RecoveryCodeService::new(Arc::new(MemStore::default()), users.clone()),
        users,
    )
}

#[test]
fn codes_are_ten_distinct_groups_of_base32() {
    let codes: Vec<String> = (0..CODE_COUNT).map(|_| new_code()).collect();
    for c in &codes {
        assert_eq!(c.len(), 19, "{c}");
        assert_eq!(c.matches('-').count(), 3, "{c}");
        assert!(normalize(c).is_some(), "{c}");
    }
    let unique: std::collections::HashSet<_> = codes.iter().collect();
    assert_eq!(unique.len(), CODE_COUNT);
}

#[test]
fn base32_matches_rfc4648() {
    // RFC 4648 §10 test vector, unpadded, at a 5-byte boundary.
    assert_eq!(base32(b"fooba"), "MZXW6YTB");
}

#[test]
fn typed_codes_are_normalised_and_bad_ones_refused() {
    assert_eq!(
        normalize(" abcd-efgh ijkl-mnop ").as_deref(),
        Some("ABCDEFGHIJKLMNOP")
    );
    assert!(normalize("ABCD-EFGH-IJKL-MNO").is_none(), "too short");
    assert!(
        normalize("ABCD-EFGH-IJKL-MNO1").is_none(),
        "1 is not base32"
    );
}

#[tokio::test]
async fn a_code_signs_in_once() {
    let (svc, users) = service();
    let alice = users.add("alice", |_| {});
    let codes = svc.generate(alice).await.unwrap();
    assert_eq!(svc.status(alice).await.unwrap().remaining, 10);

    let typed = codes[3].to_lowercase().replace('-', " ");
    assert_eq!(svc.redeem("alice", &typed).await.unwrap(), alice);
    assert_eq!(svc.status(alice).await.unwrap().remaining, 9);
    assert!(matches!(
        svc.redeem("alice", &codes[3]).await,
        Err(RecoveryError::Rejected)
    ));
}

#[tokio::test]
async fn a_new_set_retires_the_old_one() {
    let (svc, users) = service();
    let alice = users.add("alice", |_| {});
    let old = svc.generate(alice).await.unwrap();
    let new = svc.generate(alice).await.unwrap();
    assert!(matches!(
        svc.redeem("alice", &old[0]).await,
        Err(RecoveryError::Rejected)
    ));
    assert!(svc.redeem("alice", &new[0]).await.is_ok());
}

#[tokio::test]
async fn a_code_only_opens_its_own_account() {
    let (svc, users) = service();
    let alice = users.add("alice", |_| {});
    users.add("bob", |_| {});
    let codes = svc.generate(alice).await.unwrap();
    assert!(matches!(
        svc.redeem("bob", &codes[0]).await,
        Err(RecoveryError::Rejected)
    ));
    assert!(matches!(
        svc.redeem("nobody", &codes[0]).await,
        Err(RecoveryError::Rejected)
    ));
    // Still unused for Alice.
    assert!(svc.redeem("alice", &codes[0]).await.is_ok());
}

#[tokio::test]
async fn deactivated_and_external_accounts_are_refused() {
    let (svc, users) = service();
    let alice = users.add("alice", |_| {});
    let codes = svc.generate(alice).await.unwrap();
    users.0.lock().unwrap().get_mut(&alice).unwrap().is_active = false;
    assert!(matches!(
        svc.redeem("alice", &codes[0]).await,
        Err(RecoveryError::Rejected)
    ));
    assert!(matches!(
        svc.generate(alice).await,
        Err(RecoveryError::AccountInactive)
    ));

    let guest = users.add("guest", |u| u.is_external = true);
    assert!(matches!(
        svc.generate(guest).await,
        Err(RecoveryError::ExternalUser)
    ));
}
