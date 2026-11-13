//! Passkey ceremonies driven end to end by webauthn-authenticator-rs's
//! software authenticator, against in-memory ports.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

use super::*;

const ORIGIN: &str = "https://oxi.example.org";

#[derive(Default)]
struct MemStore {
    rows: Mutex<Vec<StoredPasskey>>,
    uses: Mutex<u32>,
}

#[async_trait]
impl PasskeyStorePort for MemStore {
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, DomainError> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .filter(|r| r.user_id == user_id)
            .cloned()
            .collect())
    }
    async fn find_by_credential_id(&self, c: &[u8]) -> Result<Option<StoredPasskey>, DomainError> {
        let rows = self.rows.lock().unwrap();
        Ok(rows.iter().find(|r| r.credential_id == c).cloned())
    }
    async fn insert(
        &self,
        user_id: Uuid,
        credential_id: &[u8],
        passkey: &serde_json::Value,
        name: &str,
    ) -> Result<StoredPasskey, DomainError> {
        let mut rows = self.rows.lock().unwrap();
        if rows.iter().any(|r| r.credential_id == credential_id) {
            return Err(DomainError::already_exists("Passkey", "credential"));
        }
        let row = StoredPasskey {
            id: Uuid::new_v4(),
            user_id,
            credential_id: credential_id.to_vec(),
            passkey: passkey.clone(),
            name: name.to_string(),
            created_at: Utc::now(),
            last_used_at: None,
        };
        rows.push(row.clone());
        Ok(row)
    }
    async fn record_use(&self, id: Uuid, passkey: &serde_json::Value) -> Result<(), DomainError> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows.iter_mut().find(|r| r.id == id).unwrap();
        row.passkey = passkey.clone();
        row.last_used_at = Some(Utc::now());
        *self.uses.lock().unwrap() += 1;
        Ok(())
    }
    async fn rename(&self, user_id: Uuid, id: Uuid, name: &str) -> Result<bool, DomainError> {
        let mut rows = self.rows.lock().unwrap();
        Ok(
            match rows.iter_mut().find(|r| r.id == id && r.user_id == user_id) {
                Some(r) => {
                    r.name = name.to_string();
                    true
                }
                None => false,
            },
        )
    }
    async fn delete(&self, user_id: Uuid, id: Uuid) -> Result<bool, DomainError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|r| !(r.id == id && r.user_id == user_id));
        Ok(rows.len() < before)
    }
}

#[derive(Default)]
struct MemUsers(Mutex<HashMap<Uuid, PasskeyUserView>>);

impl MemUsers {
    fn add(&self, f: impl FnOnce(&mut PasskeyUserView)) -> Uuid {
        let id = Uuid::new_v4();
        let mut v = PasskeyUserView {
            id,
            account_name: format!("user-{id}"),
            display_name: "Test User".into(),
            is_active: true,
            is_external: false,
            has_other_login: true,
        };
        f(&mut v);
        self.0.lock().unwrap().insert(id, v);
        id
    }
    fn set(&self, id: Uuid, f: impl FnOnce(&mut PasskeyUserView)) {
        f(self.0.lock().unwrap().get_mut(&id).unwrap());
    }
}

#[async_trait]
impl PasskeyUserPort for MemUsers {
    async fn find_user(&self, id: Uuid) -> Result<Option<PasskeyUserView>, DomainError> {
        Ok(self.0.lock().unwrap().get(&id).cloned())
    }
}

struct Fixture {
    svc: PasskeyService,
    store: Arc<MemStore>,
    users: Arc<MemUsers>,
}

fn fixture() -> Fixture {
    let store = Arc::new(MemStore::default());
    let users = Arc::new(MemUsers::default());
    let svc = PasskeyService::new(ORIGIN, store.clone(), users.clone()).unwrap();
    Fixture { svc, store, users }
}

fn origin() -> Url {
    Url::parse(ORIGIN).unwrap()
}

/// `falsify_uv = true`: the soft token claims user verification, which
/// passkeys require.
fn authenticator() -> SoftPasskey {
    SoftPasskey::new(true)
}

async fn register(f: &Fixture, auth: &mut SoftPasskey, user: Uuid) -> PasskeyInfo {
    let (cid, ccr) = f.svc.start_registration(user).await.unwrap();
    let cred = auth.do_registration(origin(), ccr).unwrap();
    f.svc
        .finish_registration(user, cid, &cred, "Laptop")
        .await
        .unwrap()
}

/// Play the browser's part of a username-less sign-in with the soft
/// token, which only knows the allow-list flow:
/// - the server sends an empty `allowCredentials` (discoverable); a
///   browser offers its stored passkeys, so name the registered ones here;
/// - a browser returns the user handle the credential was created with;
///   the soft token does not, so set it. It is not covered by the
///   signature, which is why the service checks it against the
///   credential's owner.
fn browser_sign_in(
    f: &Fixture,
    auth: &mut SoftPasskey,
    mut rcr: RequestChallengeResponse,
    handle: Uuid,
) -> PublicKeyCredential {
    rcr.public_key.allow_credentials = f
        .store
        .rows
        .lock()
        .unwrap()
        .iter()
        .map(|r| webauthn_rs_proto::AllowCredentials {
            type_: "public-key".into(),
            id: r.credential_id.clone(),
            transports: None,
        })
        .collect();
    let mut cred = auth.do_authentication(origin(), rcr).unwrap();
    cred.response.user_handle = Some(handle.as_bytes().to_vec());
    cred
}

async fn sign_in(
    f: &Fixture,
    auth: &mut SoftPasskey,
    handle: Uuid,
) -> (Uuid, Result<Uuid, PasskeyError>) {
    let (cid, rcr) = f.svc.start_login().unwrap();
    let cred = browser_sign_in(f, auth, rcr, handle);
    (cid, f.svc.finish_login(cid, &cred).await)
}

#[tokio::test]
async fn register_then_sign_in() {
    let f = fixture();
    let user = f.users.add(|_| {});
    let mut auth = authenticator();
    let info = register(&f, &mut auth, user).await;
    assert_eq!(info.name, "Laptop");
    assert_eq!(f.svc.list(user).await.unwrap().len(), 1);

    let (_, res) = sign_in(&f, &mut auth, user).await;
    assert_eq!(res.unwrap(), user);
    // Counter / last-used written back on every sign-in.
    assert_eq!(*f.store.uses.lock().unwrap(), 1);
    assert!(f.store.rows.lock().unwrap()[0].last_used_at.is_some());
}

#[tokio::test]
async fn sign_in_ceremony_is_single_use() {
    let f = fixture();
    let user = f.users.add(|_| {});
    let mut auth = authenticator();
    register(&f, &mut auth, user).await;

    let (cid, rcr) = f.svc.start_login().unwrap();
    let cred = browser_sign_in(&f, &mut auth, rcr, user);
    assert!(f.svc.finish_login(cid, &cred).await.is_ok());
    assert!(matches!(
        f.svc.finish_login(cid, &cred).await,
        Err(PasskeyError::CeremonyExpired)
    ));
}

#[tokio::test]
async fn credential_must_belong_to_the_claimed_user() {
    let f = fixture();
    let alice = f.users.add(|_| {});
    let bob = f.users.add(|_| {});
    let mut auth = authenticator();
    register(&f, &mut auth, alice).await;

    // Alice's credential presented with Bob's user handle.
    let (_, res) = sign_in(&f, &mut auth, bob).await;
    assert!(matches!(res, Err(PasskeyError::UnknownCredential)));
}

#[tokio::test]
async fn deactivated_account_cannot_sign_in() {
    let f = fixture();
    let user = f.users.add(|_| {});
    let mut auth = authenticator();
    register(&f, &mut auth, user).await;
    f.users.set(user, |u| u.is_active = false);

    let (_, res) = sign_in(&f, &mut auth, user).await;
    assert!(matches!(res, Err(PasskeyError::AccountInactive)));
}

#[tokio::test]
async fn registration_ceremony_belongs_to_its_user() {
    let f = fixture();
    let alice = f.users.add(|_| {});
    let mallory = f.users.add(|_| {});
    let (cid, ccr) = f.svc.start_registration(alice).await.unwrap();
    let cred = authenticator().do_registration(origin(), ccr).unwrap();

    let res = f.svc.finish_registration(mallory, cid, &cred, "x").await;
    assert!(matches!(res, Err(PasskeyError::CeremonyExpired)));
    assert!(f.store.rows.lock().unwrap().is_empty());
}

#[tokio::test]
async fn externals_cannot_register() {
    let f = fixture();
    let guest = f.users.add(|u| u.is_external = true);
    assert!(matches!(
        f.svc.start_registration(guest).await,
        Err(PasskeyError::ExternalUser)
    ));
}

#[tokio::test]
async fn last_way_in_cannot_be_removed() {
    let f = fixture();
    let user = f.users.add(|u| u.has_other_login = false);
    let mut auth = authenticator();
    let first = register(&f, &mut auth, user).await;
    assert!(matches!(
        f.svc.delete(user, first.id).await,
        Err(PasskeyError::LastFactor)
    ));

    // With a second passkey, either one may go.
    let mut other = authenticator();
    register(&f, &mut other, user).await;
    f.svc.delete(user, first.id).await.unwrap();
    assert_eq!(f.svc.list(user).await.unwrap().len(), 1);
}

#[tokio::test]
async fn only_the_owner_can_rename_or_remove() {
    let f = fixture();
    let alice = f.users.add(|_| {});
    let bob = f.users.add(|_| {});
    let key = register(&f, &mut authenticator(), alice).await;

    assert!(matches!(
        f.svc.rename(bob, key.id, "mine").await,
        Err(PasskeyError::NotFound)
    ));
    assert!(matches!(
        f.svc.delete(bob, key.id).await,
        Err(PasskeyError::NotFound)
    ));
    f.svc.rename(alice, key.id, "  Phone  ").await.unwrap();
    assert_eq!(f.svc.list(alice).await.unwrap()[0].name, "Phone");
}

#[tokio::test]
async fn names_are_validated() {
    let f = fixture();
    let user = f.users.add(|_| {});
    let key = register(&f, &mut authenticator(), user).await;
    for bad in ["", "   ", &"x".repeat(NAME_MAX_CHARS + 1), "a\u{0007}b"] {
        assert!(matches!(
            f.svc.rename(user, key.id, bad).await,
            Err(PasskeyError::InvalidName)
        ));
    }
}

#[test]
fn relying_party_comes_from_the_public_url() {
    let users: Arc<dyn PasskeyUserPort> = Arc::new(MemUsers::default());
    let store: Arc<dyn PasskeyStorePort> = Arc::new(MemStore::default());
    assert!(
        PasskeyService::new(
            "https://oxi.example.org/cloud",
            store.clone(),
            users.clone()
        )
        .is_ok()
    );
    assert!(PasskeyService::new("not a url", store.clone(), users.clone()).is_err());
}

/// The JSON the SPA hands to navigator.credentials (and passkeys.hurl
/// asserts on): camelCase members, base64url binaries, a discoverable
/// sign-in with an empty allow list.
#[tokio::test]
async fn option_json_matches_what_the_browser_needs() {
    let f = fixture();
    let user = f.users.add(|_| {});
    let (_, ccr) = f.svc.start_registration(user).await.unwrap();
    let reg = serde_json::to_value(&ccr).unwrap();
    let pk = &reg["publicKey"];
    assert_eq!(pk["rp"]["id"], "oxi.example.org");
    assert!(
        pk["challenge"]
            .as_str()
            .unwrap()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    );
    assert_eq!(pk["authenticatorSelection"]["residentKey"], "preferred");
    assert_eq!(pk["authenticatorSelection"]["userVerification"], "required");
    assert!(pk["user"]["id"].is_string());

    let (_, rcr) = f.svc.start_login().unwrap();
    let login = serde_json::to_value(&rcr).unwrap();
    assert_eq!(
        login["publicKey"]["allowCredentials"],
        serde_json::json!([])
    );
    assert_eq!(login["publicKey"]["userVerification"], "required");
}

// ── step-up re-authentication (Phase 2a) ────────────────────────────

async fn confirm(f: &Fixture, auth: &mut SoftPasskey, user: Uuid) -> (Uuid, PublicKeyCredential) {
    let (cid, rcr) = f.svc.start_reauth(user).await.unwrap();
    // Allow-list flow: the challenge already names the user's passkeys.
    (cid, auth.do_authentication(origin(), rcr).unwrap())
}

#[tokio::test]
async fn own_passkey_confirms_and_updates_the_counter() {
    let f = fixture();
    let user = f.users.add(|_| {});
    let mut auth = authenticator();
    register(&f, &mut auth, user).await;
    assert!(f.svc.has_passkeys(user).await.unwrap());

    let (cid, cred) = confirm(&f, &mut auth, user).await;
    f.svc.finish_reauth(user, cid, &cred).await.unwrap();
    assert_eq!(*f.store.uses.lock().unwrap(), 1);
    // Single use.
    assert!(matches!(
        f.svc.finish_reauth(user, cid, &cred).await,
        Err(PasskeyError::CeremonyExpired)
    ));
}

#[tokio::test]
async fn confirming_needs_a_passkey() {
    let f = fixture();
    let user = f.users.add(|_| {});
    assert!(!f.svc.has_passkeys(user).await.unwrap());
    assert!(matches!(
        f.svc.start_reauth(user).await,
        Err(PasskeyError::UnknownCredential)
    ));
}

/// A stolen session of Alice must not be confirmable with Mallory's
/// passkey: neither by finishing Alice's ceremony as Mallory, nor by
/// answering Alice's ceremony with an assertion from Mallory's key.
#[tokio::test]
async fn only_the_callers_own_passkey_confirms() {
    let f = fixture();
    let alice = f.users.add(|_| {});
    let mallory = f.users.add(|_| {});
    let mut alice_key = authenticator();
    let mut mallory_key = authenticator();
    register(&f, &mut alice_key, alice).await;
    register(&f, &mut mallory_key, mallory).await;

    let (alice_cid, alice_cred) = confirm(&f, &mut alice_key, alice).await;
    assert!(matches!(
        f.svc.finish_reauth(mallory, alice_cid, &alice_cred).await,
        Err(PasskeyError::CeremonyExpired)
    ));

    let (alice_cid, _) = f.svc.start_reauth(alice).await.unwrap();
    let (_, mallory_cred) = confirm(&f, &mut mallory_key, mallory).await;
    assert!(matches!(
        f.svc.finish_reauth(alice, alice_cid, &mallory_cred).await,
        Err(PasskeyError::VerificationFailed)
    ));
}

#[tokio::test]
async fn deactivated_account_cannot_confirm() {
    let f = fixture();
    let user = f.users.add(|_| {});
    let mut auth = authenticator();
    register(&f, &mut auth, user).await;
    let (cid, cred) = confirm(&f, &mut auth, user).await;
    f.users.set(user, |u| u.is_active = false);
    assert!(matches!(
        f.svc.finish_reauth(user, cid, &cred).await,
        Err(PasskeyError::AccountInactive)
    ));
}
