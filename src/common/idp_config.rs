//! Configuration for OxiCloud acting as an OpenID Provider ("IdP mode").
//!
//! Distinct from [`super::config::OidcConfig`], which configures OxiCloud as
//! a relying party of an *upstream* IdP. The env prefix is `OXICLOUD_IDP_`
//! precisely so it can never be confused with the existing
//! `OXICLOUD_OIDC_PROVIDER_NAME` (the upstream IdP's display name).
//!
//! ```text
//! OXICLOUD_IDP_CLIENTS=tuwunel,grafana
//! OXICLOUD_IDP_CLIENT_tuwunel_REDIRECT_URIS=https://chat.example.org/_matrix/client/unstable/login/sso/callback/oxicloud
//! OXICLOUD_IDP_CLIENT_tuwunel_SECRET_FILE=/run/secrets/tuwunel-oidc
//! OXICLOUD_IDP_CLIENT_tuwunel_NAME=Chat
//! OXICLOUD_IDP_CLIENT_tuwunel_SKIP_CONSENT=true
//! ```
//!
//! The provider is enabled iff `OXICLOUD_IDP_CLIENTS` names at least one
//! client. Clients are static: there is no dynamic registration, so the set
//! of relying parties that can obtain an identity assertion is exactly what
//! the operator wrote down. See `docs/plan/chat-matrix.md` § seam 1.

use std::collections::HashSet;

/// Minimum client-secret length. The secret is compared in constant time,
/// but a short one is still guessable offline from nothing.
pub const MIN_CLIENT_SECRET_LEN: usize = 32;

#[derive(Debug, Clone, Default)]
pub struct IdpConfig {
    pub clients: Vec<IdpClientConfig>,
}

impl IdpConfig {
    pub fn enabled(&self) -> bool {
        !self.clients.is_empty()
    }

    pub fn client(&self, client_id: &str) -> Option<&IdpClientConfig> {
        self.clients.iter().find(|c| c.id == client_id)
    }

    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from an arbitrary key lookup so tests never touch process env
    /// (which is shared across the concurrently running test threads).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let raw = lookup("OXICLOUD_IDP_CLIENTS").unwrap_or_default();
        let mut seen = HashSet::new();
        let mut clients = Vec::new();

        for id in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(format!(
                    "OXICLOUD_IDP_CLIENTS: client id {id:?} may only contain [A-Za-z0-9_-]"
                ));
            }
            if !seen.insert(id.to_string()) {
                return Err(format!(
                    "OXICLOUD_IDP_CLIENTS: client id {id:?} listed twice"
                ));
            }
            clients.push(IdpClientConfig::from_lookup(id, &lookup)?);
        }

        Ok(Self { clients })
    }
}

#[derive(Clone)]
pub struct IdpClientConfig {
    pub id: String,
    /// Shown on the consent page ("Sign in to <name>").
    pub name: String,
    pub secret: String,
    /// Exact-match allowlist. No prefix or wildcard matching: an open
    /// redirect here hands authorization codes to whoever controls the
    /// target.
    pub redirect_uris: Vec<String>,
    /// First-party clients (the bundled chat homeserver) skip the consent
    /// prompt. The user still has to be signed in to OxiCloud.
    pub skip_consent: bool,
}

// Hand-written so the secret never reaches a log line through `{:?}`.
impl std::fmt::Debug for IdpClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdpClientConfig")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .field("redirect_uris", &self.redirect_uris)
            .field("skip_consent", &self.skip_consent)
            .finish()
    }
}

impl IdpClientConfig {
    fn from_lookup(id: &str, lookup: &impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let key = |suffix: &str| format!("OXICLOUD_IDP_CLIENT_{id}_{suffix}");

        let secret = match (lookup(&key("SECRET")), lookup(&key("SECRET_FILE"))) {
            (Some(_), Some(_)) => {
                return Err(format!(
                    "{} and {} are both set; pick one",
                    key("SECRET"),
                    key("SECRET_FILE")
                ));
            }
            (Some(s), None) => s,
            (None, Some(path)) => std::fs::read_to_string(&path)
                .map_err(|e| format!("{}: cannot read {path}: {e}", key("SECRET_FILE")))?,
            (None, None) => {
                return Err(format!(
                    "client {id:?}: set {} or {}",
                    key("SECRET"),
                    key("SECRET_FILE")
                ));
            }
        };
        let secret = secret.trim().to_string();
        if secret.len() < MIN_CLIENT_SECRET_LEN {
            return Err(format!(
                "client {id:?}: secret must be at least {MIN_CLIENT_SECRET_LEN} characters"
            ));
        }

        let redirect_uris: Vec<String> = lookup(&key("REDIRECT_URIS"))
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if redirect_uris.is_empty() {
            return Err(format!("client {id:?}: {} is empty", key("REDIRECT_URIS")));
        }
        for uri in &redirect_uris {
            validate_redirect_uri(uri).map_err(|e| format!("client {id:?}: {uri}: {e}"))?;
        }

        let skip_consent = match lookup(&key("SKIP_CONSENT")) {
            None => false,
            Some(v) => v.trim().parse::<bool>().map_err(|_| {
                format!("{}: expected true or false, got {v:?}", key("SKIP_CONSENT"))
            })?,
        };

        Ok(Self {
            id: id.to_string(),
            name: lookup(&key("NAME"))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| id.to_string()),
            secret,
            redirect_uris,
            skip_consent,
        })
    }
}

/// Absolute `https` URL without a fragment; plain `http` only for loopback
/// hosts (local development). Codes travel in the query string, so a
/// cleartext redirect target would leak them to the network.
fn validate_redirect_uri(uri: &str) -> Result<(), &'static str> {
    let url = url::Url::parse(uri).map_err(|_| "not an absolute URL")?;
    if url.fragment().is_some() {
        return Err("must not contain a fragment");
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" => match url.host_str() {
            Some("localhost") | Some("127.0.0.1") | Some("[::1]") => Ok(()),
            _ => Err("http is only allowed for localhost"),
        },
        _ => Err("scheme must be https"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn parse(pairs: &[(&str, &str)]) -> Result<IdpConfig, String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        IdpConfig::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn disabled_when_no_clients_listed() {
        let cfg = parse(&[]).unwrap();
        assert!(!cfg.enabled());
    }

    #[test]
    fn parses_a_full_client() {
        let cfg = parse(&[
            ("OXICLOUD_IDP_CLIENTS", " tuwunel "),
            ("OXICLOUD_IDP_CLIENT_tuwunel_SECRET", SECRET),
            (
                "OXICLOUD_IDP_CLIENT_tuwunel_REDIRECT_URIS",
                "https://chat.example.org/cb, http://localhost:8008/cb",
            ),
            ("OXICLOUD_IDP_CLIENT_tuwunel_NAME", "Chat"),
            ("OXICLOUD_IDP_CLIENT_tuwunel_SKIP_CONSENT", "true"),
        ])
        .unwrap();
        let c = cfg.client("tuwunel").unwrap();
        assert_eq!(c.name, "Chat");
        assert!(c.skip_consent);
        assert_eq!(c.redirect_uris.len(), 2);
        assert!(cfg.client("other").is_none());
    }

    #[test]
    fn debug_output_redacts_the_secret() {
        let cfg = parse(&[
            ("OXICLOUD_IDP_CLIENTS", "c"),
            ("OXICLOUD_IDP_CLIENT_c_SECRET", SECRET),
            (
                "OXICLOUD_IDP_CLIENT_c_REDIRECT_URIS",
                "https://x.example/cb",
            ),
        ])
        .unwrap();
        assert!(!format!("{cfg:?}").contains(SECRET));
    }

    #[test]
    fn rejects_bad_configs() {
        let base = |extra: &[(&'static str, &'static str)]| {
            let mut v = vec![
                ("OXICLOUD_IDP_CLIENTS", "c"),
                (
                    "OXICLOUD_IDP_CLIENT_c_REDIRECT_URIS",
                    "https://x.example/cb",
                ),
            ];
            v.extend_from_slice(extra);
            v
        };
        // missing secret
        assert!(parse(&base(&[])).is_err());
        // short secret
        assert!(parse(&base(&[("OXICLOUD_IDP_CLIENT_c_SECRET", "short")])).is_err());
        // both secret forms
        assert!(
            parse(&base(&[
                ("OXICLOUD_IDP_CLIENT_c_SECRET", SECRET),
                ("OXICLOUD_IDP_CLIENT_c_SECRET_FILE", "/nonexistent"),
            ]))
            .is_err()
        );
        // bad skip_consent
        assert!(
            parse(&base(&[
                ("OXICLOUD_IDP_CLIENT_c_SECRET", SECRET),
                ("OXICLOUD_IDP_CLIENT_c_SKIP_CONSENT", "yes"),
            ]))
            .is_err()
        );
        // duplicate id / bad id
        assert!(parse(&[("OXICLOUD_IDP_CLIENTS", "c,c")]).is_err());
        assert!(parse(&[("OXICLOUD_IDP_CLIENTS", "a.b")]).is_err());
    }

    #[test]
    fn redirect_uri_rules() {
        assert!(validate_redirect_uri("https://x.example/cb").is_ok());
        assert!(validate_redirect_uri("http://localhost:1/cb").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1/cb").is_ok());
        assert!(validate_redirect_uri("http://x.example/cb").is_err());
        assert!(validate_redirect_uri("https://x.example/cb#f").is_err());
        assert!(validate_redirect_uri("/relative").is_err());
        assert!(validate_redirect_uri("javascript:alert(1)").is_err());
    }
}
