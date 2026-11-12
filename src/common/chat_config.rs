//! Chat (Matrix) integration settings. See `docs/plan/chat-matrix.md`.
//!
//! ```text
//! OXICLOUD_ENABLE_CHAT=true
//! OXICLOUD_CHAT_HOMESERVER_URL=https://matrix.example.org
//! ```
//!
//! The homeserver URL is the public base URL clients use (the one in
//! `/.well-known/matrix/client`). The SPA navigates there to start the SSO
//! sign-in. Its API calls go to `/_matrix/*` on OxiCloud's own origin, which
//! the reverse proxy forwards to the homeserver: the SPA's CSP allows
//! `connect-src 'self'` only, and that policy is fixed at build time.

/// Off unless `OXICLOUD_ENABLE_CHAT=true`, and then it needs a homeserver.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChatConfig {
    /// `Some` iff chat is enabled. No trailing slash.
    pub homeserver_url: Option<String>,
}

impl ChatConfig {
    pub fn enabled(&self) -> bool {
        self.homeserver_url.is_some()
    }

    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from an arbitrary key lookup so tests never touch process env.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let enabled = match lookup("OXICLOUD_ENABLE_CHAT").as_deref().map(str::trim) {
            None | Some("") => false,
            Some(v) => v
                .parse::<bool>()
                .map_err(|_| format!("OXICLOUD_ENABLE_CHAT: expected true or false, got {v:?}"))?,
        };
        if !enabled {
            return Ok(Self::default());
        }

        let raw = lookup("OXICLOUD_CHAT_HOMESERVER_URL").unwrap_or_default();
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(
                "OXICLOUD_ENABLE_CHAT=true requires OXICLOUD_CHAT_HOMESERVER_URL \
                 (the homeserver's public base URL, e.g. https://matrix.example.org)"
                    .to_string(),
            );
        }
        let url = url::Url::parse(raw)
            .map_err(|e| format!("OXICLOUD_CHAT_HOMESERVER_URL {raw:?}: {e}"))?;
        if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
            return Err(format!(
                "OXICLOUD_CHAT_HOMESERVER_URL {raw:?}: must be an absolute http(s) URL"
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(format!(
                "OXICLOUD_CHAT_HOMESERVER_URL {raw:?}: must not carry a query or fragment"
            ));
        }

        Ok(Self {
            homeserver_url: Some(url.as_str().trim_end_matches('/').to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse(pairs: &[(&str, &str)]) -> Result<ChatConfig, String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        ChatConfig::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn off_by_default_even_with_a_url() {
        let cfg = parse(&[("OXICLOUD_CHAT_HOMESERVER_URL", "https://m.example.org")]).unwrap();
        assert!(!cfg.enabled());
        assert_eq!(cfg.homeserver_url, None);
    }

    #[test]
    fn enabled_requires_a_url() {
        let err = parse(&[("OXICLOUD_ENABLE_CHAT", "true")]).unwrap_err();
        assert!(err.contains("OXICLOUD_CHAT_HOMESERVER_URL"), "{err}");
    }

    #[test]
    fn trailing_slash_is_dropped() {
        let cfg = parse(&[
            ("OXICLOUD_ENABLE_CHAT", "true"),
            ("OXICLOUD_CHAT_HOMESERVER_URL", "https://m.example.org/"),
        ])
        .unwrap();
        assert_eq!(cfg.homeserver_url.as_deref(), Some("https://m.example.org"));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "matrix.example.org",
            "ftp://m.example.org",
            "https://m.example.org/?x=1",
        ] {
            let r = parse(&[
                ("OXICLOUD_ENABLE_CHAT", "true"),
                ("OXICLOUD_CHAT_HOMESERVER_URL", bad),
            ]);
            assert!(r.is_err(), "{bad} accepted");
        }
        assert!(parse(&[("OXICLOUD_ENABLE_CHAT", "yes")]).is_err());
    }
}
