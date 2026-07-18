//! Authentication boundary types.
//!
//! Credentials are resolved by the daemon. Public requests never carry a
//! tenant, uid, or gid assertion.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use slatefs_core::config::{ConsumerIdentityConfig, load_bearer_token_file};

/// Server-derived identity attached to an authenticated request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TenantPrincipal {
    pub tenant: String,
    pub uid: u32,
    pub gid: u32,
}

/// Fixed POSIX identity configured for one tenant credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TenantIdentity {
    pub uid: u32,
    pub gid: u32,
}

impl Default for TenantIdentity {
    fn default() -> Self {
        Self {
            uid: 1000,
            gid: 1000,
        }
    }
}

#[derive(Clone)]
pub struct TenantAuthenticator {
    static_tokens: BTreeMap<String, String>,
    token_files: BTreeMap<String, PathBuf>,
    identities: BTreeMap<String, ConsumerIdentityConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("authentication required")]
    Unauthorized,
    #[error("tenant token sources are temporarily unavailable")]
    Unavailable,
}

impl TenantAuthenticator {
    #[must_use]
    pub fn new(
        static_tokens: BTreeMap<String, String>,
        token_files: BTreeMap<String, PathBuf>,
        identities: BTreeMap<String, ConsumerIdentityConfig>,
    ) -> Self {
        Self {
            static_tokens,
            token_files,
            identities,
        }
    }

    pub fn authenticate(&self, authorization: Option<&str>) -> Result<TenantPrincipal, AuthError> {
        let token = authorization
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty())
            .ok_or(AuthError::Unauthorized)?;
        let mut matched = None;
        for (tenant, expected) in &self.static_tokens {
            if constant_time_eq(token.as_bytes(), expected.as_bytes())
                && matched.replace(tenant.as_str()).is_some()
            {
                return Err(AuthError::Unavailable);
            }
        }
        for (tenant, path) in &self.token_files {
            let tokens = load_bearer_token_file(path).map_err(|_| AuthError::Unavailable)?;
            if tokens
                .iter()
                .any(|expected| constant_time_eq(token.as_bytes(), expected.as_bytes()))
                && matched.replace(tenant.as_str()).is_some()
            {
                return Err(AuthError::Unavailable);
            }
        }
        let tenant = matched.ok_or(AuthError::Unauthorized)?;
        let identity = self.identities.get(tenant).ok_or(AuthError::Unauthorized)?;
        Ok(TenantPrincipal {
            tenant: tenant.to_owned(),
            uid: identity.uid,
            gid: identity.gid,
        })
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut different = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        different |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    different == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn token_files_are_reread_and_support_rotation_overlap() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tenant.tokens");
        fs::write(&path, "new\nold\n").unwrap();
        let auth = TenantAuthenticator::new(
            BTreeMap::new(),
            BTreeMap::from([("acme".into(), path.clone())]),
            BTreeMap::from([(
                "acme".into(),
                ConsumerIdentityConfig {
                    uid: 1000,
                    gid: 1000,
                },
            )]),
        );
        assert_eq!(
            auth.authenticate(Some("Bearer old")).unwrap().tenant,
            "acme"
        );
        fs::write(path, "next\nnew\n").unwrap();
        assert!(matches!(
            auth.authenticate(Some("Bearer old")),
            Err(AuthError::Unauthorized)
        ));
        assert_eq!(auth.authenticate(Some("Bearer next")).unwrap().uid, 1000);
    }

    #[test]
    fn unrelated_global_token_is_rejected() {
        let auth = TenantAuthenticator::new(
            BTreeMap::from([("acme".into(), "tenant".into())]),
            BTreeMap::new(),
            BTreeMap::from([(
                "acme".into(),
                ConsumerIdentityConfig {
                    uid: 1000,
                    gid: 1000,
                },
            )]),
        );
        assert!(matches!(
            auth.authenticate(Some("Bearer global-admin")),
            Err(AuthError::Unauthorized)
        ));
    }
}
