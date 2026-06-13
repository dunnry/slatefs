//! Core error type. Frontends map these to protocol errors (NFS status / 9P
//! errno); the CLI prints them.

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage engine: {0}")]
    SlateDb(#[from] slatedb::Error),

    #[error("object store: {0}")]
    ObjectStore(#[from] slatedb::object_store::Error),

    /// AEAD open failed, a key failed to unwrap, or key material is malformed.
    /// Fail closed: callers must never fall back to serving questionable data
    /// (plan §7).
    #[error("crypto failure (fail-closed): {0}")]
    Crypto(String),

    #[error("{kind} {name:?} not found")]
    NotFound { kind: &'static str, name: String },

    #[error("{kind} {name:?} already exists")]
    AlreadyExists { kind: &'static str, name: String },

    #[error("invalid {what}: {reason}")]
    Invalid { what: &'static str, reason: String },

    #[error("codec: {0}")]
    Codec(#[from] postcard::Error),

    #[error("config: {0}")]
    Config(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn is_fenced_slatedb_error(error: &slatedb::Error) -> bool {
    matches!(
        error.kind(),
        slatedb::ErrorKind::Closed(slatedb::CloseReason::Fenced)
    )
}

impl Error {
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    pub fn not_found(kind: &'static str, name: impl Into<String>) -> Self {
        Error::NotFound {
            kind,
            name: name.into(),
        }
    }

    pub fn already_exists(kind: &'static str, name: impl Into<String>) -> Self {
        Error::AlreadyExists {
            kind,
            name: name.into(),
        }
    }

    pub fn invalid(what: &'static str, reason: impl Into<String>) -> Self {
        Error::Invalid {
            what,
            reason: reason.into(),
        }
    }

    pub(crate) fn is_fenced(&self) -> bool {
        matches!(self, Error::SlateDb(error) if is_fenced_slatedb_error(error))
    }
}
