//! Stable error envelope and HTTP mapping contract.

use axum::Json;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use slatefs_core::vfs::FsError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AuthenticationRequired,
    PermissionDenied,
    NotFound,
    Conflict,
    InvalidPath,
    InvalidRequest,
    MalformedRange,
    RangeNotSatisfiable,
    ReadOnlyView,
    PreconditionFailed,
    QuotaExceeded,
    RateLimited,
    PrimaryUnavailable,
    Internal,
}

impl ErrorCode {
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::AuthenticationRequired => 401,
            Self::MalformedRange => 400,
            Self::PermissionDenied => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::PreconditionFailed => 412,
            Self::RangeNotSatisfiable => 416,
            Self::RateLimited => 429,
            Self::InvalidPath | Self::InvalidRequest | Self::ReadOnlyView => 422,
            Self::QuotaExceeded => 507,
            Self::PrimaryUnavailable => 503,
            Self::Internal => 500,
        }
    }
}

#[derive(Debug)]
pub struct HttpError {
    pub status: StatusCode,
    pub envelope: ErrorEnvelope,
    pub retry_after: Option<u64>,
}

impl HttpError {
    #[must_use]
    pub fn new(code: ErrorCode, request_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::from_u16(code.clone().status()).expect("valid error status"),
            envelope: ErrorEnvelope {
                error: ApiError {
                    code,
                    message: message.into(),
                    request_id: request_id.into(),
                    details: Value::Object(Default::default()),
                },
            },
            retry_after: None,
        }
    }

    #[must_use]
    pub fn from_fs(error: FsError, request_id: &str, primary_dead: bool) -> Self {
        let code = match error {
            FsError::NotPermitted | FsError::AccessDenied | FsError::ReadOnly => {
                ErrorCode::PermissionDenied
            }
            FsError::NotFound | FsError::NoData => ErrorCode::NotFound,
            FsError::Exists | FsError::CrossDevice | FsError::NotEmpty | FsError::TooManyLinks => {
                ErrorCode::Conflict
            }
            FsError::BadHandle | FsError::Stale => ErrorCode::PreconditionFailed,
            FsError::QuotaExceeded | FsError::NoSpace => ErrorCode::QuotaExceeded,
            FsError::WouldBlock => ErrorCode::RateLimited,
            FsError::Invalid
            | FsError::NotDir
            | FsError::IsDir
            | FsError::NameTooLong
            | FsError::FileTooBig
            | FsError::NotSupported => ErrorCode::InvalidRequest,
            FsError::Io if primary_dead => ErrorCode::PrimaryUnavailable,
            FsError::Io => ErrorCode::Internal,
        };
        let mut result = Self::new(code, request_id, "filesystem operation failed");
        if matches!(error, FsError::WouldBlock) {
            result.retry_after = Some(1);
        }
        result
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let request_id = self.envelope.error.request_id.clone();
        let mut response = (self.status, Json(self.envelope)).into_response();
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-request-id"), value);
        }
        if let Some(seconds) = self.retry_after {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    pub request_id: String,
    #[serde(default)]
    pub details: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub error: ApiError,
}
