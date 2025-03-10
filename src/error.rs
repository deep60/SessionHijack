use actix_web::{HttpResponse, ResponseError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Account is locked")]
    AccountLocked,

    #[error("Invalid session")]
    InvalidSession,

    #[error("Session expired")]
    SessionExpired,

    #[error("IP address mismatch")]
    IPMismatch,

    #[error("User agent mismatch")]
    UserAgentMismatch,

    #[error("Device fingerprint mismatch")]
    DeviceFingerprintMismatch,

    #[error("Invalid IP address")]
    InvalidIPAddress,

    #[error("Invalid user agent")]
    InvalidUserAgent,
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        match self {
            Error::AccountLocked => HttpResponse::Forbidden().json(self.to_string()),
            Error::InvalidSession | Error::SessionExpired => {
                HttpResponse::Unauthorized().json(self.to_string())
            }
            Error::IPMismatch | Error::UserAgentMismatch | Error::DeviceFingerprintMismatch => {
                HttpResponse::Forbidden().json(self.to_string())
            }
            _ => HttpResponse::InternalServerError().json(self.to_string()),
        }
    }
}
