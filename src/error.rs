use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
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
    #[error("Too many sessions")]
    TooManySessions,
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}
