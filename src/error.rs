use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Internal server error")]
    InternalServerError,
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Invalid IP address")]
    InvalidIPAddress,
    #[error("Invalid user agent")]
    InvalidUserAgent,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Session expired")]
    SessionExpired,
    #[error("Invalid session")]
    InvalidSession,
    #[error("Session hijacking detected")]
    SessionHijacking,
    #[error("Invalid CSRF token")]
    InvalidCsrfToken,
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Account is locked")]
    AccountLocked,
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        match self {
            Error::InternalServerError | Error::Internal(_) => {
                HttpResponse::InternalServerError().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::BadRequest(ref message) => {
                HttpResponse::BadRequest().json(ErrorResponse {
                    message: message.clone(),
                })
            }
            Error::Unauthorized | Error::SessionExpired | Error::InvalidSession => {
                HttpResponse::Unauthorized().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::InvalidIPAddress | Error::InvalidUserAgent => {
                HttpResponse::BadRequest().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::DatabaseError(ref error) => {
                HttpResponse::InternalServerError().json(ErrorResponse {
                    message: error.to_string(),
                })
            }
            Error::NotFound(ref message) => {
                HttpResponse::NotFound().json(ErrorResponse {
                    message: message.clone(),
                })
            }
            Error::AccountLocked => {
                HttpResponse::Forbidden().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::SessionNotFound => {
                HttpResponse::NotFound().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::SessionHijacking => {
                HttpResponse::Forbidden().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::InvalidCsrfToken => {
                HttpResponse::BadRequest().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::RedisError(ref error) => {
                HttpResponse::InternalServerError().json(ErrorResponse {
                    message: error.to_string(),
                })
            }
        }
    }
}
