use actix_web::{HttpResponse, ResponseError};
use std::fmt;
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid IP address")]
    InvalidIPAddress,
    #[error("Invalid user agent")]
    InvalidUserAgent,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Session expired")]
    SessionExpired,
    #[error("Session hijacking detected")]
    SessionHijacking,
    #[error("Invalid CSRF token")]
    InvalidCsrfToken,
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InternalServerError => write!(f, "Internal Server Error"),
            Error::Internal(msg) => write!(f, "Internal Error: {}", msg),
            Error::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            Error::Unauthorized => write!(f, "Unauthorized"),
            Error::InvalidIPAddress => write!(f, "Invalid IP Address"),
            Error::InvalidUserAgent => write!(f, "Invalid User Agent"),
            Error::SessionExpired => write!(f, "Session Expired"),
            Error::InvalidSession => write!(f, "Invalid Session"),
            Error::DatabaseError(msg) => write!(f, "Database Error: {}", msg),
            Error::NotFound(msg) => write!(f, "Not Found: {}", msg),
            Error::AccountLocked => write!(f, "Account is locked"),
        }
    }
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

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        Error::DatabaseError(error)
    }
}
