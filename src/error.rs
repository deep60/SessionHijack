use actix_web::{HttpResponse, ResponseError};
use derive_more::Display;
use serde::Serialize;

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Internal Server Error")]
    InternalServerError,

    #[display(fmt = "Bad Request: {}", _0)]
    BadRequest(String),

    #[display(fmt = "Unauthorized")]
    Unauthorized,

    #[display(fmt = "Invalid IP Address")]
    InvalidIPAddress,

    #[display(fmt = "Invalid User Agent")]
    InvalidUserAgent,

    #[display(fmt = "Session Expired")]
    SessionExpired,

    #[display(fmt = "Invalid Session")]
    InvalidSession,

    #[display(fmt = "Database Error: {}", _0)]
    DatabaseError(String),

    #[display(fmt = "Not Found: {}", _0)]
    NotFound(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        match self {
            Error::InternalServerError => {
                HttpResponse::InternalServerError().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::BadRequest(ref message) => {
                HttpResponse::BadRequest().json(ErrorResponse {
                    message: message.clone(),
                })
            }
            Error::Unauthorized => {
                HttpResponse::Unauthorized().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::InvalidIPAddress | Error::InvalidUserAgent => {
                HttpResponse::BadRequest().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::SessionExpired | Error::InvalidSession => {
                HttpResponse::Unauthorized().json(ErrorResponse {
                    message: self.to_string(),
                })
            }
            Error::DatabaseError(ref error) => {
                HttpResponse::InternalServerError().json(ErrorResponse {
                    message: error.clone(),
                })
            }
            Error::NotFound(ref message) => {
                HttpResponse::NotFound().json(ErrorResponse {
                    message: message.clone(),
                })
            }
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        Error::DatabaseError(error.to_string())
    }
}
