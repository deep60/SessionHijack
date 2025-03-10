use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use rand::{thread_rng, Rng};
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse, http::StatusCode,
};
use uuid::Uuid;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const TOKEN_LENGTH: usize = 32;
const TOKEN_EXPIRY: Duration = Duration::from_secs(3600); // 1 hour

#[derive(Debug)]
pub enum CsrfError {
    InvalidToken,
}

impl std::fmt::Display for CsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CsrfError::InvalidToken => write!(f, "Invalid CSRF token"),
        }
    }
}

impl std::error::Error for CsrfError {}

impl actix_web::ResponseError for CsrfError {
    fn error_response(&self) -> HttpResponse {
        match self {
            CsrfError::InvalidToken => {
                HttpResponse::Forbidden().body("Invalid CSRF token")
            }
        }
    }
}

#[derive(Default)]
pub struct CsrfStore {
    tokens: HashMap<String, String>,
}

impl CsrfStore {
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }

    pub fn generate_token(&mut self, user_id: Option<String>) -> String {
        let token = Uuid::new_v4().to_string();
        if let Some(id) = user_id {
            self.tokens.insert(id, token.clone());
        }
        token
    }

    pub fn validate_token(&self, user_id: &str, token: &str) -> bool {
        self.tokens.get(user_id).map_or(false, |t| t == token)
    }

    pub fn remove_token(&mut self, user_id: &str) {
        self.tokens.remove(user_id);
    }
}

pub struct CsrfMiddleware {
    store: Arc<Mutex<CsrfStore>>,
}

impl CsrfMiddleware {
    pub fn new(store: Arc<Mutex<CsrfStore>>) -> Self {
        Self { store }
    }
}

impl<S, B> Transform<S, ServiceRequest> for CsrfMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CsrfMiddlewareService<S>;
    type InitError = ();
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Transform, Self::InitError>>>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let store = self.store.clone();
        Box::pin(async move {
            Ok(CsrfMiddlewareService {
                service,
                store,
            })
        })
    }
}

pub struct CsrfMiddlewareService<S> {
    service: S,
    store: Arc<Mutex<CsrfStore>>,
}

impl<S, B> Service<ServiceRequest> for CsrfMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Skip CSRF check for GET requests
        if req.method() == actix_web::http::Method::GET {
            return Box::pin(self.service.call(req));
        }

        // Get CSRF token from header
        let token = req
            .headers()
            .get("X-CSRF-Token")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        // Get user ID from session
        let user_id = req
            .extensions()
            .get::<String>()
            .map(|s| s.clone());

        if let (Some(token), Some(user_id)) = (token, user_id) {
            let mut store = self.store.lock().unwrap();
            if store.validate_token(&user_id, &token) {
                return Box::pin(self.service.call(req));
            }
        }

        Box::pin(async move {
            Err(CsrfError::InvalidToken.into())
        })
    }
}
