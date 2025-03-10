use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    rc::Rc,
    sync::Mutex,
};
use uuid::Uuid;

use crate::error::Error as AppError;

pub struct CsrfStore {
    tokens: Mutex<Vec<String>>,
}

impl CsrfStore {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(Vec::new()),
        }
    }

    pub fn generate_token(&self) -> String {
        let token = Uuid::new_v4().to_string();
        let mut store = self.tokens.lock().unwrap();
        store.push(token.clone());
        token
    }

    pub fn validate_token(&self, token: &str) -> bool {
        let store = self.tokens.lock().unwrap();
        store.contains(&token.to_string())
    }
}

pub struct CsrfProtection;

impl<S, B> Transform<S, ServiceRequest> for CsrfProtection
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CsrfProtectionMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CsrfProtectionMiddleware { service }))
    }
}

pub struct CsrfProtectionMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for CsrfProtectionMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if req.method() == "GET" {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res)
            });
        }

        let csrf_token = req.headers().get("X-CSRF-Token");
        if csrf_token.is_none() {
            return Box::pin(async move {
                Err(AppError::InvalidCsrfToken.into())
            });
        }

        let token = csrf_token.unwrap().to_str().unwrap_or("");
        let store = req
            .app_data::<actix_web::web::Data<Rc<CsrfStore>>>()
            .expect("CSRF store not configured");

        if !store.validate_token(token) {
            return Box::pin(async move {
                Err(AppError::InvalidCsrfToken.into())
            });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}
