use std::sync::Arc;
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::{ready, Ready};
use crate::services::session_services::SessionService;

pub struct SessionMiddleware {
    session_service: Arc<SessionService>,
}

impl SessionMiddleware {
    pub fn new(session_service: Arc<SessionService>) -> Self {
        Self { session_service }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SessionMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SessionMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SessionMiddlewareService {
            service,
            session_service: self.session_service.clone(),
        }))
    }
}

pub struct SessionMiddlewareService<S> {
    service: S,
    session_service: Arc<SessionService>,
}
