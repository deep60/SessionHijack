use actix_web::{web, HttpRequest, HttpResponse, Responder, dev::{ServiceRequest, Payload}};
use serde_json::json;
use crate::{
    services::{
        auth_service::AuthService,
        session_services::SessionService,
        session_protection::LoginRequest,
    },
    error::Error,
};
use actix_session::Session;
use crate::{
    models::user::User,
    error::Error as AppError,
};

#[derive(serde::Deserialize)]
pub struct AuthLoginRequest {
    username: String,
    password: String,
}

pub async fn login(
    credentials: web::Json<AuthLoginRequest>,
    session: Session,
    session_service: web::Data<SessionService>,
    req: HttpRequest,
    payload: Payload,
) -> impl Responder {
    // TODO: Implement actual authentication logic here
    // For now, we'll just create a session with a test user
    let user = User {
        id: uuid::Uuid::new_v4(),
        username: credentials.username.clone(),
        password_hash: "dummy_hash".to_string(), // TODO: Implement proper password hashing
        failed_login_attempts: 0,
        last_login: None,
        is_locked: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    // Create a ServiceRequest from HttpRequest and Payload
    let service_req = ServiceRequest::from_parts(req, payload);
    if let Err(e) = session_service.create_session(&session, &user, &service_req).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Login successful"
    }))
}

pub async fn logout(
    session: Session,
    session_service: web::Data<SessionService>,
) -> impl Responder {
    if let Err(e) = session_service.destroy_session(&session).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Logout successful"
    }))
}
