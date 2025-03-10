use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use actix_session::{Session, SessionMiddleware, storage::RedisSessionStore};
use actix_identity::{IdentityService, CookieIdentityPolicy};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::Mutex;
use std::rc::Rc;

mod config;
mod error;
mod middleware;
mod services;

use crate::config::SecurityConfig;
use crate::middleware::csrf_protection::{CsrfStore, CsrfProtection};
use crate::services::session_protection::{LoginAttemptStore, SessionManager};

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(
    credentials: web::Json<LoginRequest>,
    session: Session,
    login_store: web::Data<Arc<LoginAttemptStore>>,
    session_manager: web::Data<Arc<SessionManager>>,
    csrf_store: web::Data<Rc<CsrfStore>>,
) -> impl Responder {
    // Record login attempt
    if let Err(e) = login_store.record_attempt(&credentials.username) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": e.to_string()
        }));
    }

    // TODO: Implement actual authentication logic here
    // For now, we'll just create a session
    let user_id = "test_user".to_string();
    
    // Create session
    if let Err(e) = session_manager.create_session(&session, user_id.clone()).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }));
    }

    // Generate CSRF token
    let csrf_token = csrf_store.generate_token();

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Login successful",
        "csrf_token": csrf_token
    }))
}

async fn logout(
    session: Session,
    session_manager: web::Data<Arc<SessionManager>>,
    csrf_store: web::Data<Rc<CsrfStore>>,
) -> impl Responder {
    if let Err(e) = session_manager.destroy_session(&session).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Logout successful"
    }))
}

async fn protected_resource(
    session: Session,
    session_manager: web::Data<Arc<SessionManager>>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    // Validate session
    if let Err(e) = session_manager.validate_session(ServiceRequest::from(req), &session).await {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": e.to_string()
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Protected resource accessed successfully"
    }))
}

async fn get_csrf_token(
    session: Session,
    csrf_store: web::Data<Rc<CsrfStore>>,
) -> impl Responder {
    let token = csrf_store.generate_token();
    HttpResponse::Ok().json(serde_json::json!({
        "csrf_token": token
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load configuration
    let config = SecurityConfig::default();

    // Initialize Redis session store
    let redis_store = RedisSessionStore::new(config.redis_url.clone())
        .expect("Failed to create Redis session store");

    // Initialize stores
    let login_store = Arc::new(LoginAttemptStore::new(config.clone()));
    let session_manager = Arc::new(SessionManager::new(config.clone()));
    let csrf_store = Rc::new(CsrfStore::new());

    HttpServer::new(move || {
        App::new()
            .wrap(
                SessionMiddleware::builder(redis_store.clone())
                    .cookie_secure(config.cookie_secure)
                    .cookie_http_only(config.cookie_http_only)
                    .cookie_same_site(config.cookie_same_site.parse().unwrap())
                    .build()
            )
            .wrap(CsrfProtection)
            .app_data(web::Data::new(login_store.clone()))
            .app_data(web::Data::new(session_manager.clone()))
            .app_data(web::Data::new(csrf_store.clone()))
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/protected", web::get().to(protected_resource))
            .route("/csrf-token", web::get().to(get_csrf_token))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
