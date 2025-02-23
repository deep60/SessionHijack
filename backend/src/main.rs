
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_identity::{CookieIdentityPolicy, IdentityExt, IdentityService};
use actix_session::{Session, CookieSession};
use std::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use chrono::Utc;
use std::net::IpAddr;
use std::str::FromStr;

mod session_protection;
mod csrf_protection;
use session_protection::{
    SessionData, 
    SessionStore, 
    SessionProtection,
    LoginRequest,
    LogoutRequest
};
use csrf_protection::CsrfStore;


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let session_store = Arc::new(Mutex::new(SessionStore::new()));
    let csrf_store = Arc::new(Mutex::new(CSrfStore::new()));

    println!("Starting server at http://127.0.0.1:3000");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(session_store.clone()))
            .app_data(web::Data::new(csrf_store.clone()))
            //Set up secure cookie policy
            .warp(IdentityService::new(CookieIdentityPolicy::new(&[0;32])
                    .name("auth-cookie")
                    .secure(true)
                    .http_only(true)
                    .same_site(actix_web::cookie::SameSite::Strict)
                    .max_age(Duration::from_secs(3600))
            ))
            //Session middleware
            .warp(CookieSession::signed(&[0;32])
                .secure(true)
                .http_only(true)
                .name("session")
                .max_age(3600)
            )
            ///Routes
            .service(web::resource("/login").route(web::post().to(login)))
            .service(web::resource("/logout").route(web::post().to(logout)))
            .service(web::resource("/protected").route(web::get().to(protected_resources)))
            .service(web::resource("/csrf_token").route(web::get().to(get_csrf_token)))
            .service(web::resource("/").route(web::get().to(index)))
    })
    .bind("127.0.0.1:3000")
    .run()
    .await
}
   
async fn index() -> impl Responder {
    HttpResponse::Ok().body(include_str!("../frontend/index.html"))
}

async fn login(
    req: web::Json<LoginRequest>,
    session: Session,
    session_store: web::Data<Arc<Mutex<SessionStore>>>,
    request: actix_web::HttpRequest,
) ->impl Responder {
    // Simple Hardcore authentication
    if req.username == "user" && req.password == "password" {
        let session_id = Uuid::new_v4().to_string();
        let ip = request.connection_info().peer_addr()
            .and_then(|addr| addr.split(':').next())
            .and_then(|ip| IpAddr::from_str(ip).ok())
            .unwrap_or_else(|| IpAddr::from_str("0.0.0.0").unwrap());

        let user_agent = request.headers()
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown").to_string();

        let new_session = SessionData {
            user_id: "user123".to_string(),
            username: req.username.clone(),
            ip_address: ip,
            user_agent,
            created_at: Utc::now(),
            last_Activity: Utc::now(),
            is_valid: true,
        };

        //STORE Session
        session_store.lock().unwrap().add_session(session_id.clone());
        // SET Cookie
        session.insert("session_id", session_id.clone()).unwrap();

        HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "messgae": "Logged in successfully",
            "session_id": session_id,
            "user_id": "user1234"
        }))
    } else {
        HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "error",
            "messgae": "Inavalid credentials"
        }))
    }
}

async fn logout(
    session: Session,
    req: web::Json<LogoutRequest>,
    session_store: web::Data<Arc<Mutex<SessionStore>>>,
) ->impl Responder {
    let session_id = match session.get::<String>("session_id") {
        Ok(Some(id)) => id,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({
            "status": "error",
            "messgae": "No active session"
        })),
    };

    let mut store = session_store.lock().unwrap();
    if let Some(session_data) = store.get_session(&session_id) {
        if session_data.user_id != req.user_id {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "status": "error",
                "messgae": "Session doesn't belong to this user"
            }));
        }

        store.invalidate_session(&session_id);
        session.remove("session_id");

        HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "Logged out successfully"
        }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({
            "status": "error",
            "messgae": "Session not found"
        }))
    }
}

async fn protected_resource(
    session: Session,
    request: actix_web::HttpRequest,
    session_store: web::Data<Arc<Mutex<SessionStore>>>,
) ->impl Responder {
    let session_id = match session.get::<String>("session_id") {
        Ok(Some(id)) => id,
        _ => return HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "error",
            "messgae": "Authentication required"
        })),
    };

    let ip = request.connection_info().peer_addr()
        .and_then(|addr| addr.split(':').next())
        .and_then(|ip| IpAddr::from_str(ip).ok())
        .unwrap_or_else(|| IpAddr::from_str("0.0.0.0").unwrap());

    let user_agent = request.headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown").to_string();

    let simulated_ip = request.headers()
        .get("X-Simulated-IP")
        .and_then(|h| h.to_str().ok())
        .and_then(|ip| IpAddr::from_str(ip).ok());

    let simulated_user_agent = request.headers()
        .get("X-Simulated-User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let check_ip = simulated_ip.unwrap_or(ip);
    let check_ua = simulated_user_agent.unwrap_or(user_agent);
    let mut store = session_store.lock().unwrap();

    if let Some(session_data) = store.get_session(&session_id) {
        if !session_data.is_valid {
            session.remove("session_id");
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "status": "error",
                "messgae": "Session hasn been invalidated"
            }));
        }

        if session_data.ip_address != check_ip {
            store.invalidate_session(&session_id);
            session.remove("session_id");
            return HttpResponse::Forbidden().json(serde_json::json!({
                "status": "error",
                "message": "Session hijacking detected: IP address mismatch"
            }));
        }

        if session_data.user_agent != check_ua {
            store.invalidate_session(&session_id);
            session.remove("session_id");
            return HttpResponse::Forbidden().json(serde_json::json!({
                "status": "error",
                "message": "Session hijacking detected: User agent mismatch"
            }));
        }

        store.update_last_activity(&session_id);

        HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "Access granted to protected resource",
            "user": {
                "id": session_data.user_id,
                "username": session_data.username
            }
        }))
    } else {
        session.remove("session_id");
        HttpResponse::Unauthorized().json(serde_json::json!({
            "status": "error",
            "message": "Inavalid session"
        }))
    }
}

async fn get_csrf_token(
    session: Session,
    csrf_store: web::Data<Arc<Mutex<CsrfStore,>>>
) -> impl Responder {
    let user_id = session.get::<String>("session_id").ok().flatten();

    //Generate new CSRF token
    let token = csrf_store.lock().unwrap().generate_token(user_id);
    HttpResponse::Ok().json(serde_json::json!({
        "csrf_token": token
    }))
}
