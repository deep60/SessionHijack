use std::sync::{Arc, Mutex};
use actix_web::HttpRequest;
use chrono::Utc;
use uuid::Uuid;
use sha2::{Sha256, Digest};
use std::net::IpAddr;
use crate::{
    models::{user::User, session::Session},
    error::Error,
    config::SecurityConfig,
    services::session_protection::{SessionStore, SessionProtection},
};

pub struct SessionService {
    store: Arc<Mutex<SessionStore>>,
    config: SecurityConfig,
}

impl SessionService {
    pub fn new(store: Arc<Mutex<SessionStore>>, config: SecurityConfig) -> Self {
        Self { store, config }
    }

    pub async fn create_session(
        &self,
        user: &User,
        request: &HttpRequest,
    ) -> Result<Session, Error> {
        let ip = self.extract_ip_address(request)?;
        let user_agent = self.extract_user_agent(request)?;
        let device_fingerprint = self.generate_device_fingerprint(request);

        self.enforce_session_limits(user.id).await?;

        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            token: Uuid::new_v4().to_string(),
            ip_address: ip,
            user_agent,
            device_fingerprint,
            csrf_token: self.generate_csrf_token(),
            created_at: Utc::now(),
            last_activity: Utc::now(),
            expires_at: Utc::now() + self.config.session_timeout,
            is_valid: true,
        };

        Ok(session)
    }

    fn generate_device_fingerprint(&self, request: &HttpRequest) -> String {
        let mut fingerprint = String::new();
        
        if let Some(ip) = request.connection_info().realip_remote_addr() {
            fingerprint.push_str(ip);
        }
        
        if let Some(ua) = request.headers().get("User-Agent") {
            if let Ok(ua_str) = ua.to_str() {
                fingerprint.push_str(ua_str);
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(fingerprint.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn extract_ip_address(&self, request: &HttpRequest) -> Result<IpAddr, Error> {
        request
            .connection_info()
            .realip_remote_addr()
            .and_then(|ip| ip.parse().ok())
            .ok_or(Error::InvalidIPAddress)
    }

    fn extract_user_agent(&self, request: &HttpRequest) -> Result<String, Error> {
        request
            .headers()
            .get("User-Agent")
            .and_then(|ua| ua.to_str().ok())
            .map(|s| s.to_string())
            .ok_or(Error::InvalidUserAgent)
    }

    fn generate_csrf_token(&self) -> String {
        Uuid::new_v4().to_string()
    }

    async fn enforce_session_limits(&self, _user_id: Uuid) -> Result<(), Error> {
        // Implementation for session limits
        Ok(())
    }
}

impl SessionProtection for SessionService {
    fn validate_session(&self, session_id: &str, ip: IpAddr, user_agent: &str) -> bool {
        if let Ok(store) = self.store.lock() {
            if let Some(session) = store.get_session(session_id) {
                if !session.is_valid {
                    return false;
                }

                if self.is_session_expired(&session) {
                    return false;
                }

                if session.ip_address.to_string() != ip.to_string() {
                    return false;
                }

                if session.user_agent != user_agent {
                    return false;
                }

                true
            } else {
                false
            }
        } else {
            false
        }
    }

    fn is_session_expired(&self, session: &Session) -> bool {
        Utc::now() > session.expires_at
    }

    fn clear_expired_sessions(&mut self) {
        if let Ok(mut store) = self.store.lock() {
            store.clear_expired_sessions();
        }
    }
}
