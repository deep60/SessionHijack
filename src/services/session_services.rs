use std::sync::Arc;
use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use chrono::Utc;
use uuid::Uuid;
use sha2::{Sha256, Digest};
use std::net::IpAddr;
use actix_session::Session;
use crate::{
    models::user::User,
    error::Error as AppError,
    config::SecurityConfig,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionData {
    pub user_id: Uuid,
    pub ip_address: IpAddr,
    pub user_agent: String,
    pub device_fingerprint: String,
    pub csrf_token: String,
    pub created_at: chrono::DateTime<Utc>,
    pub last_activity: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

pub struct SessionService {
    config: Arc<SecurityConfig>,
}

impl SessionService {
    pub fn new(config: Arc<SecurityConfig>) -> Self {
        Self { config }
    }

    pub async fn validate_session(
        &self,
        req: ServiceRequest,
        session: &Session,
    ) -> Result<ServiceRequest, Error> {
        // Check if user is authenticated
        if let Some(user_id) = session.get::<String>("user_id").map_err(|e| AppError::Internal(e.to_string()))? {
            // Add user_id to request extensions for use in handlers
            req.extensions_mut().insert(user_id);
            Ok(req)
        } else {
            Err(AppError::Unauthorized.into())
        }
    }

    pub async fn create_session(
        &self,
        session: &Session,
        user: &User,
        request: &ServiceRequest,
    ) -> Result<(), Error> {
        let ip = self.extract_ip_address(request)?;
        let user_agent = self.extract_user_agent(request)?;
        let device_fingerprint = self.generate_device_fingerprint(request);
        let csrf_token = self.generate_csrf_token();

        let session_data = SessionData {
            user_id: user.id,
            ip_address: ip,
            user_agent,
            device_fingerprint,
            csrf_token,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(self.config.session_ttl),
        };

        // Store session data
        session.insert("user_id", user.id.to_string())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        session.insert("session_data", session_data)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(())
    }

    pub async fn destroy_session(&self, session: &Session) -> Result<(), Error> {
        session.purge()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn generate_device_fingerprint(&self, request: &ServiceRequest) -> String {
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

    fn extract_ip_address(&self, request: &ServiceRequest) -> Result<IpAddr, Error> {
        request
            .connection_info()
            .realip_remote_addr()
            .and_then(|ip| ip.parse().ok())
            .ok_or(AppError::InvalidIPAddress.into())
    }

    fn extract_user_agent(&self, request: &ServiceRequest) -> Result<String, Error> {
        request
            .headers()
            .get("User-Agent")
            .and_then(|ua| ua.to_str().ok())
            .map(|s| s.to_string())
            .ok_or(AppError::InvalidUserAgent.into())
    }

    fn generate_csrf_token(&self) -> String {
        Uuid::new_v4().to_string()
    }
}
