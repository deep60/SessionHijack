use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::collections::HashMap;
use crate::models::session::Session;
use uuid;
use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_session::Session;
use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use crate::error::Error as AppError;
use crate::config::SecurityConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub user_id: String,
    pub username: String,
    pub ip_address: IpAddr,
    pub user_agent: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub is_valid: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutRequest {
    pub user_id: String,
}

pub trait SessionProtection {
    fn validate_session(&self, session_id: &str, ip: IpAddr, user_agent: &str) -> bool;
    fn is_session_expired(&self, session: &SessionData) -> bool;
    fn clear_expired_sessions(&mut self);
}

#[derive(Default)]
pub struct SessionStore {
    sessions: HashMap<String, SessionData>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn add_session(&mut self, session_id: String, user_id: String, ip: IpAddr, user_agent: String) {
        let session_data = SessionData {
            user_id: user_id.clone(),
            username: "user".to_string(), // This should come from the user service
            ip_address: ip,
            user_agent,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            is_valid: true,
        };
        self.sessions.insert(session_id, session_data);
    }

    pub fn get_session(&self, session_id: &str) -> Option<&SessionData> {
        self.sessions.get(session_id)
    }

    pub fn remove_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn invalidate_session(&mut self, session_id: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.is_valid = false;
        }
    }

    pub fn clear_expired_sessions(&mut self) {
        let now = Utc::now();
        self.sessions.retain(|_, session| {
            let is_valid = session.is_valid && (now - session.last_activity).num_seconds() < 3600;
            if !is_valid {
                session.is_valid = false;
            }
            is_valid
        });
    }
}

impl SessionProtection for SessionStore {
    fn validate_session(&self, session_id: &str, ip: IpAddr, user_agent: &str) -> bool {
        if let Some(session) = self.sessions.get(session_id) {
            if !session.is_valid {
                return false;
            }

            if self.is_session_expired(session) {
                return false;
            }

            if session.ip_address != ip {
                return false;
            }

            if session.user_agent != user_agent {
                return false;
            }

            true
        } else {
            false
        }
    }

    fn is_session_expired(&self, session: &SessionData) -> bool {
        Utc::now() > session.created_at + chrono::Duration::hours(1)
    }

    fn clear_expired_sessions(&mut self) {
        let now = Utc::now();
        self.sessions.retain(|_, session| {
            let is_valid = session.is_valid && (now - session.last_activity).num_seconds() < 3600;
            if !is_valid {
                session.is_valid = false;
            }
            is_valid
        });
    }
}

pub struct LoginAttempt {
    count: u32,
    last_attempt: SystemTime,
}

pub struct LoginAttemptStore {
    attempts: Mutex<HashMap<String, LoginAttempt>>,
    config: SecurityConfig,
}

impl LoginAttemptStore {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            config,
        }
    }

    pub fn record_attempt(&self, username: &str) -> Result<(), AppError> {
        let mut attempts = self.attempts.lock().unwrap();
        let now = SystemTime::now();
        
        let attempt = attempts.entry(username.to_string()).or_insert(LoginAttempt {
            count: 0,
            last_attempt: now,
        });

        if attempt.count >= self.config.max_login_attempts {
            let lockout_duration = Duration::from_secs(self.config.lockout_duration as u64);
            if now.duration_since(attempt.last_attempt).unwrap() < lockout_duration {
                return Err(AppError::AccountLocked);
            }
            // Reset counter if lockout period has passed
            attempt.count = 0;
        }

        attempt.count += 1;
        attempt.last_attempt = now;
        Ok(())
    }

    pub fn reset_attempts(&self, username: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(username);
    }
}

pub struct SessionProtection;

impl SessionProtection {
    pub fn new() -> Self {
        Self
    }

    pub async fn validate_session(
        &self,
        req: ServiceRequest,
        session: &Session,
    ) -> Result<ServiceRequest, Error> {
        // Check if user is authenticated
        if let Some(user_id) = session.get::<String>("user_id").await? {
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
        user_id: String,
    ) -> Result<(), Error> {
        session.insert("user_id", user_id).await?;
        Ok(())
    }

    pub async fn destroy_session(&self, session: &Session) -> Result<(), Error> {
        session.purge().await?;
        Ok(())
    }
}
