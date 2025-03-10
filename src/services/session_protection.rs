use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::collections::HashMap;
use crate::models::session::Session;
use uuid;

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
