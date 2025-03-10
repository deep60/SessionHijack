use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::{collections::HashMap, env::home_dir};
use crate::models::session::Session;

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
    fn is_session_expired(&self, session: &Session) -> bool;
    fn clear_expired_sessions(&mut self);
}

pub struct SessionStore {
    sessions: HashMap<String, Session>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn add_session(&mut self, session_id: String, data: SessionData) {
        self.sessions.insert(session_id, data);
    }

    pub fn get_session(&self, session_id: &str) -> Option<SessionData> {
        self.sessions.get(session_id).cloned()
    }

    pub fn invalidate_session(&mut self, session_id: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.is_valid = false;
        }
    }

    pub fn update_last_activity(&mut self, session_id: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_activity = Utc::now();
        }
    }

    pub fn remove_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }
}

impl SessionProtection for SessionStore {
    fn validate_session(&self, session_id: &str, ip: IpAddr, user_agent: &str) -> bool {
        if let Some(session) = self.sessions.get(session_id) {
            if !session.is_valid {
                return false;
            }

            // Check if the session is expired
            if self.is_session_expired(session) {
                return false;
            }

            //Check if IP address changed (potential hijacking)
            if session.ip_address != ip {
                return false;
            }

            // Check if user agent changed
            if session.user_agent != user_agent {
                return false;
            }

            true
        } else {
            false
        }
    }

    fn is_session_expired(&self, session: &Session) -> bool {
        Utc::now() > session.expires_at
    }

    fn clear_expired_sessions(&mut self) {
        let expired_sessions: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, data)| {
                self.is_session_expired(data)
            })
            .map(|(id, _)| id.clone())
            .collect();

        for session_id in expired_sessions {
            self.sessions.remove(&session_id);
        }
    }
}
