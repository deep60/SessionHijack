use chrono::Duration;
use serde::Deserialize;
use std::env;

#[derive(Clone)]
pub struct SecurityConfig {
    pub session_timeout: Duration,
    pub max_sessions_per_user: usize,
    pub csrf_token_length: usize,
    pub csrf_token_expiry: Duration,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::hours(1),
            max_sessions_per_user: 5,
            csrf_token_length: 32,
            csrf_token_expiry: Duration::hours(1),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self, env::VarError> {
        Ok(Self {
            host: env::var("DB_HOST")?,
            port: env::var("DB_PORT")?.parse().unwrap_or(5432),
            username: env::var("DB_USER")?,
            password: env::var("DB_PASSWORD")?,
            database: env::var("DB_NAME")?,
        })
    }

    pub fn connection_string(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.username, self.password, self.host, self.port, self.database
        )
    }
}
