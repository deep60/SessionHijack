use chrono::Duration;
use serde::Deserialize;
use std::env;

#[derive(Clone, Debug)]
pub struct SecurityConfig {
    pub session_timeout: Duration,
    pub max_sessions_per_user: usize,
    pub max_failed_attempts: usize,
    pub lockout_duration: Duration,
    pub password_min_length: usize,
    pub password_require_numbers: bool,
    pub password_require_symbols: bool,
    pub password_require_uppercase: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::hours(24),
            max_sessions_per_user: 5,
            max_failed_attempts: 5,
            lockout_duration: Duration::minutes(30),
            password_min_length: 8,
            password_require_numbers: true,
            password_require_symbols: true,
            password_require_uppercase: true,
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
