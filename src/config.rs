use chrono::Duration;
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub session_ttl: i64,
    pub max_login_attempts: u32,
    pub lockout_duration: i64,
    pub csrf_token_ttl: i64,
    pub redis_url: String,
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            session_ttl: 3600,
            max_login_attempts: 5,
            lockout_duration: 1800,
            csrf_token_ttl: 3600,
            redis_url: "redis://127.0.0.1/".to_string(),
            cookie_secure: true,
            cookie_http_only: true,
            cookie_same_site: "Strict".to_string(),
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
