use chrono::Duration;

pub struct SecurityConfig {
    pub session_timeout: Duration,
    pub max_sessions_per_user: i32,
    pub enforce_ip_validation: bool,
    pub enforce_user_agent_validation: bool,
    pub enforce_fingerprint_validation: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::hours(1),
            max_sessions_per_user: 5,
            enforce_ip_validation: true,
            enforce_user_agent_validation: true,
            enforce_fingerprint_validation: true,
        }
    }
}
