pub struct SecurityConfig {
    pub session_timeout_minutes: u32,
    pub max_session_per_user: u32,
    pub enforce_ip_validation: bool,
    pub enforce_user_agent_validation: bool,
    pub enforce_fingerprint_validation: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            session_timeout_minutes: 30,
            max_session_per_user: 5,
            enforce_ip_validation: true,
            enforce_user_agent_validation: true,
            enforce_fingerprint_validation: false,
        }
    }
}
