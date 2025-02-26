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
        let fingerprint = self.generate_device_fingerprint(request);

        // Check for existing sessions
        self.enforce_session_limits(user.id.clone())?;

        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            ip_address: ip,
            user_agent,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            csrf_token: self.generate_csrf_token(),
            is_valid: true,
            device_fingerprint: fingerprint,
        };

        self.store.lock().unwrap().add_session(session.clone());
        Ok(session)
    }

    fn generate_device_fingerprint(&self, request: &HttpRequest) -> String {
        // Combine multiple factors for a more reliable fingerprint
        let ip = request.connection_info().peer_addr().unwrap_or("unknown");
        let user_agent = request
            .headers()
            .get("User-Agent")
            .map(|h| h.to_str().unwrap_or(""))
            .unwrap_or("");
        let accept_lang = request
            .headers()
            .get("Accept-Language")
            .map(|h| h.to_str().unwrap_or(""))
            .unwrap_or("");

        let fingerprint = format!("{}:{}:{}", ip, user_agent, accept_lang);
        sha256::hash(fingerprint.as_bytes())
    }

    pub fn validate_session(
        &self,
        session_id: &str,
        request: &HttpRequest,
    ) -> Result<Session, Error> {
        let store = self.store.lock().unwrap();
        let session = store.get_session(session_id)?;

        // Validate session
        if !session.is_valid {
            return Err(Error::InvalidSession);
        }

        // Check expiration
        if self.is_session_expired(&session) {
            return Err(Error::SessionExpired);
        }

        // Validate IP
        let current_ip = self.extract_ip_address(request)?;
        if session.ip_address != current_ip {
            return Err(Error::IPMismatch);
        }

        // Validate User-Agent
        let current_ua = self.extract_user_agent(request)?;
        if session.user_agent != current_ua {
            return Err(Error::UserAgentMismatch);
        }

        // Validate device fingerprint
        let current_fingerprint = self.generate_device_fingerprint(request);
        if session.device_fingerprint != current_fingerprint {
            return Err(Error::DeviceFingerprintMismatch);
        }

        Ok(session)
    }
}
