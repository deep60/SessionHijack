use actix_web::cookie::time::Duration;
use chrono::{DateTime, Duration, Utc};
use rand::{seq::IndexedRandom, thread_rng, Rng};
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct CsrfToken {
    token: String,
    created_at: DateTime<Utc>,
    user_id: Option<String>,
}

pub struct CsrfStore {
    tokens: HashMap<String, CsrfToken>,
}

impl CsrfStore {
    pub fn new() -> Self {
        CsrfStore {
            tokens: HashMap::new(),
        }
    }

    pub fn generate_token(&mut self, user_id: Option<String>) -> String {
        let token = generate_random_token(32);

        self.tokens.insert(
            token.clone(),
            CsrfToken {
                token: token.clone(),
                created_at: Utc::now(),
                user_id,
            },
        );
        token
    }

    pub fn validate_token(&self, token: &str, user_id: Option<&str>) -> bool {
        if let Some(token_data) = self.tokens.get(token) {
            let token_age = Utc::now() - token_data.created_at;
            if token_age > Duration::hours(24) {
                return false;
            }

            if let Some(uid) = user_id {
                if let Some(token_uid) = &token_data.user_id {
                    return uid == token_uid;
                }
                return false;
            }

            true
        } else {
            false
        }
    }

    pub fn remove_token(&mut self, token: &str) {
        self.tokens.remove(token);
    }

    pub fn clean_expired_tokens(&mut self) {
        let now = Utc::now();
        self.tokens
            .retain(|_, token_data| now - token_data.created_at <= Duration::hours(24));
    }
}

fn generate_random_token(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = thread_rng();

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
