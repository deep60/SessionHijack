use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

pub struct AuthService {
    pool: PgPool,
    config: SecurityConfig,
}

impl AuthService {
    pub fn new(pool: PgPool, config: SecurityConfig) -> Self {
        Self { pool, config }
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<User>, Error> {
        let user = match User::find_by_username(&self.pool, username).await? {
            Some(user) => user,
            None => return Ok(None),
        };

        if user.is_locked {
            return Err(Error::AccountLocked);
        }

        let password_hash =
            PasswordHash::new(&user.password_hash).map_err(|e| Error::Internal(e.to_string()))?;

        let is_valid = Argon2::default()
            .verify_password(password.as_bytes(), &password_hash)
            .is_ok();

        user.update_login_attempts(&self.pool, is_valid).await?;

        if is_valid {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn hash_password(&self, password: &str) -> Result<(String, String), Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| Error::Internal(e.to_string()))?
            .to_string();

        Ok((password_hash, salt.to_string()))
    }
}
