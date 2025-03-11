use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub failed_login_attempts: i32,
    pub last_login: Option<DateTime<Utc>>,
    pub is_locked: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub async fn find_by_username(
        pool: &PgPool,
        username: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT * FROM users WHERE username = $1
            "#,
            username
        )
        .fetch_optional(pool)
        .await
    }

    pub async fn reset_failed_attempts(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE users
            SET failed_login_attempts = 0,
                last_login = NOW(),
                is_locked = false,
                updated_at = NOW()
            WHERE id = $1
            "#,
            self.id
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn increment_failed_attempts(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE users
            SET failed_login_attempts = failed_login_attempts + 1,
                is_locked = CASE WHEN failed_login_attempts >= 5 THEN true ELSE false END,
                updated_at = NOW()
            WHERE id = $1
            "#,
            self.id
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn update_login_attempts(&self, pool: &PgPool, is_valid: bool) -> Result<(), sqlx::Error> {
        if is_valid {
            self.reset_failed_attempts(pool).await
        } else {
            self.increment_failed_attempts(pool).await
        }
    }
}
