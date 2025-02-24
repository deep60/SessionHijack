use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub salt: String,
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
    ) -> Result<Option<Self>, sqlx: Error> {
        sqlx::query_as!(
            User,
            r#"
            SELECT * FROM users WHERE username = $1
            "#,
            username
        )
        .fetch_options(pool)
    }

    pub async fn update_login_attempt(
        &self,
        pool: &PgPool,
        success: bool,
    ) -> Result<(), sqlx::Error> {
        if success {
            sqlx::query!(
                r#"
                UPDATE users
                SET failed_login_attempts = 0,
                    last_login = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                "#,
                self.id
            )
            .execute(pool)
            .await?;
        } else {
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
        }
        Ok(())
    }
}
