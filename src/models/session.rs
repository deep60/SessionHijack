use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub ip_address: IpAddr,
    pub user_agent: String,
    pub device_fingerprint: String,
    pub csrf_token: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_valid: bool,
}

impl Session {
    pub async fn create(
        pool: &PgPool,
        user_id: Uuid,
        ip_address: IpAddr,
        user_agent: &str,
        device_fingerprint: &str,
        csrf_token: &str,
        expiry: DateTime<Utc>,
    ) -> Result<Self, sqlx::Error> {
        let session = Session {
            id: Uuid::new_v4(),
            user_id,
            token: Uuid::new_v4().to_string(),
            ip_address,
            user_agent: user_agent.to_string(),
            device_fingerprint: device_fingerprint.to_string(),
            csrf_token: csrf_token.to_string(),
            created_at: Utc::now(),
            last_activity: Utc::now(),
            expires_at: expiry,
            is_valid: true,
        };

        sqlx::query!(
            r#"
            INSERT INTO sessions
            (id, user_id, token, ip_address, user_agent, device_fingerprint, csrf_token, created_at, last_activity, expires_at, is_valid)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            session.id,
            session.user_id,
            session.token,
            session.ip_address.to_string(),
            session.user_agent,
            session.device_fingerprint,
            session.csrf_token,
            session.created_at,
            session.last_activity,
            session.expires_at,
            session.is_valid,
        )
            .execute(pool)
            .await?;

        Ok(session)
    }

    pub async fn find_by_token(pool: &PgPool, token: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Session,
            r#"
            SELECT * FROM sessions WHERE token = $1 AND is_valid = true
            "#,
            token
        )
        .fetch_optional(pool)
        .await
    }

    pub async fn update_activity(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE sessions
            SET last_activity = NOW()
            WHERE id = $1
            "#,
            self.id
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn invalidate(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE sessions
            SET is_valid = false
            WHERE id = $1
            "#,
            self.id
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}
