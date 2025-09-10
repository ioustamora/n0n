use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::access_control::authentication::LoginAttempt;

#[derive(Clone)]
pub struct SessionManager {
    config: SessionConfig,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    user_sessions: Arc<RwLock<HashMap<String, Vec<String>>>>,
    is_running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub max_session_duration_hours: u32,
    pub idle_timeout_minutes: u32,
    pub max_concurrent_sessions: u32,
    pub secure_cookies: bool,
    pub session_encryption: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user_id: String,
    pub status: SessionStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: Option<DateTime<Utc>>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Active,
    Expired,
    Terminated,
    Suspended,
}

impl SessionManager {
    pub async fn new(config: SessionConfig) -> Result<Self, SessionError> {
        Ok(Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start(&self) -> Result<(), SessionError> {
        let mut running = self.is_running.write().await;
        if *running {
            return Err(SessionError::AlreadyRunning);
        }
        *running = true;
        log::info!("Session manager started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), SessionError> {
        let mut running = self.is_running.write().await;
        *running = false;
        log::info!("Session manager stopped");
        Ok(())
    }

    pub async fn create_session(&self, user_id: &str, login_attempt: &LoginAttempt) -> Result<Session, SessionError> {
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(self.config.max_session_duration_hours as i64);

        let session = Session {
            session_id: session_id.clone(),
            user_id: user_id.to_string(),
            status: SessionStatus::Active,
            created_at: now,
            expires_at,
            last_activity: Some(now),
            ip_address: login_attempt.ip_address.clone(),
            user_agent: login_attempt.user_agent.clone(),
            metadata: HashMap::new(),
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session.clone());

        let mut user_sessions = self.user_sessions.write().await;
        user_sessions.entry(user_id.to_string()).or_insert_with(Vec::new).push(session_id);

        Ok(session)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<Session, SessionError> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id)
            .cloned()
            .ok_or_else(|| SessionError::SessionNotFound(session_id.to_string()))
    }

    pub async fn terminate_session(&self, session_id: &str) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.status = SessionStatus::Terminated;
        }
        Ok(())
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_session_duration_hours: 8,
            idle_timeout_minutes: 30,
            max_concurrent_sessions: 3,
            secure_cookies: true,
            session_encryption: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Session manager already running")]
    AlreadyRunning,
    
    #[error("Session manager not running")]
    NotRunning,
    
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("Too many concurrent sessions")]
    TooManySessions,
}