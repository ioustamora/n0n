use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::access_control::{AccessControlRequest, AccessControlResponse};
use crate::access_control::authentication::LoginAttempt;
use crate::access_control::sessions::Session;

#[derive(Clone)]
pub struct AuditLogger {
    config: AuditConfig,
    audit_events: Arc<RwLock<Vec<AuditEvent>>>,
    is_running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub log_all_events: bool,
    pub retention_days: u32,
    pub max_events: usize,
    pub real_time_monitoring: bool,
    pub export_format: AuditExportFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditExportFormat {
    JSON,
    CSV,
    XML,
    SIEM,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub event_type: AuditEventType,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub resource: Option<String>,
    pub action: Option<String>,
    pub result: AuditResult,
    pub details: HashMap<String, String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    ResourceAccess,
    SessionManagement,
    PolicyViolation,
    AdminAction,
    SystemEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure,
    Denied,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub user_id: Option<String>,
    pub event_type: Option<AuditEventType>,
    pub resource: Option<String>,
    pub result: Option<AuditResult>,
    pub limit: Option<usize>,
}

impl AuditLogger {
    pub async fn new(config: AuditConfig) -> Result<Self, AuditError> {
        Ok(Self {
            config,
            audit_events: Arc::new(RwLock::new(Vec::new())),
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start(&self) -> Result<(), AuditError> {
        let mut running = self.is_running.write().await;
        if *running {
            return Err(AuditError::AlreadyRunning);
        }
        *running = true;
        log::info!("Audit logger started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), AuditError> {
        let mut running = self.is_running.write().await;
        *running = false;
        log::info!("Audit logger stopped");
        Ok(())
    }

    pub async fn log_access_attempt(&self, request: &AccessControlRequest, audit_id: &str) -> Result<(), AuditError> {
        let event = AuditEvent {
            id: audit_id.to_string(),
            event_type: AuditEventType::Authorization,
            timestamp: Utc::now(),
            user_id: Some(request.user_id.clone()),
            session_id: Some(request.session_id.clone()),
            resource: Some(request.resource.clone()),
            action: Some(request.action.clone()),
            result: AuditResult::Success, // Will be updated when decision is made
            details: HashMap::new(),
            ip_address: request.context.ip_address.clone(),
            user_agent: request.context.user_agent.clone(),
        };

        let mut events = self.audit_events.write().await;
        events.push(event);
        self.maintain_event_limit(&mut events);

        Ok(())
    }

    pub async fn log_access_decision(&self, request: &AccessControlRequest, response: &AccessControlResponse) -> Result<(), AuditError> {
        let result = match response.decision {
            crate::access_control::abac::AccessDecision::Permit => AuditResult::Success,
            _ => AuditResult::Denied,
        };

        let mut details = HashMap::new();
        details.insert("decision".to_string(), format!("{:?}", response.decision));
        details.insert("reason".to_string(), response.reason.clone());

        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            event_type: AuditEventType::Authorization,
            timestamp: Utc::now(),
            user_id: Some(request.user_id.clone()),
            session_id: Some(request.session_id.clone()),
            resource: Some(request.resource.clone()),
            action: Some(request.action.clone()),
            result,
            details,
            ip_address: request.context.ip_address.clone(),
            user_agent: request.context.user_agent.clone(),
        };

        let mut events = self.audit_events.write().await;
        events.push(event);
        self.maintain_event_limit(&mut events);

        Ok(())
    }

    pub async fn log_authentication_success(&self, attempt: &LoginAttempt, session: &Session) -> Result<(), AuditError> {
        let mut details = HashMap::new();
        details.insert("session_id".to_string(), session.session_id.clone());
        details.insert("mfa_used".to_string(), attempt.mfa_provided.to_string());

        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            event_type: AuditEventType::Authentication,
            timestamp: attempt.timestamp,
            user_id: Some(session.user_id.clone()),
            session_id: Some(session.session_id.clone()),
            resource: None,
            action: Some("login".to_string()),
            result: AuditResult::Success,
            details,
            ip_address: attempt.ip_address.clone(),
            user_agent: attempt.user_agent.clone(),
        };

        let mut events = self.audit_events.write().await;
        events.push(event);
        self.maintain_event_limit(&mut events);

        Ok(())
    }

    pub async fn log_authentication_failure(&self, attempt: &LoginAttempt, reason: &str) -> Result<(), AuditError> {
        let mut details = HashMap::new();
        details.insert("failure_reason".to_string(), reason.to_string());

        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            event_type: AuditEventType::Authentication,
            timestamp: attempt.timestamp,
            user_id: Some(attempt.username.clone()),
            session_id: None,
            resource: None,
            action: Some("login".to_string()),
            result: AuditResult::Failure,
            details,
            ip_address: attempt.ip_address.clone(),
            user_agent: attempt.user_agent.clone(),
        };

        let mut events = self.audit_events.write().await;
        events.push(event);
        self.maintain_event_limit(&mut events);

        Ok(())
    }

    pub async fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, AuditError> {
        let events = self.audit_events.read().await;
        let mut result = Vec::new();

        for event in events.iter() {
            if let Some(start_time) = &query.start_time {
                if event.timestamp < *start_time {
                    continue;
                }
            }

            if let Some(end_time) = &query.end_time {
                if event.timestamp > *end_time {
                    continue;
                }
            }

            if let Some(user_id) = &query.user_id {
                if event.user_id.as_ref() != Some(user_id) {
                    continue;
                }
            }

            if let Some(event_type) = &query.event_type {
                if &event.event_type != event_type {
                    continue;
                }
            }

            if let Some(resource) = &query.resource {
                if event.resource.as_ref() != Some(resource) {
                    continue;
                }
            }

            if let Some(result) = &query.result {
                if &event.result != result {
                    continue;
                }
            }

            result.push(event.clone());

            if let Some(limit) = query.limit {
                if result.len() >= limit {
                    break;
                }
            }
        }

        Ok(result)
    }

    fn maintain_event_limit(&self, events: &mut Vec<AuditEvent>) {
        while events.len() > self.config.max_events {
            events.remove(0);
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_all_events: true,
            retention_days: 2555, // 7 years
            max_events: 1000000,
            real_time_monitoring: true,
            export_format: AuditExportFormat::JSON,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Audit logger already running")]
    AlreadyRunning,
    
    #[error("Audit logger not running")]
    NotRunning,
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Export error: {0}")]
    ExportError(String),
}