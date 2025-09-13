use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use anyhow::Result;

/// Audit event types for security logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    // Authentication events
    AuthenticationAttempt,
    AuthenticationSuccess,
    AuthenticationFailure,
    
    // Authorization events  
    AccessGranted,
    AccessDenied,
    PermissionChanged,
    
    // Cryptographic operations
    KeyGenerated,
    KeyRotated,
    KeyDestroyed,
    EncryptionOperation,
    DecryptionOperation,
    SigningOperation,
    VerificationOperation,
    
    // File operations
    FileUploaded,
    FileDownloaded,
    FileDeleted,
    FileAccessed,
    
    // Configuration changes
    ConfigurationChanged,
    SettingsModified,
    PolicyUpdated,
    
    // System events
    ApplicationStarted,
    ApplicationStopped,
    BackupCreated,
    BackupRestored,
    
    // Security events
    SuspiciousActivity,
    SecurityViolation,
    IntrusionAttempt,
    DataIntegrityViolation,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Type of audit event
    pub event_type: AuditEventType,
    /// User or system component that triggered the event
    pub actor: String,
    /// Target of the action (file, user, system component)
    pub target: Option<String>,
    /// Result of the operation (success, failure, etc.)
    pub result: AuditResult,
    /// Additional context and details
    pub details: serde_json::Value,
    /// Source IP address (if applicable)
    pub source_ip: Option<String>,
    /// Session ID (if applicable)
    pub session_id: Option<String>,
    /// Severity level of the event
    pub severity: AuditSeverity,
}

/// Result of an audited operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure,
    PartialSuccess,
    Warning,
}

/// Severity level for audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Audit logger for security and compliance
pub struct AuditLogger {
    file_path: PathBuf,
    enabled: bool,
}

impl AuditLogger {
    pub fn new(file_path: PathBuf, enabled: bool) -> Self {
        Self { file_path, enabled }
    }
    
    /// Log an audit event
    pub async fn log_event(&self, entry: AuditEntry) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        // Also log to structured tracing
        tracing::warn!(
            timestamp = %entry.timestamp,
            event_type = ?entry.event_type,
            actor = %entry.actor,
            target = ?entry.target,
            result = ?entry.result,
            severity = ?entry.severity,
            source_ip = ?entry.source_ip,
            session_id = ?entry.session_id,
            details = %entry.details,
            category = "audit",
            "Audit event logged"
        );
        
        // Write to audit log file
        let json_line = serde_json::to_string(&entry)?;
        let log_line = format!("{}\n", json_line);
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
            .await?;
            
        file.write_all(log_line.as_bytes()).await?;
        file.sync_all().await?;
        
        Ok(())
    }
    
    /// Log an authentication event
    pub async fn log_authentication(
        &self,
        event_type: AuditEventType,
        actor: &str,
        result: AuditResult,
        source_ip: Option<String>,
        details: serde_json::Value,
    ) -> Result<()> {
        let severity = match result {
            AuditResult::Success => AuditSeverity::Low,
            AuditResult::Failure => AuditSeverity::Medium,
            _ => AuditSeverity::Low,
        };
        
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            target: None,
            result,
            details,
            source_ip,
            session_id: None,
            severity,
        };
        
        self.log_event(entry).await
    }
    
    /// Log a file operation
    pub async fn log_file_operation(
        &self,
        event_type: AuditEventType,
        actor: &str,
        target: &str,
        result: AuditResult,
        file_size: Option<u64>,
        checksum: Option<String>,
        session_id: Option<String>,
    ) -> Result<()> {
        let mut details = serde_json::Map::new();
        if let Some(size) = file_size {
            details.insert("file_size".to_string(), serde_json::Value::Number(size.into()));
        }
        if let Some(hash) = checksum {
            details.insert("checksum".to_string(), serde_json::Value::String(hash));
        }
        
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            target: Some(target.to_string()),
            result,
            details: serde_json::Value::Object(details),
            source_ip: None,
            session_id,
            severity: AuditSeverity::Low,
        };
        
        self.log_event(entry).await
    }
    
    /// Log a cryptographic operation
    pub async fn log_crypto_operation(
        &self,
        event_type: AuditEventType,
        actor: &str,
        key_id: &str,
        result: AuditResult,
        algorithm: Option<String>,
        details: serde_json::Value,
    ) -> Result<()> {
        let mut detail_map = if let serde_json::Value::Object(map) = details {
            map
        } else {
            serde_json::Map::new()
        };
        
        detail_map.insert("key_id".to_string(), serde_json::Value::String(key_id.to_string()));
        if let Some(alg) = algorithm {
            detail_map.insert("algorithm".to_string(), serde_json::Value::String(alg));
        }
        
        let severity = match event_type {
            AuditEventType::KeyDestroyed => AuditSeverity::High,
            AuditEventType::KeyGenerated | AuditEventType::KeyRotated => AuditSeverity::Medium,
            _ => AuditSeverity::Low,
        };
        
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            target: Some(key_id.to_string()),
            result,
            details: serde_json::Value::Object(detail_map),
            source_ip: None,
            session_id: None,
            severity,
        };
        
        self.log_event(entry).await
    }
    
    /// Log a security event
    pub async fn log_security_event(
        &self,
        event_type: AuditEventType,
        actor: &str,
        target: Option<String>,
        severity: AuditSeverity,
        source_ip: Option<String>,
        details: serde_json::Value,
    ) -> Result<()> {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            target,
            result: AuditResult::Warning,
            details,
            source_ip,
            session_id: None,
            severity,
        };
        
        self.log_event(entry).await
    }
    
    /// Log a configuration change
    pub async fn log_config_change(
        &self,
        actor: &str,
        setting_name: &str,
        old_value: Option<String>,
        new_value: String,
        session_id: Option<String>,
    ) -> Result<()> {
        let mut details = serde_json::Map::new();
        details.insert("setting_name".to_string(), serde_json::Value::String(setting_name.to_string()));
        details.insert("new_value".to_string(), serde_json::Value::String(new_value));
        if let Some(old_val) = old_value {
            details.insert("old_value".to_string(), serde_json::Value::String(old_val));
        }
        
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: AuditEventType::ConfigurationChanged,
            actor: actor.to_string(),
            target: Some(setting_name.to_string()),
            result: AuditResult::Success,
            details: serde_json::Value::Object(details),
            source_ip: None,
            session_id,
            severity: AuditSeverity::Medium,
        };
        
        self.log_event(entry).await
    }
}

/// Global audit logger instance
static mut AUDIT_LOGGER: Option<AuditLogger> = None;
static AUDIT_INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the global audit logger
pub fn init_audit_logger(file_path: PathBuf, enabled: bool) {
    AUDIT_INIT.call_once(|| {
        unsafe {
            AUDIT_LOGGER = Some(AuditLogger::new(file_path, enabled));
        }
    });
}

/// Get the global audit logger
pub fn get_audit_logger() -> Option<&'static AuditLogger> {
    unsafe { AUDIT_LOGGER.as_ref() }
}

/// Convenience macros for audit logging
#[macro_export]
macro_rules! audit_log {
    ($event_type:expr, $actor:expr, $result:expr, $details:expr) => {
        if let Some(logger) = $crate::logging::audit::get_audit_logger() {
            let entry = $crate::logging::audit::AuditEntry {
                timestamp: chrono::Utc::now(),
                event_type: $event_type,
                actor: $actor.to_string(),
                target: None,
                result: $result,
                details: $details,
                source_ip: None,
                session_id: None,
                severity: $crate::logging::audit::AuditSeverity::Low,
            };
            
            tokio::spawn(async move {
                if let Err(e) = logger.log_event(entry).await {
                    tracing::error!("Failed to write audit log: {}", e);
                }
            });
        }
    };
}

#[macro_export]
macro_rules! audit_crypto {
    ($event_type:expr, $actor:expr, $key_id:expr, $result:expr) => {
        if let Some(logger) = $crate::logging::audit::get_audit_logger() {
            tokio::spawn(async move {
                if let Err(e) = logger.log_crypto_operation(
                    $event_type,
                    $actor,
                    $key_id,
                    $result,
                    None,
                    serde_json::json!({}),
                ).await {
                    tracing::error!("Failed to write crypto audit log: {}", e);
                }
            });
        }
    };
}

#[macro_export]
macro_rules! audit_file {
    ($event_type:expr, $actor:expr, $target:expr, $result:expr) => {
        if let Some(logger) = $crate::logging::audit::get_audit_logger() {
            tokio::spawn(async move {
                if let Err(e) = logger.log_file_operation(
                    $event_type,
                    $actor,
                    $target,
                    $result,
                    None,
                    None,
                    None,
                ).await {
                    tracing::error!("Failed to write file audit log: {}", e);
                }
            });
        }
    };
}

#[macro_export]
macro_rules! audit_security {
    ($event_type:expr, $actor:expr, $severity:expr, $details:expr) => {
        if let Some(logger) = $crate::logging::audit::get_audit_logger() {
            tokio::spawn(async move {
                if let Err(e) = logger.log_security_event(
                    $event_type,
                    $actor,
                    None,
                    $severity,
                    None,
                    $details,
                ).await {
                    tracing::error!("Failed to write security audit log: {}", e);
                }
            });
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::fs;

    #[tokio::test]
    async fn test_audit_logger_file_operation() {
        let temp_file = NamedTempFile::new().unwrap();
        let audit_path = temp_file.path().to_path_buf();
        
        let logger = AuditLogger::new(audit_path.clone(), true);
        
        logger.log_file_operation(
            AuditEventType::FileUploaded,
            "test_user",
            "test_file.txt",
            AuditResult::Success,
            Some(1024),
            Some("sha256hash".to_string()),
            Some("session123".to_string()),
        ).await.unwrap();
        
        // Verify the log was written
        let content = fs::read_to_string(&audit_path).await.unwrap();
        assert!(!content.is_empty());
        assert!(content.contains("FileUploaded"));
        assert!(content.contains("test_user"));
        assert!(content.contains("test_file.txt"));
    }

    #[tokio::test]
    async fn test_audit_logger_crypto_operation() {
        let temp_file = NamedTempFile::new().unwrap();
        let audit_path = temp_file.path().to_path_buf();
        
        let logger = AuditLogger::new(audit_path.clone(), true);
        
        logger.log_crypto_operation(
            AuditEventType::KeyGenerated,
            "system",
            "key_id_123",
            AuditResult::Success,
            Some("AES256".to_string()),
            serde_json::json!({"purpose": "data_encryption"}),
        ).await.unwrap();
        
        let content = fs::read_to_string(&audit_path).await.unwrap();
        assert!(content.contains("KeyGenerated"));
        assert!(content.contains("key_id_123"));
        assert!(content.contains("AES256"));
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: AuditEventType::FileAccessed,
            actor: "user123".to_string(),
            target: Some("document.pdf".to_string()),
            result: AuditResult::Success,
            details: serde_json::json!({"action": "read"}),
            source_ip: Some("192.168.1.100".to_string()),
            session_id: Some("sess_456".to_string()),
            severity: AuditSeverity::Low,
        };
        
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.is_empty());
        
        let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.actor, "user123");
        assert_eq!(deserialized.target, Some("document.pdf".to_string()));
    }
}