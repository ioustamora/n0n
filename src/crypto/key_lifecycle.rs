use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use chrono::{DateTime, Utc, Duration};
use thiserror::Error;
use uuid::Uuid;
use tokio::time::Interval;

use crate::crypto::key_management::{
    KeyManagementSystem, KeyStatus, 
    KeyRotationResult, KeyManagementError
};

/// Key lifecycle management system
pub struct KeyLifecycleManager {
    /// Key management system reference
    kms: Arc<KeyManagementSystem>,
    /// Lifecycle policies
    lifecycle_policies: Arc<RwLock<HashMap<String, LifecyclePolicy>>>,
    /// Rotation scheduler
    rotation_scheduler: Arc<Mutex<RotationScheduler>>,
    /// Lifecycle events log
    lifecycle_events: Arc<RwLock<Vec<LifecycleEvent>>>,
    /// Running background tasks
    background_tasks: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
    /// Configuration
    config: LifecycleConfig,
}

#[derive(Error, Debug)]
pub enum LifecycleError {
    #[error("Policy not found: {policy_id}")]
    PolicyNotFound { policy_id: String },
    
    #[error("Invalid lifecycle policy: {reason}")]
    InvalidPolicy { reason: String },
    
    #[error("Rotation failed: {reason}")]
    RotationFailed { reason: String },
    
    #[error("Lifecycle event failed: {reason}")]
    LifecycleEventFailed { reason: String },
    
    #[error("Scheduler error: {reason}")]
    SchedulerError { reason: String },
    
    #[error("Key management error: {0}")]
    KeyManagementError(#[from] KeyManagementError),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Key lifecycle policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecyclePolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub key_types: Vec<String>, // Which key types this applies to
    pub rotation_config: RotationConfig,
    pub expiration_config: ExpirationConfig,
    pub deprecation_config: DeprecationConfig,
    pub revocation_config: RevocationConfig,
    pub backup_config: BackupConfig,
    pub compliance_requirements: Vec<ComplianceRequirement>,
    pub notification_config: NotificationConfig,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub enabled: bool,
}

/// Key rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    pub automatic_rotation: bool,
    pub rotation_interval: RotationInterval,
    pub rotation_triggers: Vec<RotationTrigger>,
    pub rotation_strategy: RotationStrategy,
    pub grace_period: Duration,
    pub max_active_versions: u32,
    pub require_approval: bool,
    pub approval_roles: Vec<String>,
}

/// Key expiration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpirationConfig {
    pub max_key_lifetime: Option<Duration>,
    pub warning_period: Duration,
    pub auto_renew: bool,
    pub renew_before_expiry: Duration,
    pub hard_expiry: bool,
}

/// Key lifecycle state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LifecycleState {
    Created,
    Active,
    Deprecated,
    Revoked,
    Destroyed,
    Archived,
}

/// Key deprecation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecationConfig {
    pub deprecation_period: Duration,
    pub allow_decrypt_only: bool,
    pub migration_grace_period: Duration,
    pub force_migration: bool,
}

/// Key revocation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationConfig {
    pub revocation_reasons: Vec<RevocationReason>,
    pub immediate_revocation: bool,
    pub revocation_grace_period: Option<Duration>,
    pub crl_distribution_points: Vec<String>,
    pub ocsp_responders: Vec<String>,
}

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub enable_backup: bool,
    pub backup_frequency: BackupFrequency,
    pub backup_locations: Vec<String>,
    pub encryption_required: bool,
    pub retention_period: Duration,
    pub verify_backups: bool,
}

/// Compliance requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    pub standard: String, // e.g., "FIPS-140-2", "Common Criteria", "SOC 2"
    pub requirement_id: String,
    pub description: String,
    pub validation_rules: Vec<String>,
    pub audit_frequency: Duration,
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub notification_channels: Vec<NotificationChannel>,
    pub events_to_notify: Vec<LifecycleEventType>,
    pub escalation_rules: Vec<EscalationRule>,
}

/// Rotation interval types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationInterval {
    Days(u32),
    Weeks(u32),
    Months(u32),
    Years(u32),
    UsageBased(u64), // Number of operations
    Custom(Duration),
}

/// Rotation triggers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RotationTrigger {
    ScheduledRotation,
    UsageThreshold(u64),
    SecurityIncident,
    ComplianceRequirement,
    ManualTrigger,
    KeyCompromise,
    PolicyChange,
}

/// Rotation strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationStrategy {
    /// Create new key, keep old key for decryption only
    GracefulRotation,
    /// Create new key, immediately revoke old key
    ImmediateRotation,
    /// Create new key, deprecate old key with grace period
    ScheduledDeprecation,
    /// Blue-green style rotation with validation
    BlueGreenRotation,
}

/// Revocation reasons
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RevocationReason {
    KeyCompromise,
    PolicyViolation,
    SecurityIncident,
    ComplianceRequirement,
    EndOfLife,
    SupersededByNewKey,
    AdministrativeRevocation,
    Unknown,
}

/// Backup frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupFrequency {
    Hourly,
    Daily,
    Weekly,
    Monthly,
    OnRotation,
    OnDemand,
}

/// Notification channels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannel {
    Email(String),
    Webhook(String),
    Sms(String),
    Slack(String),
    Teams(String),
    Syslog,
    Snmp,
}

/// Escalation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRule {
    pub trigger_condition: String,
    pub escalation_delay: Duration,
    pub escalation_channels: Vec<NotificationChannel>,
    pub escalation_message: String,
}

/// Lifecycle event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LifecycleEventType {
    KeyCreated,
    KeyRotated,
    KeyExpired,
    KeyDeprecated,
    KeyRevoked,
    KeyDestroyed,
    KeyBacked,
    KeyRestored,
    PolicyApplied,
    ComplianceViolation,
    RotationFailed,
    BackupFailed,
}

/// Lifecycle event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub id: String,
    pub event_type: LifecycleEventType,
    pub key_id: String,
    pub policy_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub metadata: HashMap<String, String>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Rotation scheduler
pub struct RotationScheduler {
    scheduled_rotations: HashMap<String, ScheduledRotation>,
    scheduler_interval: Interval,
    running: bool,
}

/// Scheduled rotation information
#[derive(Debug, Clone)]
struct ScheduledRotation {
    key_id: String,
    policy_id: String,
    next_rotation: DateTime<Utc>,
    rotation_config: RotationConfig,
}

/// Lifecycle configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleConfig {
    pub enable_automatic_rotation: bool,
    pub enable_automatic_cleanup: bool,
    pub enable_compliance_monitoring: bool,
    pub max_lifecycle_events: usize,
    pub cleanup_expired_keys_after: Duration,
    pub scheduler_interval: Duration,
    pub backup_encryption_key: Option<String>,
}

impl KeyLifecycleManager {
    /// Create new key lifecycle manager
    pub fn new(kms: Arc<KeyManagementSystem>, config: LifecycleConfig) -> Self {
        let scheduler_interval = tokio::time::interval(config.scheduler_interval.to_std().unwrap());
        
        Self {
            kms,
            lifecycle_policies: Arc::new(RwLock::new(HashMap::new())),
            rotation_scheduler: Arc::new(Mutex::new(RotationScheduler {
                scheduled_rotations: HashMap::new(),
                scheduler_interval,
                running: false,
            })),
            lifecycle_events: Arc::new(RwLock::new(Vec::new())),
            background_tasks: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Start lifecycle manager background services
    pub async fn start(&self) -> Result<(), LifecycleError> {
        self.start_background_tasks().await?;
        Ok(())
    }

    /// Stop lifecycle manager background services
    pub async fn stop(&self) -> Result<(), LifecycleError> {
        self.stop_background_tasks().await?;
        Ok(())
    }

    /// Create lifecycle policy
    pub async fn create_lifecycle_policy(&self, policy: LifecyclePolicy) -> Result<(), LifecycleError> {
        self.validate_lifecycle_policy(&policy)?;
        
        let policy_id = policy.id.clone();
        self.lifecycle_policies.write().await.insert(policy_id.clone(), policy);
        
        self.log_event(LifecycleEvent {
            id: Uuid::new_v4().to_string(),
            event_type: LifecycleEventType::PolicyApplied,
            key_id: "N/A".to_string(),
            policy_id: Some(policy_id),
            timestamp: Utc::now(),
            description: "Lifecycle policy created".to_string(),
            metadata: HashMap::new(),
            success: true,
            error_message: None,
        }).await;

        Ok(())
    }

    /// Apply lifecycle policy to key
    pub async fn apply_policy_to_key(&self, key_id: &str, policy_id: &str) -> Result<(), LifecycleError> {
        let policy = {
            let policies = self.lifecycle_policies.read().await;
            policies.get(policy_id)
                .ok_or_else(|| LifecycleError::PolicyNotFound { policy_id: policy_id.to_string() })?
                .clone()
        };

        // Schedule rotation if automatic rotation is enabled
        if policy.rotation_config.automatic_rotation {
            self.schedule_key_rotation(key_id, &policy).await?;
        }

        self.log_event(LifecycleEvent {
            id: Uuid::new_v4().to_string(),
            event_type: LifecycleEventType::PolicyApplied,
            key_id: key_id.to_string(),
            policy_id: Some(policy_id.to_string()),
            timestamp: Utc::now(),
            description: format!("Policy {} applied to key {}", policy_id, key_id),
            metadata: HashMap::new(),
            success: true,
            error_message: None,
        }).await;

        Ok(())
    }

    /// Trigger manual key rotation
    pub async fn trigger_key_rotation(
        &self, 
        key_id: &str, 
        reason: RotationTrigger
    ) -> Result<KeyRotationResult, LifecycleError> {
        let rotation_result = match self.kms.rotate_master_key(key_id).await {
            Ok(result) => result,
            Err(e) => {
                self.log_event(LifecycleEvent {
                    id: Uuid::new_v4().to_string(),
                    event_type: LifecycleEventType::RotationFailed,
                    key_id: key_id.to_string(),
                    policy_id: None,
                    timestamp: Utc::now(),
                    description: format!("Key rotation failed: {:?}", reason),
                    metadata: HashMap::new(),
                    success: false,
                    error_message: Some(e.to_string()),
                }).await;
                
                return Err(LifecycleError::RotationFailed { reason: e.to_string() });
            }
        };

        // Log successful rotation
        self.log_event(LifecycleEvent {
            id: Uuid::new_v4().to_string(),
            event_type: LifecycleEventType::KeyRotated,
            key_id: key_id.to_string(),
            policy_id: None,
            timestamp: Utc::now(),
            description: format!("Key rotated successfully: {:?}", reason),
            metadata: [
                ("old_key_id".to_string(), rotation_result.old_key_id.clone()),
                ("new_key_id".to_string(), rotation_result.new_key_id.clone()),
                ("affected_keys".to_string(), rotation_result.affected_data_keys.len().to_string()),
            ].iter().cloned().collect(),
            success: true,
            error_message: None,
        }).await;

        Ok(rotation_result)
    }

    /// Revoke key
    pub async fn revoke_key(&self, key_id: &str, reason: RevocationReason) -> Result<(), LifecycleError> {
        // Update key status to revoked
        // In a real implementation, this would update the key in the KMS
        
        self.log_event(LifecycleEvent {
            id: Uuid::new_v4().to_string(),
            event_type: LifecycleEventType::KeyRevoked,
            key_id: key_id.to_string(),
            policy_id: None,
            timestamp: Utc::now(),
            description: format!("Key revoked: {:?}", reason),
            metadata: [("reason".to_string(), format!("{:?}", reason))].iter().cloned().collect(),
            success: true,
            error_message: None,
        }).await;

        // Send notifications
        self.send_lifecycle_notifications(LifecycleEventType::KeyRevoked, key_id).await?;

        Ok(())
    }

    /// Get key lifecycle status
    pub async fn get_key_lifecycle_status(&self, key_id: &str) -> Result<KeyLifecycleStatus, LifecycleError> {
        let events = self.lifecycle_events.read().await;
        let key_events: Vec<_> = events.iter()
            .filter(|e| e.key_id == key_id)
            .collect();

        let last_rotation = key_events.iter()
            .filter(|e| e.event_type == LifecycleEventType::KeyRotated)
            .map(|e| e.timestamp)
            .max();

        let status = if key_events.iter().any(|e| e.event_type == LifecycleEventType::KeyRevoked) {
            KeyStatus::Revoked
        } else if key_events.iter().any(|e| e.event_type == LifecycleEventType::KeyDeprecated) {
            KeyStatus::Deprecated
        } else {
            KeyStatus::Active
        };

        // Calculate next rotation if scheduled
        let next_rotation = self.get_next_scheduled_rotation(key_id).await;

        Ok(KeyLifecycleStatus {
            key_id: key_id.to_string(),
            status,
            created_at: key_events.iter()
                .filter(|e| e.event_type == LifecycleEventType::KeyCreated)
                .map(|e| e.timestamp)
                .min(),
            last_rotation,
            next_rotation,
            total_rotations: key_events.iter()
                .filter(|e| e.event_type == LifecycleEventType::KeyRotated)
                .count() as u32,
            compliance_status: self.check_key_compliance(key_id).await?,
            applied_policies: self.get_applied_policies(key_id).await,
        })
    }

    /// Get lifecycle events for a key
    pub async fn get_key_lifecycle_events(&self, key_id: &str) -> Result<Vec<LifecycleEvent>, LifecycleError> {
        let events = self.lifecycle_events.read().await;
        Ok(events.iter()
            .filter(|e| e.key_id == key_id)
            .cloned()
            .collect())
    }

    /// Generate compliance report
    pub async fn generate_compliance_report(&self, standard: &str) -> Result<ComplianceReport, LifecycleError> {
        let policies = self.lifecycle_policies.read().await;
        let events = self.lifecycle_events.read().await;

        let applicable_policies: Vec<_> = policies.values()
            .filter(|p| p.compliance_requirements.iter()
                .any(|req| req.standard == standard))
            .collect();

        let compliance_violations: Vec<_> = events.iter()
            .filter(|e| e.event_type == LifecycleEventType::ComplianceViolation)
            .filter(|e| e.metadata.get("standard").map_or(false, |s| s == standard))
            .cloned()
            .collect();

        let total_keys = self.kms.list_master_keys().await?.len();
        let compliant_keys = total_keys - compliance_violations.len();

        let recommendations = self.generate_compliance_recommendations(standard, &compliance_violations).await;
        
        Ok(ComplianceReport {
            standard: standard.to_string(),
            generated_at: Utc::now(),
            total_keys,
            compliant_keys,
            violation_count: compliance_violations.len(),
            applicable_policies: applicable_policies.len(),
            violations: compliance_violations,
            recommendations,
        })
    }

    // Private helper methods

    async fn start_rotation_scheduler(&self) -> Result<(), LifecycleError> {
        let scheduler = self.rotation_scheduler.clone();
        let kms = self.kms.clone();
        let events = self.lifecycle_events.clone();

        let task_handle = tokio::spawn(async move {
            let mut scheduler = scheduler.lock().await;
            scheduler.running = true;

            while scheduler.running {
                scheduler.scheduler_interval.tick().await;
                
                let now = Utc::now();
                let mut rotations_to_perform = Vec::new();

                // Check for scheduled rotations
                for (key_id, rotation) in &scheduler.scheduled_rotations {
                    if rotation.next_rotation <= now {
                        rotations_to_perform.push((key_id.clone(), rotation.clone()));
                    }
                }

                // Perform rotations
                for (key_id, rotation) in rotations_to_perform {
                    match kms.rotate_master_key(&key_id).await {
                        Ok(result) => {
                            log::info!("Automatic key rotation successful: {} -> {}", 
                                result.old_key_id, result.new_key_id);
                            
                            // Log event
                            let event = LifecycleEvent {
                                id: Uuid::new_v4().to_string(),
                                event_type: LifecycleEventType::KeyRotated,
                                key_id: key_id.clone(),
                                policy_id: Some(rotation.policy_id.clone()),
                                timestamp: Utc::now(),
                                description: "Automatic key rotation".to_string(),
                                metadata: HashMap::new(),
                                success: true,
                                error_message: None,
                            };
                            
                            events.write().await.push(event);

                            // Schedule next rotation
                            if let Some(next_rotation) = Self::calculate_next_rotation(&rotation.rotation_config) {
                                scheduler.scheduled_rotations.insert(key_id.clone(), ScheduledRotation {
                                    key_id: key_id.clone(),
                                    policy_id: rotation.policy_id,
                                    next_rotation,
                                    rotation_config: rotation.rotation_config,
                                });
                            }
                        }
                        Err(e) => {
                            log::error!("Automatic key rotation failed for {}: {}", key_id, e);
                            
                            // Log failure event
                            let event = LifecycleEvent {
                                id: Uuid::new_v4().to_string(),
                                event_type: LifecycleEventType::RotationFailed,
                                key_id: key_id.clone(),
                                policy_id: Some(rotation.policy_id.clone()),
                                timestamp: Utc::now(),
                                description: "Automatic key rotation failed".to_string(),
                                metadata: HashMap::new(),
                                success: false,
                                error_message: Some(e.to_string()),
                            };
                            
                            events.write().await.push(event);
                        }
                    }
                }
            }
        });

        self.background_tasks.write().await.insert("rotation_scheduler".to_string(), task_handle);
        Ok(())
    }

    async fn start_compliance_monitor(&self) -> Result<(), LifecycleError> {
        let policies = self.lifecycle_policies.clone();
        let events = self.lifecycle_events.clone();
        let kms = self.kms.clone();

        let task_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // Check hourly

            loop {
                interval.tick().await;
                
                // Check compliance for all policies
                let policy_map = policies.read().await;
                for policy in policy_map.values() {
                    for requirement in &policy.compliance_requirements {
                        // Perform compliance check
                        if let Err(violation) = Self::check_compliance_requirement(requirement, &kms).await {
                            let event = LifecycleEvent {
                                id: Uuid::new_v4().to_string(),
                                event_type: LifecycleEventType::ComplianceViolation,
                                key_id: "N/A".to_string(),
                                policy_id: Some(policy.id.clone()),
                                timestamp: Utc::now(),
                                description: format!("Compliance violation: {}", violation),
                                metadata: [
                                    ("standard".to_string(), requirement.standard.clone()),
                                    ("requirement_id".to_string(), requirement.requirement_id.clone()),
                                ].iter().cloned().collect(),
                                success: false,
                                error_message: Some(violation),
                            };
                            
                            events.write().await.push(event);
                        }
                    }
                }
            }
        });

        self.background_tasks.write().await.insert("compliance_monitor".to_string(), task_handle);
        Ok(())
    }

    async fn start_cleanup_service(&self) -> Result<(), LifecycleError> {
        let events = self.lifecycle_events.clone();
        let config = self.config.clone();

        let task_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(86400)); // Check daily

            loop {
                interval.tick().await;
                
                // Clean up old events
                let mut events_guard = events.write().await;
                let current_len = events_guard.len();
                if current_len > config.max_lifecycle_events {
                    events_guard.drain(0..current_len - config.max_lifecycle_events);
                }
                
                // Clean up expired keys (placeholder - would need KMS integration)
                log::info!("Cleanup service: Cleaned up old lifecycle events");
            }
        });

        self.background_tasks.write().await.insert("cleanup_service".to_string(), task_handle);
        Ok(())
    }

    async fn schedule_key_rotation(&self, key_id: &str, policy: &LifecyclePolicy) -> Result<(), LifecycleError> {
        if let Some(next_rotation) = Self::calculate_next_rotation(&policy.rotation_config) {
            let rotation = ScheduledRotation {
                key_id: key_id.to_string(),
                policy_id: policy.id.clone(),
                next_rotation,
                rotation_config: policy.rotation_config.clone(),
            };

            self.rotation_scheduler.lock().await
                .scheduled_rotations
                .insert(key_id.to_string(), rotation);
        }

        Ok(())
    }

    fn calculate_next_rotation(config: &RotationConfig) -> Option<DateTime<Utc>> {
        if !config.automatic_rotation {
            return None;
        }

        let now = Utc::now();
        let next = match &config.rotation_interval {
            RotationInterval::Days(days) => now + Duration::days(*days as i64),
            RotationInterval::Weeks(weeks) => now + Duration::weeks(*weeks as i64),
            RotationInterval::Months(months) => {
                // Approximate months as 30 days
                now + Duration::days(*months as i64 * 30)
            }
            RotationInterval::Years(years) => now + Duration::days(*years as i64 * 365),
            RotationInterval::Custom(duration) => now + *duration,
            RotationInterval::UsageBased(_) => {
                // Usage-based rotation would need additional tracking
                now + Duration::days(30) // Default fallback
            }
        };

        Some(next)
    }

    async fn log_event(&self, event: LifecycleEvent) {
        let mut events = self.lifecycle_events.write().await;
        events.push(event);

        // Limit events to max configured
        let current_len = events.len();
        if current_len > self.config.max_lifecycle_events {
            events.drain(0..current_len - self.config.max_lifecycle_events);
        }
    }

    async fn send_lifecycle_notifications(&self, event_type: LifecycleEventType, key_id: &str) -> Result<(), LifecycleError> {
        // Placeholder for notification sending
        log::info!("Notification: {:?} for key {}", event_type, key_id);
        Ok(())
    }

    async fn get_next_scheduled_rotation(&self, key_id: &str) -> Option<DateTime<Utc>> {
        let scheduler = self.rotation_scheduler.lock().await;
        scheduler.scheduled_rotations.get(key_id)
            .map(|rotation| rotation.next_rotation)
    }

    async fn check_key_compliance(&self, _key_id: &str) -> Result<ComplianceStatus, LifecycleError> {
        // Placeholder implementation
        Ok(ComplianceStatus::Compliant)
    }

    async fn get_applied_policies(&self, _key_id: &str) -> Vec<String> {
        // Placeholder implementation
        vec![]
    }

    fn validate_lifecycle_policy(&self, policy: &LifecyclePolicy) -> Result<(), LifecycleError> {
        if policy.name.is_empty() {
            return Err(LifecycleError::InvalidPolicy { 
                reason: "Policy name cannot be empty".to_string() 
            });
        }

        if policy.rotation_config.max_active_versions == 0 {
            return Err(LifecycleError::InvalidPolicy { 
                reason: "Must allow at least 1 active key version".to_string() 
            });
        }

        Ok(())
    }

    async fn check_compliance_requirement(
        _requirement: &ComplianceRequirement, 
        _kms: &KeyManagementSystem
    ) -> Result<(), String> {
        // Placeholder implementation
        Ok(())
    }

    async fn generate_compliance_recommendations(
        &self,
        _standard: &str,
        _violations: &[LifecycleEvent]
    ) -> Vec<String> {
        // Placeholder implementation
        vec![
            "Implement regular key rotation schedule".to_string(),
            "Enable automatic backup for all keys".to_string(),
            "Review and update key lifecycle policies".to_string(),
        ]
    }

    /// Get active lifecycle policies
    pub async fn get_active_policies(&self) -> Vec<LifecyclePolicy> {
        let policies = self.lifecycle_policies.read().await;
        policies.values().cloned().collect()
    }

    /// Start background tasks for lifecycle management
    pub async fn start_background_tasks(&self) -> Result<(), LifecycleError> {
        self.start_rotation_scheduler().await?;
        self.start_cleanup_service().await?;
        log::info!("Lifecycle background tasks started");
        Ok(())
    }

    /// Stop background tasks for lifecycle management
    pub async fn stop_background_tasks(&self) -> Result<(), LifecycleError> {
        let mut tasks = self.background_tasks.write().await;
        for (name, handle) in tasks.drain() {
            handle.abort();
            log::info!("Stopped background task: {}", name);
        }
        log::info!("Lifecycle background tasks stopped");
        Ok(())
    }
}

/// Key lifecycle status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLifecycleStatus {
    pub key_id: String,
    pub status: KeyStatus,
    pub created_at: Option<DateTime<Utc>>,
    pub last_rotation: Option<DateTime<Utc>>,
    pub next_rotation: Option<DateTime<Utc>>,
    pub total_rotations: u32,
    pub compliance_status: ComplianceStatus,
    pub applied_policies: Vec<String>,
}

/// Compliance status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    Warning,
    Unknown,
}

/// Compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub standard: String,
    pub generated_at: DateTime<Utc>,
    pub total_keys: usize,
    pub compliant_keys: usize,
    pub violation_count: usize,
    pub applicable_policies: usize,
    pub violations: Vec<LifecycleEvent>,
    pub recommendations: Vec<String>,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            enable_automatic_rotation: true,
            enable_automatic_cleanup: true,
            enable_compliance_monitoring: true,
            max_lifecycle_events: 10000,
            cleanup_expired_keys_after: Duration::days(30),
            scheduler_interval: Duration::minutes(5),
            backup_encryption_key: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_management::{KeyStoreConfig, KeyPolicy, KeyOperation};

    #[tokio::test]
    async fn test_lifecycle_manager_creation() -> Result<(), Box<dyn std::error::Error>> {
        let kms_config = KeyStoreConfig::default();
        let kms = Arc::new(KeyManagementSystem::new(kms_config));
        
        let lifecycle_config = LifecycleConfig::default();
        let lifecycle_manager = KeyLifecycleManager::new(kms, lifecycle_config);

        // Test basic functionality
        assert!(!lifecycle_manager.background_tasks.read().await.is_empty() == false);

        Ok(())
    }

    #[tokio::test]
    async fn test_lifecycle_policy_creation() -> Result<(), Box<dyn std::error::Error>> {
        let kms_config = KeyStoreConfig::default();
        let kms = Arc::new(KeyManagementSystem::new(kms_config));
        
        let lifecycle_config = LifecycleConfig::default();
        let lifecycle_manager = KeyLifecycleManager::new(kms, lifecycle_config);

        let policy = LifecyclePolicy {
            id: "test-policy".to_string(),
            name: "Test Lifecycle Policy".to_string(),
            description: "Test policy for key lifecycle".to_string(),
            key_types: vec!["master".to_string()],
            rotation_config: RotationConfig {
                automatic_rotation: true,
                rotation_interval: RotationInterval::Days(90),
                rotation_triggers: vec![RotationTrigger::ScheduledRotation],
                rotation_strategy: RotationStrategy::GracefulRotation,
                grace_period: Duration::days(7),
                max_active_versions: 3,
                require_approval: false,
                approval_roles: vec![],
            },
            expiration_config: ExpirationConfig {
                max_key_lifetime: Some(Duration::days(365)),
                warning_period: Duration::days(30),
                auto_renew: true,
                renew_before_expiry: Duration::days(7),
                hard_expiry: false,
            },
            deprecation_config: DeprecationConfig {
                deprecation_period: Duration::days(30),
                allow_decrypt_only: true,
                migration_grace_period: Duration::days(14),
                force_migration: false,
            },
            revocation_config: RevocationConfig {
                revocation_reasons: vec![RevocationReason::KeyCompromise],
                immediate_revocation: false,
                revocation_grace_period: Some(Duration::hours(24)),
                crl_distribution_points: vec![],
                ocsp_responders: vec![],
            },
            backup_config: BackupConfig {
                enable_backup: true,
                backup_frequency: BackupFrequency::Daily,
                backup_locations: vec!["s3://backup-bucket".to_string()],
                encryption_required: true,
                retention_period: Duration::days(90),
                verify_backups: true,
            },
            compliance_requirements: vec![
                ComplianceRequirement {
                    standard: "FIPS-140-2".to_string(),
                    requirement_id: "4.7.1".to_string(),
                    description: "Key lifecycle management".to_string(),
                    validation_rules: vec!["regular_rotation".to_string()],
                    audit_frequency: Duration::days(30),
                }
            ],
            notification_config: NotificationConfig {
                enabled: true,
                notification_channels: vec![NotificationChannel::Email("admin@example.com".to_string())],
                events_to_notify: vec![LifecycleEventType::KeyRotated, LifecycleEventType::KeyRevoked],
                escalation_rules: vec![],
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            enabled: true,
        };

        lifecycle_manager.create_lifecycle_policy(policy).await?;

        // Verify policy was created
        let policies = lifecycle_manager.lifecycle_policies.read().await;
        assert!(policies.contains_key("test-policy"));

        Ok(())
    }
}