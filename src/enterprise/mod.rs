//! Enterprise integration and workflow capabilities
//! 
//! This module provides comprehensive enterprise integration including:
//! - LDAP/Active Directory integration for user management
//! - Single Sign-On (SSO) with SAML, OAuth, and OpenID Connect
//! - Workflow automation and approval processes  
//! - Enterprise messaging and notification systems
//! - Business intelligence and reporting
//! - Integration with enterprise systems (ERP, CRM, etc.)

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

pub mod directory;
pub mod sso;
pub mod workflows;
pub mod messaging;
pub mod reporting;
pub mod integrations;

pub use directory::{
    DirectoryService, LdapConfig, ActiveDirectoryConfig, DirectoryUser, DirectoryGroup,
    DirectoryError, UserSyncConfig, GroupMapping
};

pub use sso::{
    SingleSignOnService, SamlConfig, OAuthConfig, OpenIdConnectConfig,
    SsoProvider, SsoSession, SsoError
};

pub use workflows::{
    WorkflowEngine, Workflow, WorkflowStep, ApprovalProcess, WorkflowInstance,
    WorkflowStatus, WorkflowError
};

pub use messaging::{
    MessagingService, MessageTemplate, NotificationChannel, MessagingProvider,
    MessagingError, MessagePriority
};

pub use reporting::{
    ReportingService, Report, ReportTemplate, ReportSchedule, Dashboard,
    ReportingError, ChartType
};

pub use integrations::{
    IntegrationService, SystemIntegration, ApiConnector, DataSync,
    IntegrationError, ConnectorType
};

/// Unified enterprise service providing all integration capabilities
#[derive(Clone)]
pub struct EnterpriseService {
    directory_service: Arc<DirectoryService>,
    sso_service: Arc<SingleSignOnService>,
    workflow_engine: Arc<WorkflowEngine>,
    messaging_service: Arc<MessagingService>,
    reporting_service: Arc<ReportingService>,
    integration_service: Arc<IntegrationService>,
    config: EnterpriseConfig,
    service_state: Arc<RwLock<ServiceState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseConfig {
    pub directory_config: DirectoryServiceConfig,
    pub sso_config: SsoServiceConfig,
    pub workflow_config: WorkflowConfig,
    pub messaging_config: MessagingConfig,
    pub reporting_config: ReportingConfig,
    pub integration_config: IntegrationConfig,
    pub enterprise_settings: EnterpriseSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryServiceConfig {
    pub ldap_config: Option<LdapConfig>,
    pub active_directory_config: Option<ActiveDirectoryConfig>,
    pub user_sync_enabled: bool,
    pub group_sync_enabled: bool,
    pub sync_interval_hours: u32,
    pub user_sync_config: UserSyncConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoServiceConfig {
    pub enabled: bool,
    pub saml_providers: Vec<SamlConfig>,
    pub oauth_providers: Vec<OAuthConfig>,
    pub oidc_providers: Vec<OpenIdConnectConfig>,
    pub default_provider: Option<String>,
    pub session_timeout_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowConfig {
    pub enabled: bool,
    pub max_concurrent_workflows: u32,
    pub default_timeout_hours: u32,
    pub approval_timeout_hours: u32,
    pub notification_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingConfig {
    pub providers: Vec<MessagingProvider>,
    pub default_provider: String,
    pub rate_limiting: RateLimitConfig,
    pub template_storage_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    pub enabled: bool,
    pub storage_path: String,
    pub max_report_size_mb: u64,
    pub retention_days: u32,
    pub scheduled_reports_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub enabled: bool,
    pub max_connections: u32,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
    pub health_check_interval_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseSettings {
    pub organization_name: String,
    pub organization_domain: String,
    pub time_zone: String,
    pub business_hours: BusinessHours,
    pub localization: LocalizationSettings,
    pub branding: BrandingSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessHours {
    pub start_time: String,
    pub end_time: String,
    pub working_days: Vec<u8>, // 0-6, Sunday = 0
    pub holidays: Vec<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalizationSettings {
    pub default_locale: String,
    pub supported_locales: Vec<String>,
    pub date_format: String,
    pub time_format: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandingSettings {
    pub logo_url: Option<String>,
    pub primary_color: String,
    pub secondary_color: String,
    pub custom_css: Option<String>,
    pub favicon_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_limit: u32,
}

#[derive(Debug, Clone)]
struct ServiceState {
    started_at: DateTime<Utc>,
    is_running: bool,
    directory_connected: bool,
    sso_active_sessions: u64,
    workflows_running: u64,
    messages_sent_today: u64,
    reports_generated: u64,
    integrations_active: u64,
}

impl EnterpriseService {
    /// Create a new enterprise service with all components initialized
    pub async fn new(config: EnterpriseConfig) -> Result<Self, EnterpriseError> {
        // Initialize directory service
        let directory_service = Arc::new(
            DirectoryService::new(config.directory_config.clone()).await?
        );
        
        // Initialize SSO service
        let sso_service = Arc::new(
            SingleSignOnService::new(config.sso_config.clone()).await?
        );
        
        // Initialize workflow engine
        let workflow_engine = Arc::new(
            WorkflowEngine::new(config.workflow_config.clone()).await?
        );
        
        // Initialize messaging service
        let messaging_service = Arc::new(
            MessagingService::new(config.messaging_config.clone()).await?
        );
        
        // Initialize reporting service
        let reporting_service = Arc::new(
            ReportingService::new(config.reporting_config.clone()).await?
        );
        
        // Initialize integration service
        let integration_service = Arc::new(
            IntegrationService::new(config.integration_config.clone()).await?
        );

        let service_state = Arc::new(RwLock::new(ServiceState {
            started_at: Utc::now(),
            is_running: false,
            directory_connected: false,
            sso_active_sessions: 0,
            workflows_running: 0,
            messages_sent_today: 0,
            reports_generated: 0,
            integrations_active: 0,
        }));

        Ok(Self {
            directory_service,
            sso_service,
            workflow_engine,
            messaging_service,
            reporting_service,
            integration_service,
            config,
            service_state,
        })
    }

    /// Start all enterprise services
    pub async fn start(&self) -> Result<(), EnterpriseError> {
        let mut state = self.service_state.write().await;
        
        if state.is_running {
            return Err(EnterpriseError::ServiceAlreadyRunning);
        }

        // Start individual services
        self.directory_service.start().await?;
        self.sso_service.start().await?;
        self.workflow_engine.start().await?;
        self.messaging_service.start().await?;
        self.reporting_service.start().await?;
        self.integration_service.start().await?;

        // Update service state
        state.is_running = true;
        state.started_at = Utc::now();
        state.directory_connected = self.directory_service.is_connected().await?;
        state.integrations_active = self.integration_service.get_active_connections().await?;

        log::info!("Enterprise service started successfully");
        Ok(())
    }

    /// Stop all enterprise services gracefully
    pub async fn stop(&self) -> Result<(), EnterpriseError> {
        let mut state = self.service_state.write().await;
        
        if !state.is_running {
            return Ok(());
        }

        // Stop individual services in reverse order
        self.integration_service.stop().await?;
        self.reporting_service.stop().await?;
        self.messaging_service.stop().await?;
        self.workflow_engine.stop().await?;
        self.sso_service.stop().await?;
        self.directory_service.stop().await?;
        
        state.is_running = false;

        log::info!("Enterprise service stopped successfully");
        Ok(())
    }

    /// Get comprehensive enterprise service status
    pub async fn get_service_status(&self) -> Result<EnterpriseStatus, EnterpriseError> {
        let state = self.service_state.read().await;
        let uptime = Utc::now().signed_duration_since(state.started_at);

        // Get status from individual services
        let directory_status = self.directory_service.get_status().await?;
        let sso_status = self.sso_service.get_status().await?;
        let workflow_status = self.workflow_engine.get_status().await?;
        let messaging_status = self.messaging_service.get_status().await?;
        let reporting_status = self.reporting_service.get_status().await?;
        let integration_status = self.integration_service.get_status().await?;

        Ok(EnterpriseStatus {
            is_running: state.is_running,
            uptime_seconds: uptime.num_seconds() as u64,
            directory_status,
            sso_status,
            workflow_status,
            messaging_status,
            reporting_status,
            integration_status,
            overall_health: self.calculate_overall_health(&state).await,
        })
    }

    /// Sync users and groups from directory service
    pub async fn sync_directory(&self) -> Result<DirectorySyncResult, EnterpriseError> {
        if !self.config.directory_config.user_sync_enabled && !self.config.directory_config.group_sync_enabled {
            return Err(EnterpriseError::SyncDisabled);
        }

        let result = self.directory_service.sync_all().await?;
        
        // Update service state
        let mut state = self.service_state.write().await;
        state.directory_connected = true;

        log::info!("Directory sync completed: {} users, {} groups", 
            result.users_synced, result.groups_synced);

        Ok(result)
    }

    /// Initiate SSO authentication
    pub async fn initiate_sso_auth(&self, provider_id: &str, return_url: &str) -> Result<SsoAuthRequest, EnterpriseError> {
        if !self.config.sso_config.enabled {
            return Err(EnterpriseError::SsoDisabled);
        }

        let auth_request = self.sso_service.initiate_auth(provider_id, return_url).await?;
        
        let mut state = self.service_state.write().await;
        state.sso_active_sessions += 1;

        Ok(auth_request)
    }

    /// Start a new workflow instance
    pub async fn start_workflow(&self, workflow_id: &str, initiator: &str, data: HashMap<String, serde_json::Value>) -> Result<WorkflowInstance, EnterpriseError> {
        if !self.config.workflow_config.enabled {
            return Err(EnterpriseError::WorkflowsDisabled);
        }

        let instance = self.workflow_engine.start_workflow(workflow_id, initiator, data).await?;
        
        let mut state = self.service_state.write().await;
        state.workflows_running += 1;

        log::info!("Started workflow instance: {}", instance.id);
        Ok(instance)
    }

    /// Send enterprise notification
    pub async fn send_notification(&self, template_id: &str, recipients: Vec<String>, data: HashMap<String, String>) -> Result<MessageDeliveryStatus, EnterpriseError> {
        let status = self.messaging_service.send_templated_message(template_id, recipients, data).await?;
        
        let mut state = self.service_state.write().await;
        state.messages_sent_today += 1;

        Ok(status)
    }

    /// Generate enterprise report
    pub async fn generate_report(&self, report_id: &str, parameters: HashMap<String, String>) -> Result<ReportResult, EnterpriseError> {
        if !self.config.reporting_config.enabled {
            return Err(EnterpriseError::ReportingDisabled);
        }

        let report = self.reporting_service.generate_report(report_id, parameters).await?;
        
        let mut state = self.service_state.write().await;
        state.reports_generated += 1;

        Ok(report)
    }

    // Private helper methods

    async fn calculate_overall_health(&self, _state: &ServiceState) -> HealthStatus {
        // Calculate overall health based on individual service statuses
        // This would consider factors like:
        // - Directory connectivity
        // - SSO provider availability  
        // - Workflow engine performance
        // - Message delivery rates
        // - Integration health

        HealthStatus::Healthy // Placeholder
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseStatus {
    pub is_running: bool,
    pub uptime_seconds: u64,
    pub directory_status: DirectoryServiceStatus,
    pub sso_status: SsoServiceStatus,
    pub workflow_status: WorkflowEngineStatus,
    pub messaging_status: MessagingServiceStatus,
    pub reporting_status: ReportingServiceStatus,
    pub integration_status: IntegrationServiceStatus,
    pub overall_health: HealthStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryServiceStatus {
    pub connected: bool,
    pub last_sync: Option<DateTime<Utc>>,
    pub total_users: u64,
    pub total_groups: u64,
    pub sync_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoServiceStatus {
    pub enabled: bool,
    pub active_sessions: u64,
    pub provider_count: u64,
    pub authentication_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEngineStatus {
    pub enabled: bool,
    pub running_workflows: u64,
    pub completed_today: u64,
    pub average_completion_time_minutes: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingServiceStatus {
    pub messages_sent_today: u64,
    pub delivery_rate: f64,
    pub provider_count: u64,
    pub queue_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingServiceStatus {
    pub enabled: bool,
    pub reports_generated: u64,
    pub scheduled_reports_active: u64,
    pub storage_used_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationServiceStatus {
    pub active_connections: u64,
    pub total_integrations: u64,
    pub data_sync_rate: f64,
    pub health_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectorySyncResult {
    pub users_synced: u64,
    pub groups_synced: u64,
    pub errors: Vec<String>,
    pub duration_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoAuthRequest {
    pub provider_id: String,
    pub auth_url: String,
    pub state: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDeliveryStatus {
    pub message_id: String,
    pub sent_count: u64,
    pub failed_count: u64,
    pub delivery_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportResult {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub file_path: String,
    pub size_bytes: u64,
    pub format: String,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            directory_config: DirectoryServiceConfig::default(),
            sso_config: SsoServiceConfig::default(),
            workflow_config: WorkflowConfig::default(),
            messaging_config: MessagingConfig::default(),
            reporting_config: ReportingConfig::default(),
            integration_config: IntegrationConfig::default(),
            enterprise_settings: EnterpriseSettings::default(),
        }
    }
}

impl Default for DirectoryServiceConfig {
    fn default() -> Self {
        Self {
            ldap_config: None,
            active_directory_config: None,
            user_sync_enabled: false,
            group_sync_enabled: false,
            sync_interval_hours: 24,
            user_sync_config: UserSyncConfig::default(),
        }
    }
}

impl Default for SsoServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            saml_providers: Vec::new(),
            oauth_providers: Vec::new(),
            oidc_providers: Vec::new(),
            default_provider: None,
            session_timeout_minutes: 480,
        }
    }
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_concurrent_workflows: 1000,
            default_timeout_hours: 24,
            approval_timeout_hours: 72,
            notification_enabled: true,
        }
    }
}

impl Default for MessagingConfig {
    fn default() -> Self {
        Self {
            providers: Vec::new(),
            default_provider: "smtp".to_string(),
            rate_limiting: RateLimitConfig::default(),
            template_storage_path: "./templates".to_string(),
        }
    }
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            storage_path: "./reports".to_string(),
            max_report_size_mb: 100,
            retention_days: 90,
            scheduled_reports_enabled: true,
        }
    }
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_connections: 50,
            timeout_seconds: 30,
            retry_attempts: 3,
            health_check_interval_minutes: 5,
        }
    }
}

impl Default for EnterpriseSettings {
    fn default() -> Self {
        Self {
            organization_name: "n0n Enterprise".to_string(),
            organization_domain: "enterprise.local".to_string(),
            time_zone: "UTC".to_string(),
            business_hours: BusinessHours::default(),
            localization: LocalizationSettings::default(),
            branding: BrandingSettings::default(),
        }
    }
}

impl Default for BusinessHours {
    fn default() -> Self {
        Self {
            start_time: "09:00".to_string(),
            end_time: "17:00".to_string(),
            working_days: vec![1, 2, 3, 4, 5], // Monday to Friday
            holidays: Vec::new(),
        }
    }
}

impl Default for LocalizationSettings {
    fn default() -> Self {
        Self {
            default_locale: "en-US".to_string(),
            supported_locales: vec!["en-US".to_string(), "en-GB".to_string()],
            date_format: "YYYY-MM-DD".to_string(),
            time_format: "HH:mm:ss".to_string(),
            currency: "USD".to_string(),
        }
    }
}

impl Default for BrandingSettings {
    fn default() -> Self {
        Self {
            logo_url: None,
            primary_color: "#007acc".to_string(),
            secondary_color: "#f5f5f5".to_string(),
            custom_css: None,
            favicon_url: None,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 60,
            requests_per_hour: 1000,
            burst_limit: 10,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnterpriseError {
    #[error("Directory service error: {0}")]
    Directory(#[from] DirectoryError),
    
    #[error("SSO service error: {0}")]
    Sso(#[from] SsoError),
    
    #[error("Workflow error: {0}")]
    Workflow(#[from] WorkflowError),
    
    #[error("Messaging error: {0}")]
    Messaging(#[from] MessagingError),
    
    #[error("Reporting error: {0}")]
    Reporting(#[from] ReportingError),
    
    #[error("Integration error: {0}")]
    Integration(#[from] IntegrationError),
    
    #[error("Service already running")]
    ServiceAlreadyRunning,
    
    #[error("Service not running")]
    ServiceNotRunning,
    
    #[error("Directory sync is disabled")]
    SyncDisabled,
    
    #[error("SSO is disabled")]
    SsoDisabled,
    
    #[error("Workflows are disabled")]
    WorkflowsDisabled,
    
    #[error("Reporting is disabled")]
    ReportingDisabled,
    
    #[error("Configuration error: {0}")]
    Configuration(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enterprise_service_lifecycle() {
        let config = EnterpriseConfig::default();
        let service = EnterpriseService::new(config).await.unwrap();
        
        // Test service start
        service.start().await.unwrap();
        
        // Test service status
        let status = service.get_service_status().await.unwrap();
        assert!(status.is_running);
        
        // Test service stop
        service.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_enterprise_config_defaults() {
        let config = EnterpriseConfig::default();
        
        assert_eq!(config.enterprise_settings.organization_name, "n0n Enterprise");
        assert_eq!(config.enterprise_settings.time_zone, "UTC");
        assert!(!config.sso_config.enabled);
        assert!(config.workflow_config.enabled);
        assert!(config.reporting_config.enabled);
    }
}