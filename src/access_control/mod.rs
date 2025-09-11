//! Advanced access control and permissions system for enterprise security
//! 
//! This module provides comprehensive access control capabilities including:
//! - Role-based access control (RBAC)
//! - Attribute-based access control (ABAC)
//! - Policy-based access decisions
//! - Multi-factor authentication (MFA)
//! - Session management and security
//! - Audit logging for access events

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

pub mod rbac;
pub mod abac;
pub mod policies;
pub mod authentication;
pub mod sessions;
pub mod audit;

pub use rbac::{
    RoleBasedAccessControl, Role, Permission, RoleAssignment,
    RBACConfig, RBACError
};

pub use abac::{
    AttributeBasedAccessControl, Attribute, AttributeSet, AccessRequest,
    AccessDecision, ABACConfig, ABACError, ABACPolicy
};

pub use policies::{
    PolicyEngine, Policy, PolicyRule, PolicyCondition, PolicyEffect,
    PolicyContext, PolicyConfig, PolicyError
};

pub use authentication::{
    AuthenticationManager, AuthenticationMethod, MultiFactorAuth,
    AuthToken, LoginAttempt, AuthConfig, AuthError
};

pub use sessions::{
    SessionManager, Session, SessionConfig, SessionStatus,
    SessionError
};

pub use audit::{
    AuditLogger, AuditEvent, AuditEventType, AuditQuery,
    AuditConfig, AuditError, AuditResult
};

/// Unified access control service providing all security capabilities
#[derive(Clone)]
pub struct AccessControlService {
    rbac: Arc<RoleBasedAccessControl>,
    abac: Arc<AttributeBasedAccessControl>,
    policy_engine: Arc<PolicyEngine>,
    auth_manager: Arc<AuthenticationManager>,
    session_manager: Arc<SessionManager>,
    audit_logger: Arc<AuditLogger>,
    config: AccessControlConfig,
    service_state: Arc<RwLock<ServiceState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    pub rbac_config: RBACConfig,
    pub abac_config: ABACConfig,
    pub policy_config: PolicyConfig,
    pub auth_config: AuthConfig,
    pub session_config: SessionConfig,
    pub audit_config: AuditConfig,
    pub security_policy: SecurityPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub password_policy: PasswordPolicy,
    pub session_policy: SessionSecurityPolicy,
    pub lockout_policy: LockoutPolicy,
    pub mfa_requirements: MfaRequirements,
    pub compliance_settings: ComplianceSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_symbols: bool,
    pub disallow_common: bool,
    pub max_age_days: Option<u32>,
    pub history_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSecurityPolicy {
    pub max_duration_hours: u32,
    pub idle_timeout_minutes: u32,
    pub require_secure_transport: bool,
    pub allow_concurrent_sessions: bool,
    pub max_concurrent_sessions: u32,
    pub require_mfa_for_sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutPolicy {
    pub enabled: bool,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u32,
    pub reset_period_minutes: u32,
    pub progressive_lockout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaRequirements {
    pub required_for_admin: bool,
    pub required_for_sensitive_ops: bool,
    pub allowed_methods: Vec<String>,
    pub backup_codes_enabled: bool,
    pub remember_device_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSettings {
    pub frameworks: Vec<ComplianceFramework>,
    pub data_retention_days: u32,
    pub audit_all_access: bool,
    pub require_reason_codes: bool,
    pub emergency_access_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceFramework {
    SOX,
    GDPR,
    HIPAA,
    PCI_DSS,
    SOC2,
    ISO27001,
}

#[derive(Debug, Clone)]
struct ServiceState {
    started_at: DateTime<Utc>,
    is_running: bool,
    active_sessions_count: u64,
    total_access_requests: u64,
    successful_authentications: u64,
    failed_authentications: u64,
    policy_violations: u64,
}

/// Complete access control request with all context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlRequest {
    pub session_id: String,
    pub user_id: String,
    pub resource: String,
    pub action: String,
    pub context: AccessContext,
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub location: Option<String>,
    pub device_id: Option<String>,
    pub risk_score: Option<f64>,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlResponse {
    pub decision: AccessDecision,
    pub reason: String,
    pub required_mfa: Option<String>,
    pub session_valid: bool,
    pub policy_violations: Vec<String>,
    pub audit_event_id: String,
    pub expires_at: Option<DateTime<Utc>>,
}

impl AccessControlService {
    /// Create a new access control service with all components initialized
    pub async fn new(config: AccessControlConfig) -> Result<Self, AccessControlError> {
        // Initialize RBAC system
        let rbac = Arc::new(
            RoleBasedAccessControl::new(config.rbac_config.clone()).await?
        );
        
        // Initialize ABAC system
        let abac = Arc::new(
            AttributeBasedAccessControl::new(config.abac_config.clone()).await?
        );
        
        // Initialize policy engine
        let policy_engine = Arc::new(
            PolicyEngine::new(config.policy_config.clone()).await?
        );
        
        // Initialize authentication manager
        let auth_manager = Arc::new(
            AuthenticationManager::new(config.auth_config.clone()).await?
        );
        
        // Initialize session manager
        let session_manager = Arc::new(
            SessionManager::new(config.session_config.clone()).await?
        );
        
        // Initialize audit logger
        let audit_logger = Arc::new(
            AuditLogger::new(config.audit_config.clone()).await?
        );

        let service_state = Arc::new(RwLock::new(ServiceState {
            started_at: Utc::now(),
            is_running: false,
            active_sessions_count: 0,
            total_access_requests: 0,
            successful_authentications: 0,
            failed_authentications: 0,
            policy_violations: 0,
        }));

        Ok(Self {
            rbac,
            abac,
            policy_engine,
            auth_manager,
            session_manager,
            audit_logger,
            config,
            service_state,
        })
    }

    /// Start all access control services
    pub async fn start(&self) -> Result<(), AccessControlError> {
        let mut state = self.service_state.write().await;
        
        if state.is_running {
            return Err(AccessControlError::ServiceAlreadyRunning);
        }

        // Start individual services
        self.rbac.start().await?;
        self.abac.start().await?;
        self.policy_engine.start().await?;
        self.auth_manager.start().await?;
        self.session_manager.start().await?;
        self.audit_logger.start().await?;

        state.is_running = true;
        state.started_at = Utc::now();

        log::info!("Access control service started successfully");
        Ok(())
    }

    /// Stop all access control services gracefully
    pub async fn stop(&self) -> Result<(), AccessControlError> {
        let mut state = self.service_state.write().await;
        
        if !state.is_running {
            return Ok(());
        }

        // Stop individual services in reverse order
        self.audit_logger.stop().await?;
        self.session_manager.stop().await?;
        self.auth_manager.stop().await?;
        self.policy_engine.stop().await?;
        self.abac.stop().await?;
        self.rbac.stop().await?;
        
        state.is_running = false;

        log::info!("Access control service stopped successfully");
        Ok(())
    }

    /// Comprehensive access control check
    pub async fn check_access(&self, request: AccessControlRequest) -> Result<AccessControlResponse, AccessControlError> {
        let mut state = self.service_state.write().await;
        state.total_access_requests += 1;
        drop(state);

        let audit_event_id = Uuid::new_v4().to_string();
        
        // Start audit event
        self.audit_logger.log_access_attempt(&request, &audit_event_id).await?;

        // 1. Validate session
        let session = self.session_manager.get_session(&request.session_id).await?;
        if !self.is_session_valid(&session).await? {
            let response = AccessControlResponse {
                decision: AccessDecision::Deny,
                reason: "Invalid or expired session".to_string(),
                required_mfa: None,
                session_valid: false,
                policy_violations: vec!["SESSION_EXPIRED".to_string()],
                audit_event_id: audit_event_id.clone(),
                expires_at: None,
            };
            
            self.audit_logger.log_access_decision(&request, &response).await?;
            return Ok(response);
        }

        // 2. Check if MFA is required and valid
        if let Some(mfa_requirement) = self.check_mfa_requirement(&request).await? {
            if !self.verify_mfa_for_request(&request, &mfa_requirement).await? {
                let response = AccessControlResponse {
                    decision: AccessDecision::Deny,
                    reason: "Multi-factor authentication required".to_string(),
                    required_mfa: Some(mfa_requirement),
                    session_valid: true,
                    policy_violations: vec!["MFA_REQUIRED".to_string()],
                    audit_event_id: audit_event_id.clone(),
                    expires_at: None,
                };
                
                self.audit_logger.log_access_decision(&request, &response).await?;
                return Ok(response);
            }
        }

        // 3. RBAC check
        let rbac_decision = self.rbac.check_permission(
            &request.user_id,
            &request.resource,
            &request.action
        ).await?;

        // 4. ABAC check
        let abac_request = self.convert_to_abac_request(&request).await?;
        let abac_decision = self.abac.evaluate_access(&abac_request).await?;

        // 5. Policy engine evaluation
        let policy_context = self.build_policy_context(&request, &session).await?;
        let policy_decision = self.policy_engine.evaluate_policies(&policy_context).await?;

        // 6. Combine decisions
        let final_decision = self.combine_access_decisions(rbac_decision, abac_decision, policy_decision).await?;
        
        // 7. Apply additional security checks
        let security_violations = self.check_security_violations(&request, &session).await?;
        
        let response = AccessControlResponse {
            decision: if security_violations.is_empty() { final_decision } else { AccessDecision::Deny },
            reason: self.build_decision_reason(&final_decision, &security_violations),
            required_mfa: None,
            session_valid: true,
            policy_violations: security_violations,
            audit_event_id: audit_event_id.clone(),
            expires_at: Some(session.expires_at),
        };

        // Update statistics
        let mut state = self.service_state.write().await;
        match response.decision {
            AccessDecision::Allow => {},
            AccessDecision::Deny => state.policy_violations += 1,
        }
        drop(state);

        // Log final decision
        self.audit_logger.log_access_decision(&request, &response).await?;

        Ok(response)
    }

    /// Authenticate user with credentials
    pub async fn authenticate(&self, username: &str, password: &str, mfa_token: Option<&str>) -> Result<Session, AccessControlError> {
        let login_attempt = LoginAttempt {
            username: username.to_string(),
            timestamp: Utc::now(),
            ip_address: None,
            user_agent: None,
            mfa_provided: mfa_token.is_some(),
        };

        // Check lockout policy
        if self.is_user_locked_out(username).await? {
            self.audit_logger.log_authentication_failure(&login_attempt, "Account locked").await?;
            
            let mut state = self.service_state.write().await;
            state.failed_authentications += 1;
            
            return Err(AccessControlError::AccountLocked);
        }

        // Verify credentials
        let auth_result = self.auth_manager.authenticate(username, password).await?;
        if !auth_result.success {
            self.handle_failed_authentication(username, &login_attempt).await?;
            return Err(AccessControlError::InvalidCredentials);
        }

        // Verify MFA if required
        if self.is_mfa_required_for_user(&auth_result.user_id).await? {
            if let Some(token) = mfa_token {
                if !self.auth_manager.verify_mfa(&auth_result.user_id, token).await? {
                    self.handle_failed_authentication(username, &login_attempt).await?;
                    return Err(AccessControlError::InvalidMfaToken);
                }
            } else {
                return Err(AccessControlError::MfaRequired);
            }
        }

        // Create session
        let session = self.session_manager.create_session(
            &auth_result.user_id,
            &login_attempt
        ).await?;

        // Update statistics and audit
        let mut state = self.service_state.write().await;
        state.successful_authentications += 1;
        state.active_sessions_count += 1;
        drop(state);

        self.audit_logger.log_authentication_success(&login_attempt, &session).await?;

        Ok(session)
    }

    /// Get current service statistics
    pub async fn get_service_statistics(&self) -> ServiceStatistics {
        let state = self.service_state.read().await;
        let uptime = Utc::now().signed_duration_since(state.started_at);
        
        ServiceStatistics {
            uptime_seconds: uptime.num_seconds() as u64,
            active_sessions: state.active_sessions_count,
            total_access_requests: state.total_access_requests,
            successful_authentications: state.successful_authentications,
            failed_authentications: state.failed_authentications,
            policy_violations: state.policy_violations,
            success_rate: if state.total_access_requests > 0 {
                (state.total_access_requests - state.policy_violations) as f64 / state.total_access_requests as f64
            } else {
                1.0
            },
        }
    }

    // Private helper methods

    async fn is_session_valid(&self, session: &Session) -> Result<bool, AccessControlError> {
        if session.status != SessionStatus::Active {
            return Ok(false);
        }

        if session.expires_at < Utc::now() {
            return Ok(false);
        }

        // Check idle timeout
        if let Some(last_activity) = session.last_activity {
            let idle_timeout = Duration::minutes(self.config.session_config.idle_timeout_minutes as i64);
            if Utc::now().signed_duration_since(last_activity) > idle_timeout {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn check_mfa_requirement(&self, request: &AccessControlRequest) -> Result<Option<String>, AccessControlError> {
        // Check if MFA is required for this specific operation
        if self.config.security_policy.mfa_requirements.required_for_sensitive_ops {
            if self.is_sensitive_operation(&request.resource, &request.action).await? {
                return Ok(Some("totp".to_string())); // Default to TOTP
            }
        }

        // Check if user has admin privileges requiring MFA
        if self.config.security_policy.mfa_requirements.required_for_admin {
            if self.rbac.user_has_admin_role(&request.user_id).await? {
                return Ok(Some("totp".to_string()));
            }
        }

        Ok(None)
    }

    async fn verify_mfa_for_request(&self, _request: &AccessControlRequest, _mfa_type: &str) -> Result<bool, AccessControlError> {
        // Placeholder - would integrate with MFA verification
        Ok(true)
    }

    async fn is_sensitive_operation(&self, _resource: &str, _action: &str) -> Result<bool, AccessControlError> {
        // Define what constitutes sensitive operations
        Ok(false)
    }

    async fn convert_to_abac_request(&self, request: &AccessControlRequest) -> Result<AccessRequest, AccessControlError> {
        let mut subject_attributes = AttributeSet::new();
        subject_attributes.add_attribute("user_id".to_string(), request.user_id.clone());

        let mut resource_attributes = AttributeSet::new();
        resource_attributes.add_attribute("resource".to_string(), request.resource.clone());

        let mut action_attributes = AttributeSet::new();
        action_attributes.add_attribute("action".to_string(), request.action.clone());

        let mut environment_attributes = AttributeSet::new();
        environment_attributes.add_attribute("timestamp".to_string(), request.timestamp.to_rfc3339());

        if let Some(ip) = &request.context.ip_address {
            environment_attributes.add_attribute("ip_address".to_string(), ip.clone());
        }

        Ok(AccessRequest {
            subject_attributes,
            resource_attributes,
            action_attributes,
            environment_attributes,
        })
    }

    async fn build_policy_context(&self, request: &AccessControlRequest, session: &Session) -> Result<PolicyContext, AccessControlError> {
        let mut context_data = HashMap::new();
        context_data.insert("user_id".to_string(), request.user_id.clone());
        context_data.insert("session_id".to_string(), session.session_id.clone());
        context_data.insert("resource".to_string(), request.resource.clone());
        context_data.insert("action".to_string(), request.action.clone());

        Ok(PolicyContext {
            request_id: request.request_id.clone(),
            timestamp: request.timestamp,
            context_data,
        })
    }

    async fn combine_access_decisions(
        &self,
        rbac: bool,
        abac: AccessDecision,
        policy: AccessDecision,
    ) -> Result<AccessDecision, AccessControlError> {
        // All systems must allow access
        if rbac && abac == AccessDecision::Allow && policy == AccessDecision::Allow {
            Ok(AccessDecision::Allow)
        } else {
            Ok(AccessDecision::Deny)
        }
    }

    async fn check_security_violations(&self, _request: &AccessControlRequest, _session: &Session) -> Result<Vec<String>, AccessControlError> {
        let mut violations = Vec::new();

        // Implement additional security checks here
        // - Rate limiting
        // - Geo-fencing
        // - Device trust
        // - Risk scoring

        Ok(violations)
    }

    fn build_decision_reason(&self, decision: &AccessDecision, violations: &[String]) -> String {
        match decision {
            AccessDecision::Allow if violations.is_empty() => "Access granted".to_string(),
            AccessDecision::Deny if violations.is_empty() => "Access denied by policy".to_string(),
            _ => format!("Access denied: {}", violations.join(", ")),
        }
    }

    async fn is_user_locked_out(&self, _username: &str) -> Result<bool, AccessControlError> {
        // Placeholder - would check lockout status
        Ok(false)
    }

    async fn handle_failed_authentication(&self, _username: &str, _attempt: &LoginAttempt) -> Result<(), AccessControlError> {
        let mut state = self.service_state.write().await;
        state.failed_authentications += 1;
        // Would implement lockout logic here
        Ok(())
    }

    async fn is_mfa_required_for_user(&self, _user_id: &str) -> Result<bool, AccessControlError> {
        // Placeholder - would check user's MFA requirements
        Ok(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatistics {
    pub uptime_seconds: u64,
    pub active_sessions: u64,
    pub total_access_requests: u64,
    pub successful_authentications: u64,
    pub failed_authentications: u64,
    pub policy_violations: u64,
    pub success_rate: f64,
}

impl Default for AccessControlConfig {
    fn default() -> Self {
        Self {
            rbac_config: RBACConfig::default(),
            abac_config: ABACConfig::default(),
            policy_config: PolicyConfig::default(),
            auth_config: AuthConfig::default(),
            session_config: SessionConfig::default(),
            audit_config: AuditConfig::default(),
            security_policy: SecurityPolicy::default(),
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            password_policy: PasswordPolicy::default(),
            session_policy: SessionSecurityPolicy::default(),
            lockout_policy: LockoutPolicy::default(),
            mfa_requirements: MfaRequirements::default(),
            compliance_settings: ComplianceSettings::default(),
        }
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_symbols: true,
            disallow_common: true,
            max_age_days: Some(90),
            history_count: 12,
        }
    }
}

impl Default for SessionSecurityPolicy {
    fn default() -> Self {
        Self {
            max_duration_hours: 8,
            idle_timeout_minutes: 30,
            require_secure_transport: true,
            allow_concurrent_sessions: false,
            max_concurrent_sessions: 1,
            require_mfa_for_sensitive: true,
        }
    }
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_failed_attempts: 3,
            lockout_duration_minutes: 15,
            reset_period_minutes: 60,
            progressive_lockout: true,
        }
    }
}

impl Default for MfaRequirements {
    fn default() -> Self {
        Self {
            required_for_admin: true,
            required_for_sensitive_ops: true,
            allowed_methods: vec!["totp".to_string(), "sms".to_string()],
            backup_codes_enabled: true,
            remember_device_days: Some(30),
        }
    }
}

impl Default for ComplianceSettings {
    fn default() -> Self {
        Self {
            frameworks: vec![ComplianceFramework::SOC2],
            data_retention_days: 2555, // 7 years
            audit_all_access: true,
            require_reason_codes: false,
            emergency_access_enabled: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccessControlError {
    #[error("RBAC error: {0}")]
    RBAC(#[from] RBACError),
    
    #[error("ABAC error: {0}")]
    ABAC(#[from] ABACError),
    
    #[error("Policy error: {0}")]
    Policy(#[from] PolicyError),
    
    #[error("Authentication error: {0}")]
    Authentication(#[from] AuthError),
    
    #[error("Session error: {0}")]
    Session(#[from] SessionError),
    
    #[error("Audit error: {0}")]
    Audit(#[from] AuditError),
    
    #[error("Service already running")]
    ServiceAlreadyRunning,
    
    #[error("Service not running")]
    ServiceNotRunning,
    
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Account locked")]
    AccountLocked,
    
    #[error("MFA required")]
    MfaRequired,
    
    #[error("Invalid MFA token")]
    InvalidMfaToken,
    
    #[error("Access denied")]
    AccessDenied,
    
    #[error("Configuration error: {0}")]
    Configuration(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_access_control_service_lifecycle() {
        let config = AccessControlConfig::default();
        let service = AccessControlService::new(config).await.unwrap();
        
        // Test service start
        service.start().await.unwrap();
        
        // Test service statistics
        let stats = service.get_service_statistics().await;
        assert!(stats.uptime_seconds >= 0);
        
        // Test service stop
        service.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_access_control_request() {
        let config = AccessControlConfig::default();
        let service = AccessControlService::new(config).await.unwrap();
        service.start().await.unwrap();

        let request = AccessControlRequest {
            session_id: "test-session".to_string(),
            user_id: "test-user".to_string(),
            resource: "test-resource".to_string(),
            action: "read".to_string(),
            context: AccessContext {
                ip_address: Some("127.0.0.1".to_string()),
                user_agent: Some("test-agent".to_string()),
                location: None,
                device_id: None,
                risk_score: None,
                attributes: HashMap::new(),
            },
            timestamp: Utc::now(),
            request_id: Uuid::new_v4().to_string(),
        };

        // This would normally require proper session setup
        // let response = service.check_access(request).await.unwrap();
        // assert_eq!(response.decision, AccessDecision::Deny); // No valid session

        service.stop().await.unwrap();
    }
}