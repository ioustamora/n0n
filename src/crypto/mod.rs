//! Comprehensive cryptographic module for enterprise-grade secure file sharing
//! 
//! This module provides advanced cryptographic capabilities including:
//! - Enterprise key management systems
//! - Hardware Security Module (HSM) integration
//! - Key lifecycle management and rotation
//! - Certificate-based authentication and PKI
//! - Advanced cryptographic operations (ZKP, homomorphic encryption, MPC)

use std::sync::Arc;
use tokio::sync::RwLock;

pub mod key_management;
pub mod hsm;
pub mod key_lifecycle;
pub mod certificates;
pub mod advanced_ops;
pub mod legacy;

pub use key_management::{
    KeyManagementSystem, KeyManagementError, MasterKey, DataEncryptionKey, KeyEncryptionKey,
    KeyPolicy, KeyAlgorithm, KeyUsage, ComplianceFramework, KeyStoreConfig
};

pub use hsm::{
    HsmProvider, HsmProviderFactory, HsmConfig, HsmError,
    AwsCloudHsmProvider, AzureDedicatedHsmProvider, SafeNetLunaProvider,
    SoftHsmProvider, MockHsmProvider
};

pub use key_lifecycle::{
    KeyLifecycleManager, LifecyclePolicy, LifecycleState, RotationScheduler,
    LifecycleEvent, LifecycleConfig, NotificationSettings
};

pub use certificates::{
    CertificateManager, Certificate, CertificateAuthority, TrustStore,
    CertificatePolicy, CertificateRevocationList, OcspResponder,
    CertificateManagerConfig, CertificateError
};

pub use advanced_ops::{
    AdvancedCryptoOps, AdvancedCryptoConfig, ZkProofSystem, HomomorphicEncryptionSystem,
    MultiPartyComputationSystem, SecureRandomGenerator, CachedOperation,
    KeyDerivationFunction, AuthenticatedEncryption, AdvancedCryptoError
};

// Re-export legacy crypto functions for backward compatibility
pub use legacy::{
    init, generate_keypair, encrypt_chunk, decrypt_chunk, precompute_shared, encrypt_with_nonce,
    PublicKey, SecretKey, PrecomputedKey, NONCEBYTES
};

/// Unified cryptographic service providing all enterprise crypto capabilities
pub struct CryptoService {
    key_management: Arc<KeyManagementSystem>,
    lifecycle_manager: Arc<KeyLifecycleManager>,
    certificate_manager: Arc<CertificateManager>,
    advanced_ops: Arc<AdvancedCryptoOps>,
}

impl CryptoService {
    /// Create a new crypto service with all components initialized
    pub async fn new(
        kms_config: KeyStoreConfig,
        lifecycle_config: LifecycleConfig,
        cert_config: CertificateManagerConfig,
        advanced_config: AdvancedCryptoConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Initialize key management system
        let key_management = Arc::new(KeyManagementSystem::new(kms_config).await?);
        
        // Initialize lifecycle manager
        let lifecycle_manager = Arc::new(
            KeyLifecycleManager::new(key_management.clone(), lifecycle_config).await?
        );
        
        // Initialize certificate manager
        let certificate_manager = Arc::new(CertificateManager::new(cert_config).await?);
        
        // Initialize advanced crypto operations
        let advanced_ops = Arc::new(
            AdvancedCryptoOps::new(
                key_management.clone(),
                certificate_manager.clone(),
                advanced_config,
            ).await?
        );

        Ok(Self {
            key_management,
            lifecycle_manager,
            certificate_manager,
            advanced_ops,
        })
    }

    /// Get reference to key management system
    pub fn key_management(&self) -> &Arc<KeyManagementSystem> {
        &self.key_management
    }

    /// Get reference to lifecycle manager
    pub fn lifecycle_manager(&self) -> &Arc<KeyLifecycleManager> {
        &self.lifecycle_manager
    }

    /// Get reference to certificate manager
    pub fn certificate_manager(&self) -> &Arc<CertificateManager> {
        &self.certificate_manager
    }

    /// Get reference to advanced crypto operations
    pub fn advanced_ops(&self) -> &Arc<AdvancedCryptoOps> {
        &self.advanced_ops
    }

    /// Initialize all background services
    pub async fn start_services(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Start lifecycle management background tasks
        self.lifecycle_manager.start_background_services().await?;
        
        // Start certificate manager background tasks
        self.certificate_manager.start_background_services().await?;
        
        // Start advanced ops caching and cleanup services
        self.advanced_ops.start_background_services().await?;

        Ok(())
    }

    /// Shutdown all services gracefully
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Shutdown in reverse order
        self.advanced_ops.shutdown().await?;
        self.certificate_manager.shutdown().await?;
        self.lifecycle_manager.shutdown().await?;
        self.key_management.shutdown().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_crypto_service_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        let kms_config = KeyStoreConfig {
            storage_path: base_path.join("keys"),
            master_key_algorithm: KeyAlgorithm::Aes256,
            hsm_config: None,
            audit_enabled: true,
            compliance_frameworks: vec![ComplianceFramework::Fips1402Level2],
            cache_ttl: std::time::Duration::from_secs(3600),
            max_cache_size: 1000,
        };

        let lifecycle_config = LifecycleConfig {
            default_key_lifetime: std::time::Duration::from_secs(86400 * 365), // 1 year
            rotation_check_interval: std::time::Duration::from_secs(3600), // 1 hour
            compliance_check_interval: std::time::Duration::from_secs(86400), // 1 day
            notification_settings: NotificationSettings {
                email_notifications: true,
                webhook_url: None,
                slack_webhook: None,
                escalation_rules: Vec::new(),
            },
            audit_retention_days: 2555, // 7 years
        };

        let cert_config = CertificateManagerConfig {
            storage_path: base_path.join("certificates"),
            default_validity_period: std::time::Duration::from_secs(86400 * 365), // 1 year
            crl_update_interval: std::time::Duration::from_secs(86400), // 1 day
            ocsp_responder_timeout: std::time::Duration::from_secs(30),
            certificate_cache_ttl: std::time::Duration::from_secs(3600), // 1 hour
            max_certificate_cache_size: 10000,
            audit_enabled: true,
        };

        let advanced_config = AdvancedCryptoConfig {
            enable_zk_proofs: true,
            enable_homomorphic_encryption: true,
            enable_mpc: true,
            operation_cache_ttl: std::time::Duration::from_secs(1800), // 30 minutes
            max_operation_cache_size: 1000,
            secure_random_entropy_sources: vec!["system".to_string(), "hardware".to_string()],
            performance_monitoring: true,
            audit_all_operations: true,
        };

        let crypto_service = CryptoService::new(
            kms_config,
            lifecycle_config,
            cert_config,
            advanced_config,
        ).await.unwrap();

        // Test that all components are accessible
        assert!(!crypto_service.key_management().is_empty().await);
        assert!(crypto_service.lifecycle_manager().get_active_policies().await.is_empty());
        assert!(crypto_service.certificate_manager().list_certificates().await.unwrap().is_empty());
        assert!(!crypto_service.advanced_ops().is_initialized().await);
    }

    #[tokio::test]
    async fn test_crypto_service_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        // Create minimal configs for testing
        let kms_config = KeyStoreConfig {
            storage_path: base_path.join("keys"),
            master_key_algorithm: KeyAlgorithm::Aes256,
            hsm_config: None,
            audit_enabled: false,
            compliance_frameworks: Vec::new(),
            cache_ttl: std::time::Duration::from_secs(60),
            max_cache_size: 100,
        };

        let lifecycle_config = LifecycleConfig {
            default_key_lifetime: std::time::Duration::from_secs(3600),
            rotation_check_interval: std::time::Duration::from_secs(60),
            compliance_check_interval: std::time::Duration::from_secs(300),
            notification_settings: NotificationSettings {
                email_notifications: false,
                webhook_url: None,
                slack_webhook: None,
                escalation_rules: Vec::new(),
            },
            audit_retention_days: 30,
        };

        let cert_config = CertificateManagerConfig {
            storage_path: base_path.join("certificates"),
            default_validity_period: std::time::Duration::from_secs(86400),
            crl_update_interval: std::time::Duration::from_secs(3600),
            ocsp_responder_timeout: std::time::Duration::from_secs(10),
            certificate_cache_ttl: std::time::Duration::from_secs(300),
            max_certificate_cache_size: 100,
            audit_enabled: false,
        };

        let advanced_config = AdvancedCryptoConfig {
            enable_zk_proofs: false,
            enable_homomorphic_encryption: false,
            enable_mpc: false,
            operation_cache_ttl: std::time::Duration::from_secs(300),
            max_operation_cache_size: 100,
            secure_random_entropy_sources: vec!["system".to_string()],
            performance_monitoring: false,
            audit_all_operations: false,
        };

        let crypto_service = CryptoService::new(
            kms_config,
            lifecycle_config,
            cert_config,
            advanced_config,
        ).await.unwrap();

        // Test service startup
        crypto_service.start_services().await.unwrap();

        // Test service shutdown
        crypto_service.shutdown().await.unwrap();
    }
}