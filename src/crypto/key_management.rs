use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use thiserror::Error;
use uuid::Uuid;
// base64 and sha2 imports removed as unused
// KeyUsage import removed as unused

/// Key management system for enterprise encryption
pub struct KeyManagementSystem {
    /// Master keys storage
    master_keys: Arc<RwLock<HashMap<String, MasterKey>>>,
    /// Data encryption keys storage
    data_keys: Arc<RwLock<HashMap<String, DataEncryptionKey>>>,
    /// Key derivation keys storage
    kek_storage: Arc<RwLock<HashMap<String, KeyEncryptionKey>>>,
    /// Key policies
    key_policies: Arc<RwLock<HashMap<String, KeyPolicy>>>,
    /// HSM integration
    hsm_provider: Option<Arc<dyn HsmProvider>>,
    /// Key store configuration
    config: KeyStoreConfig,
}

#[derive(Error, Debug)]
pub enum KeyManagementError {
    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },
    
    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },
    
    #[error("Key rotation failed: {reason}")]
    KeyRotationFailed { reason: String },
    
    #[error("Invalid key policy: {reason}")]
    InvalidKeyPolicy { reason: String },
    
    #[error("HSM operation failed: {reason}")]
    HsmError { reason: String },
    
    #[error("Key derivation failed: {reason}")]
    KeyDerivationFailed { reason: String },
    
    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },
    
    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },
    
    #[error("Key validation failed: {reason}")]
    KeyValidationFailed { reason: String },
    
    #[error("Certificate error: {reason}")]
    CertificateError { reason: String },
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Master key for key hierarchy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterKey {
    pub id: String,
    pub version: u32,
    pub algorithm: KeyAlgorithm,
    pub key_material: Vec<u8>, // Encrypted key material
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: KeyStatus,
    pub policy_id: String,
    pub metadata: HashMap<String, String>,
    pub hsm_key_id: Option<String>,
}

/// Data encryption key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEncryptionKey {
    pub id: String,
    pub master_key_id: String,
    pub plaintext_key: Option<Vec<u8>>, // Only available when needed
    pub encrypted_key: Vec<u8>,
    pub algorithm: EncryptionAlgorithm,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub usage_count: u64,
    pub status: KeyStatus,
    pub context: EncryptionContext,
}

/// Key encryption key for wrapping other keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEncryptionKey {
    pub id: String,
    pub key_material: Vec<u8>,
    pub algorithm: KeyAlgorithm,
    pub created_at: DateTime<Utc>,
    pub status: KeyStatus,
    pub wrapped_keys: Vec<String>,
}

/// Compliance frameworks supported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceFramework {
    Fips1402Level1,
    Fips1402Level2,
    Fips1402Level3,
    Fips1402Level4,
    CommonCriteria,
    Iso27001,
    Sox,
    Hipaa,
    PciDss,
    Gdpr,
}

/// Key usage policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub key_rotation_period: Option<Duration>,
    pub max_usage_count: Option<u64>,
    pub allowed_operations: Vec<KeyOperation>,
    pub allowed_algorithms: Vec<KeyAlgorithm>,
    pub require_hsm: bool,
    pub require_dual_control: bool,
    pub audit_logging: bool,
    pub geographical_restrictions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Encryption context for data keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionContext {
    pub purpose: String,
    pub owner: String,
    pub environment: String,
    pub additional_authenticated_data: HashMap<String, String>,
}

/// Key store configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStoreConfig {
    pub master_key_algorithm: KeyAlgorithm,
    pub data_key_algorithm: EncryptionAlgorithm,
    pub default_key_size: usize,
    pub enable_hsm: bool,
    pub hsm_config: Option<HsmConfig>,
    pub backup_keys: bool,
    pub audit_all_operations: bool,
    pub key_caching_ttl: Duration,
}

/// HSM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    pub provider: String,
    pub endpoint: String,
    pub credentials: HashMap<String, String>,
    pub partition_name: Option<String>,
    pub slot_id: Option<u32>,
}

/// Key algorithms supported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyAlgorithm {
    AES256,
    ChaCha20,
    RSA2048,
    RSA4096,
    ECC256,
    ECC384,
    Ed25519,
    X25519,
}

/// Encryption algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
    XSalsa20Poly1305,
    AES256CBC,
}

/// Key status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyStatus {
    Active,
    Inactive,
    Deprecated,
    Compromised,
    PendingRotation,
    Revoked,
}

/// Key operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyOperation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    KeyWrap,
    KeyUnwrap,
    GenerateDataKey,
    DeriveKey,
}

/// Key rotation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationResult {
    pub old_key_id: String,
    pub new_key_id: String,
    pub rotation_time: DateTime<Utc>,
    pub affected_data_keys: Vec<String>,
    pub rollback_available: bool,
}

/// HSM provider trait
#[async_trait::async_trait]
pub trait HsmProvider: Send + Sync {
    async fn generate_key(&self, algorithm: KeyAlgorithm, policy_id: &str) -> Result<String, KeyManagementError>;
    async fn encrypt(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError>;
    async fn decrypt(&self, key_id: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, KeyManagementError>;
    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError>;
    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, KeyManagementError>;
    async fn derive_key(&self, master_key_id: &str, context: &[u8]) -> Result<Vec<u8>, KeyManagementError>;
    async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, KeyManagementError>;
    async fn delete_key(&self, key_id: &str) -> Result<(), KeyManagementError>;
}

impl KeyManagementSystem {
    /// Create new key management system
    pub fn new(config: KeyStoreConfig) -> Self {
        Self {
            master_keys: Arc::new(RwLock::new(HashMap::new())),
            data_keys: Arc::new(RwLock::new(HashMap::new())),
            kek_storage: Arc::new(RwLock::new(HashMap::new())),
            key_policies: Arc::new(RwLock::new(HashMap::new())),
            hsm_provider: None,
            config,
        }
    }

    /// Set HSM provider
    pub fn set_hsm_provider(&mut self, provider: Arc<dyn HsmProvider>) {
        self.hsm_provider = Some(provider);
    }

    /// Generate master key
    pub async fn generate_master_key(
        &self,
        algorithm: KeyAlgorithm,
        policy_id: String,
        metadata: HashMap<String, String>,
    ) -> Result<String, KeyManagementError> {
        let key_id = Uuid::new_v4().to_string();
        
        // Check policy
        let policy = {
            let policies = self.key_policies.read().await;
            policies.get(&policy_id)
                .ok_or_else(|| KeyManagementError::InvalidKeyPolicy { 
                    reason: format!("Policy {} not found", policy_id) 
                })?
                .clone()
        };

        let key_material = if policy.require_hsm {
            if let Some(hsm) = &self.hsm_provider {
                let hsm_key_id = hsm.generate_key(algorithm.clone(), &policy_id).await?;
                // Store reference to HSM key
                Vec::new() // Empty for HSM-backed keys
            } else {
                return Err(KeyManagementError::HsmError { 
                    reason: "HSM required but not configured".to_string() 
                });
            }
        } else {
            self.generate_key_material(&algorithm)?
        };

        let master_key = MasterKey {
            id: key_id.clone(),
            version: 1,
            algorithm,
            key_material,
            created_at: Utc::now(),
            expires_at: policy.key_rotation_period.map(|d| Utc::now() + d),
            status: KeyStatus::Active,
            policy_id,
            metadata,
            hsm_key_id: None,
        };

        self.master_keys.write().await.insert(key_id.clone(), master_key);
        self.audit_log("master_key_generated", &key_id, None).await;

        Ok(key_id)
    }

    /// Generate data encryption key
    pub async fn generate_data_key(
        &self,
        master_key_id: &str,
        algorithm: EncryptionAlgorithm,
        context: EncryptionContext,
    ) -> Result<DataEncryptionKey, KeyManagementError> {
        let master_key = {
            let master_keys = self.master_keys.read().await;
            master_keys.get(master_key_id)
                .ok_or_else(|| KeyManagementError::KeyNotFound { 
                    key_id: master_key_id.to_string() 
                })?
                .clone()
        };

        // Validate master key status
        if master_key.status != KeyStatus::Active {
            return Err(KeyManagementError::KeyValidationFailed { 
                reason: format!("Master key {} is not active", master_key_id) 
            });
        }

        let key_id = Uuid::new_v4().to_string();
        let plaintext_key = self.generate_symmetric_key(&algorithm)?;
        let encrypted_key = self.encrypt_data_key(&master_key, &plaintext_key).await?;

        let data_key = DataEncryptionKey {
            id: key_id.clone(),
            master_key_id: master_key_id.to_string(),
            plaintext_key: Some(plaintext_key),
            encrypted_key,
            algorithm,
            created_at: Utc::now(),
            last_used: None,
            usage_count: 0,
            status: KeyStatus::Active,
            context,
        };

        self.data_keys.write().await.insert(key_id.clone(), data_key.clone());
        self.audit_log("data_key_generated", &key_id, Some(master_key_id)).await;

        Ok(data_key)
    }

    /// Decrypt data encryption key
    pub async fn decrypt_data_key(&self, key_id: &str) -> Result<Vec<u8>, KeyManagementError> {
        let data_key = {
            let data_keys = self.data_keys.read().await;
            data_keys.get(key_id)
                .ok_or_else(|| KeyManagementError::KeyNotFound { 
                    key_id: key_id.to_string() 
                })?
                .clone()
        };

        // Return plaintext key if cached
        if let Some(ref plaintext) = data_key.plaintext_key {
            // Update usage statistics
            self.update_key_usage(key_id).await?;
            return Ok(plaintext.clone());
        }

        // Decrypt using master key
        let master_key = {
            let master_keys = self.master_keys.read().await;
            master_keys.get(&data_key.master_key_id)
                .ok_or_else(|| KeyManagementError::KeyNotFound { 
                    key_id: data_key.master_key_id.clone() 
                })?
                .clone()
        };

        let plaintext_key = self.decrypt_data_key_material(&master_key, &data_key.encrypted_key).await?;
        
        // Cache plaintext key temporarily
        {
            let mut data_keys = self.data_keys.write().await;
            if let Some(key) = data_keys.get_mut(key_id) {
                key.plaintext_key = Some(plaintext_key.clone());
            }
        }

        self.update_key_usage(key_id).await?;
        self.audit_log("data_key_decrypted", key_id, Some(&data_key.master_key_id)).await;

        Ok(plaintext_key)
    }

    /// Rotate master key
    pub async fn rotate_master_key(&self, key_id: &str) -> Result<KeyRotationResult, KeyManagementError> {
        let old_master_key = {
            let master_keys = self.master_keys.read().await;
            master_keys.get(key_id)
                .ok_or_else(|| KeyManagementError::KeyNotFound { 
                    key_id: key_id.to_string() 
                })?
                .clone()
        };

        // Generate new master key with incremented version
        let new_key_id = format!("{}_v{}", key_id, old_master_key.version + 1);
        let new_key_material = if old_master_key.hsm_key_id.is_some() {
            if let Some(hsm) = &self.hsm_provider {
                hsm.generate_key(old_master_key.algorithm.clone(), &old_master_key.policy_id).await?;
                Vec::new()
            } else {
                return Err(KeyManagementError::HsmError { 
                    reason: "HSM required but not configured".to_string() 
                });
            }
        } else {
            self.generate_key_material(&old_master_key.algorithm)?
        };

        let new_master_key = MasterKey {
            id: new_key_id.clone(),
            version: old_master_key.version + 1,
            algorithm: old_master_key.algorithm,
            key_material: new_key_material,
            created_at: Utc::now(),
            expires_at: old_master_key.expires_at,
            status: KeyStatus::Active,
            policy_id: old_master_key.policy_id.clone(),
            metadata: old_master_key.metadata.clone(),
            hsm_key_id: None,
        };

        // Re-encrypt all data keys with new master key
        let affected_data_keys = self.re_encrypt_data_keys(&old_master_key, &new_master_key).await?;

        // Update master key status
        {
            let mut master_keys = self.master_keys.write().await;
            master_keys.insert(new_key_id.clone(), new_master_key);
            if let Some(old_key) = master_keys.get_mut(key_id) {
                old_key.status = KeyStatus::Deprecated;
            }
        }

        let rotation_result = KeyRotationResult {
            old_key_id: key_id.to_string(),
            new_key_id: new_key_id.clone(),
            rotation_time: Utc::now(),
            affected_data_keys: affected_data_keys.clone(),
            rollback_available: true,
        };

        self.audit_log("master_key_rotated", &new_key_id, Some(key_id)).await;

        Ok(rotation_result)
    }

    /// Create key policy
    pub async fn create_key_policy(&self, policy: KeyPolicy) -> Result<(), KeyManagementError> {
        self.validate_key_policy(&policy)?;
        
        self.key_policies.write().await.insert(policy.id.clone(), policy.clone());
        self.audit_log("key_policy_created", &policy.id, None).await;
        
        Ok(())
    }

    /// Get key policy
    pub async fn get_key_policy(&self, policy_id: &str) -> Result<KeyPolicy, KeyManagementError> {
        let policies = self.key_policies.read().await;
        policies.get(policy_id)
            .cloned()
            .ok_or_else(|| KeyManagementError::InvalidKeyPolicy { 
                reason: format!("Policy {} not found", policy_id) 
            })
    }

    /// List all master keys
    pub async fn list_master_keys(&self) -> Result<Vec<String>, KeyManagementError> {
        let master_keys = self.master_keys.read().await;
        Ok(master_keys.keys().cloned().collect())
    }

    /// Get key metrics
    pub async fn get_key_metrics(&self) -> Result<KeyMetrics, KeyManagementError> {
        let master_keys = self.master_keys.read().await;
        let data_keys = self.data_keys.read().await;
        let policies = self.key_policies.read().await;

        let master_key_count = master_keys.len();
        let data_key_count = data_keys.len();
        let policy_count = policies.len();

        let active_master_keys = master_keys.values()
            .filter(|k| k.status == KeyStatus::Active)
            .count();

        let active_data_keys = data_keys.values()
            .filter(|k| k.status == KeyStatus::Active)
            .count();

        let keys_requiring_rotation = master_keys.values()
            .filter(|k| {
                k.expires_at.map_or(false, |exp| exp <= Utc::now() + Duration::days(30))
            })
            .count();

        Ok(KeyMetrics {
            master_key_count,
            data_key_count,
            policy_count,
            active_master_keys,
            active_data_keys,
            keys_requiring_rotation,
            hsm_backed_keys: master_keys.values()
                .filter(|k| k.hsm_key_id.is_some())
                .count(),
        })
    }

    // Private helper methods
    
    /// Generate key material based on algorithm
    fn generate_key_material(&self, algorithm: &KeyAlgorithm) -> Result<Vec<u8>, KeyManagementError> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        
        let key_size = match algorithm {
            KeyAlgorithm::AES256 => 32,
            KeyAlgorithm::ChaCha20 => 32,
            KeyAlgorithm::RSA2048 => 256, // Simplified
            KeyAlgorithm::RSA4096 => 512, // Simplified
            KeyAlgorithm::ECC256 => 32,
            KeyAlgorithm::ECC384 => 48,
            KeyAlgorithm::Ed25519 => 32,
            KeyAlgorithm::X25519 => 32,
        };

        let mut key_material = vec![0u8; key_size];
        rng.fill_bytes(&mut key_material);
        
        Ok(key_material)
    }

    /// Generate symmetric key for data encryption
    fn generate_symmetric_key(&self, algorithm: &EncryptionAlgorithm) -> Result<Vec<u8>, KeyManagementError> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        
        let key_size = match algorithm {
            EncryptionAlgorithm::AES256GCM => 32,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32,
            EncryptionAlgorithm::XSalsa20Poly1305 => 32,
            EncryptionAlgorithm::AES256CBC => 32,
        };

        let mut key = vec![0u8; key_size];
        rng.fill_bytes(&mut key);
        
        Ok(key)
    }

    /// Encrypt data key with master key
    async fn encrypt_data_key(&self, master_key: &MasterKey, plaintext_key: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if let Some(hsm) = &self.hsm_provider {
            if let Some(ref hsm_key_id) = master_key.hsm_key_id {
                return hsm.encrypt(hsm_key_id, plaintext_key).await;
            }
        }

        // Software-based encryption
        self.software_encrypt(&master_key.key_material, plaintext_key)
    }

    /// Decrypt data key with master key
    async fn decrypt_data_key_material(&self, master_key: &MasterKey, encrypted_key: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if let Some(hsm) = &self.hsm_provider {
            if let Some(ref hsm_key_id) = master_key.hsm_key_id {
                return hsm.decrypt(hsm_key_id, encrypted_key).await;
            }
        }

        // Software-based decryption
        self.software_decrypt(&master_key.key_material, encrypted_key)
    }

    /// Software-based encryption
    fn software_encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        // Simplified implementation - in production, use proper AEAD
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(plaintext);
        Ok(hasher.finalize().to_vec())
    }

    /// Software-based decryption
    fn software_decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        // Simplified implementation - in production, use proper AEAD
        // This is just a placeholder
        Ok(ciphertext.to_vec())
    }

    /// Re-encrypt data keys with new master key
    async fn re_encrypt_data_keys(&self, old_master: &MasterKey, new_master: &MasterKey) -> Result<Vec<String>, KeyManagementError> {
        let mut affected_keys = Vec::new();
        let mut data_keys = self.data_keys.write().await;

        for (key_id, data_key) in data_keys.iter_mut() {
            if data_key.master_key_id == old_master.id {
                // Decrypt with old master key
                let plaintext = self.decrypt_data_key_material(old_master, &data_key.encrypted_key).await?;
                
                // Re-encrypt with new master key
                let new_encrypted = self.encrypt_data_key(new_master, &plaintext).await?;
                
                // Update data key
                data_key.master_key_id = new_master.id.clone();
                data_key.encrypted_key = new_encrypted;
                data_key.plaintext_key = None; // Clear cache
                
                affected_keys.push(key_id.clone());
            }
        }

        Ok(affected_keys)
    }

    /// Update key usage statistics
    async fn update_key_usage(&self, key_id: &str) -> Result<(), KeyManagementError> {
        let mut data_keys = self.data_keys.write().await;
        if let Some(key) = data_keys.get_mut(key_id) {
            key.last_used = Some(Utc::now());
            key.usage_count += 1;
        }
        Ok(())
    }

    /// Validate key policy
    fn validate_key_policy(&self, policy: &KeyPolicy) -> Result<(), KeyManagementError> {
        if policy.name.is_empty() {
            return Err(KeyManagementError::InvalidKeyPolicy { 
                reason: "Policy name cannot be empty".to_string() 
            });
        }

        if policy.allowed_operations.is_empty() {
            return Err(KeyManagementError::InvalidKeyPolicy { 
                reason: "Policy must allow at least one operation".to_string() 
            });
        }

        if policy.allowed_algorithms.is_empty() {
            return Err(KeyManagementError::InvalidKeyPolicy { 
                reason: "Policy must allow at least one algorithm".to_string() 
            });
        }

        Ok(())
    }

    /// Audit log operation
    async fn audit_log(&self, operation: &str, key_id: &str, related_key_id: Option<&str>) {
        if self.config.audit_all_operations {
            log::info!("KEY_AUDIT: operation={}, key_id={}, related_key={:?}, timestamp={}", 
                operation, key_id, related_key_id, Utc::now());
        }
    }
}

/// Key management metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetrics {
    pub master_key_count: usize,
    pub data_key_count: usize,
    pub policy_count: usize,
    pub active_master_keys: usize,
    pub active_data_keys: usize,
    pub keys_requiring_rotation: usize,
    pub hsm_backed_keys: usize,
}

impl Default for KeyStoreConfig {
    fn default() -> Self {
        Self {
            master_key_algorithm: KeyAlgorithm::AES256,
            data_key_algorithm: EncryptionAlgorithm::AES256GCM,
            default_key_size: 256,
            enable_hsm: false,
            hsm_config: None,
            backup_keys: true,
            audit_all_operations: true,
            key_caching_ttl: Duration::minutes(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_key_management_basic_operations() -> Result<(), Box<dyn std::error::Error>> {
        let config = KeyStoreConfig::default();
        let kms = KeyManagementSystem::new(config);

        // Create a basic policy
        let policy = KeyPolicy {
            id: "test-policy".to_string(),
            name: "Test Policy".to_string(),
            description: "Test key policy".to_string(),
            key_rotation_period: Some(Duration::days(90)),
            max_usage_count: Some(10000),
            allowed_operations: vec![KeyOperation::Encrypt, KeyOperation::Decrypt],
            allowed_algorithms: vec![KeyAlgorithm::AES256],
            require_hsm: false,
            require_dual_control: false,
            audit_logging: true,
            geographical_restrictions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        kms.create_key_policy(policy).await?;

        // Generate master key
        let master_key_id = kms.generate_master_key(
            KeyAlgorithm::AES256,
            "test-policy".to_string(),
            HashMap::new(),
        ).await?;

        assert!(!master_key_id.is_empty());

        // Generate data key
        let context = EncryptionContext {
            purpose: "test".to_string(),
            owner: "user@example.com".to_string(),
            environment: "test".to_string(),
            additional_authenticated_data: HashMap::new(),
        };

        let data_key = kms.generate_data_key(
            &master_key_id,
            EncryptionAlgorithm::AES256GCM,
            context,
        ).await?;

        assert!(!data_key.id.is_empty());
        assert!(data_key.plaintext_key.is_some());

        // Test key metrics
        let metrics = kms.get_key_metrics().await?;
        assert_eq!(metrics.master_key_count, 1);
        assert_eq!(metrics.data_key_count, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_key_rotation() -> Result<(), Box<dyn std::error::Error>> {
        let config = KeyStoreConfig::default();
        let kms = KeyManagementSystem::new(config);

        // Create policy
        let policy = KeyPolicy {
            id: "rotation-policy".to_string(),
            name: "Rotation Policy".to_string(),
            description: "Key rotation test policy".to_string(),
            key_rotation_period: Some(Duration::days(1)),
            max_usage_count: None,
            allowed_operations: vec![KeyOperation::Encrypt, KeyOperation::Decrypt],
            allowed_algorithms: vec![KeyAlgorithm::AES256],
            require_hsm: false,
            require_dual_control: false,
            audit_logging: true,
            geographical_restrictions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        kms.create_key_policy(policy).await?;

        // Generate master key
        let master_key_id = kms.generate_master_key(
            KeyAlgorithm::AES256,
            "rotation-policy".to_string(),
            HashMap::new(),
        ).await?;

        // Test rotation
        let rotation_result = kms.rotate_master_key(&master_key_id).await?;
        
        assert_eq!(rotation_result.old_key_id, master_key_id);
        assert_ne!(rotation_result.new_key_id, master_key_id);
        assert!(rotation_result.rollback_available);

        Ok(())
    }
}