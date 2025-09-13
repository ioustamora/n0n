use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

use crate::crypto::key_management::{KeyAlgorithm, KeyManagementError, HsmProvider};

/// HSM integration errors
#[derive(Error, Debug)]
pub enum HsmError {
    #[error("Connection failed: {reason}")]
    ConnectionFailed { reason: String },
    
    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },
    
    #[error("Key operation failed: {reason}")]
    KeyOperationFailed { reason: String },
    
    #[error("Invalid configuration: {reason}")]
    InvalidConfiguration { reason: String },
    
    #[error("HSM not available: {reason}")]
    HsmNotAvailable { reason: String },
    
    #[error("Unsupported operation: {operation}")]
    UnsupportedOperation { operation: String },
    
    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// HSM factory for creating provider instances
pub struct HsmFactory {
    providers: HashMap<String, Box<dyn HsmProviderFactory>>,
}

/// HSM provider factory trait
#[async_trait]
pub trait HsmProviderFactory: Send + Sync {
    async fn create_provider(&self, config: &HsmProviderConfig) -> Result<Arc<dyn HsmProvider>, HsmError>;
    fn provider_name(&self) -> &str;
    fn supported_algorithms(&self) -> Vec<KeyAlgorithm>;
}

/// HSM provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmProviderConfig {
    pub provider_type: HsmProviderType,
    pub connection_string: String,
    pub credentials: HashMap<String, String>,
    pub partition_name: Option<String>,
    pub slot_id: Option<u32>,
    pub timeout_seconds: u32,
    pub retry_attempts: u32,
    pub enable_failover: bool,
    pub failover_providers: Vec<String>,
}

/// Supported HSM provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HsmProviderType {
    AwsCloudHsm,
    AzureDedicatedHsm,
    SafeNetLuna,
    Thales,
    SoftHsm, // For testing
    Mock,    // For development
}

/// AWS CloudHSM provider
pub struct AwsCloudHsmProvider {
    config: HsmProviderConfig,
    client: Option<Arc<dyn AwsHsmClient>>,
    key_cache: Arc<RwLock<HashMap<String, HsmKeyMetadata>>>,
}

/// Azure Dedicated HSM provider
pub struct AzureDedicatedHsmProvider {
    config: HsmProviderConfig,
    client: Option<Arc<dyn AzureHsmClient>>,
    key_cache: Arc<RwLock<HashMap<String, HsmKeyMetadata>>>,
}

/// SafeNet Luna HSM provider
pub struct SafeNetLunaProvider {
    config: HsmProviderConfig,
    session_handle: Option<u64>,
    key_cache: Arc<RwLock<HashMap<String, HsmKeyMetadata>>>,
}

/// Software HSM provider for testing
pub struct SoftHsmProvider {
    config: HsmProviderConfig,
    keys: Arc<RwLock<HashMap<String, SoftHsmKey>>>,
}

/// Mock HSM provider for development
pub struct MockHsmProvider {
    keys: Arc<RwLock<HashMap<String, MockHsmKey>>>,
    operation_delay_ms: u64,
}

/// HSM key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmKeyMetadata {
    pub key_id: String,
    pub algorithm: KeyAlgorithm,
    pub created_at: DateTime<Utc>,
    pub key_size: usize,
    pub usage_count: u64,
    pub extractable: bool,
    pub exportable: bool,
    pub attributes: HashMap<String, String>,
}

/// Soft HSM key storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SoftHsmKey {
    pub id: String,
    pub algorithm: KeyAlgorithm,
    pub key_material: Vec<u8>,
    pub metadata: HsmKeyMetadata,
}

/// Mock HSM key storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MockHsmKey {
    pub id: String,
    pub algorithm: KeyAlgorithm,
    pub key_material: Vec<u8>,
    pub metadata: HsmKeyMetadata,
}

/// AWS HSM client trait
#[async_trait]
trait AwsHsmClient: Send + Sync {
    async fn create_key(&self, algorithm: KeyAlgorithm) -> Result<String, HsmError>;
    async fn encrypt_data(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError>;
    async fn decrypt_data(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, HsmError>;
    async fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError>;
    async fn verify_signature(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, HsmError>;
    async fn delete_key(&self, key_id: &str) -> Result<(), HsmError>;
}

/// Azure HSM client trait  
#[async_trait]
trait AzureHsmClient: Send + Sync {
    async fn create_key(&self, algorithm: KeyAlgorithm) -> Result<String, HsmError>;
    async fn encrypt_data(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError>;
    async fn decrypt_data(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, HsmError>;
    async fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError>;
    async fn verify_signature(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, HsmError>;
    async fn delete_key(&self, key_id: &str) -> Result<(), HsmError>;
}

impl HsmFactory {
    /// Create new HSM factory
    pub fn new() -> Self {
        let mut factory = Self {
            providers: HashMap::new(),
        };
        
        // Register built-in providers
        factory.register_provider("aws_cloudhsm", Box::new(AwsCloudHsmFactory));
        factory.register_provider("azure_dedicated", Box::new(AzureDedicatedHsmFactory));
        factory.register_provider("safenet_luna", Box::new(SafeNetLunaFactory));
        factory.register_provider("softhsm", Box::new(SoftHsmFactory));
        factory.register_provider("mock", Box::new(MockHsmFactory));
        
        factory
    }

    /// Register HSM provider factory
    pub fn register_provider(&mut self, name: &str, factory: Box<dyn HsmProviderFactory>) {
        self.providers.insert(name.to_string(), factory);
    }

    /// Create HSM provider
    pub async fn create_provider(&self, provider_name: &str, config: &HsmProviderConfig) -> Result<Arc<dyn HsmProvider>, HsmError> {
        let factory = self.providers.get(provider_name)
            .ok_or_else(|| HsmError::InvalidConfiguration { 
                reason: format!("Unknown HSM provider: {}", provider_name) 
            })?;

        factory.create_provider(config).await
    }

    /// List available providers
    pub fn list_providers(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }
}

// Provider factory implementations

struct AwsCloudHsmFactory;

#[async_trait]
impl HsmProviderFactory for AwsCloudHsmFactory {
    async fn create_provider(&self, config: &HsmProviderConfig) -> Result<Arc<dyn HsmProvider>, HsmError> {
        let provider = AwsCloudHsmProvider::new(config.clone()).await?;
        Ok(Arc::new(provider))
    }

    fn provider_name(&self) -> &str {
        "AWS CloudHSM"
    }

    fn supported_algorithms(&self) -> Vec<KeyAlgorithm> {
        vec![
            KeyAlgorithm::AES256,
            KeyAlgorithm::RSA2048,
            KeyAlgorithm::RSA4096,
            KeyAlgorithm::ECC256,
            KeyAlgorithm::ECC384,
        ]
    }
}

struct AzureDedicatedHsmFactory;

#[async_trait]
impl HsmProviderFactory for AzureDedicatedHsmFactory {
    async fn create_provider(&self, config: &HsmProviderConfig) -> Result<Arc<dyn HsmProvider>, HsmError> {
        let provider = AzureDedicatedHsmProvider::new(config.clone()).await?;
        Ok(Arc::new(provider))
    }

    fn provider_name(&self) -> &str {
        "Azure Dedicated HSM"
    }

    fn supported_algorithms(&self) -> Vec<KeyAlgorithm> {
        vec![
            KeyAlgorithm::AES256,
            KeyAlgorithm::RSA2048,
            KeyAlgorithm::RSA4096,
            KeyAlgorithm::ECC256,
        ]
    }
}

struct SafeNetLunaFactory;

#[async_trait]
impl HsmProviderFactory for SafeNetLunaFactory {
    async fn create_provider(&self, config: &HsmProviderConfig) -> Result<Arc<dyn HsmProvider>, HsmError> {
        let provider = SafeNetLunaProvider::new(config.clone()).await?;
        Ok(Arc::new(provider))
    }

    fn provider_name(&self) -> &str {
        "SafeNet Luna"
    }

    fn supported_algorithms(&self) -> Vec<KeyAlgorithm> {
        vec![
            KeyAlgorithm::AES256,
            KeyAlgorithm::ChaCha20,
            KeyAlgorithm::RSA2048,
            KeyAlgorithm::RSA4096,
            KeyAlgorithm::ECC256,
            KeyAlgorithm::ECC384,
        ]
    }
}

struct SoftHsmFactory;

#[async_trait]
impl HsmProviderFactory for SoftHsmFactory {
    async fn create_provider(&self, config: &HsmProviderConfig) -> Result<Arc<dyn HsmProvider>, HsmError> {
        let provider = SoftHsmProvider::new(config.clone())?;
        Ok(Arc::new(provider))
    }

    fn provider_name(&self) -> &str {
        "SoftHSM"
    }

    fn supported_algorithms(&self) -> Vec<KeyAlgorithm> {
        vec![
            KeyAlgorithm::AES256,
            KeyAlgorithm::ChaCha20,
            KeyAlgorithm::RSA2048,
            KeyAlgorithm::RSA4096,
            KeyAlgorithm::ECC256,
            KeyAlgorithm::ECC384,
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::X25519,
        ]
    }
}

struct MockHsmFactory;

#[async_trait]
impl HsmProviderFactory for MockHsmFactory {
    async fn create_provider(&self, _config: &HsmProviderConfig) -> Result<Arc<dyn HsmProvider>, HsmError> {
        let provider = MockHsmProvider::new();
        Ok(Arc::new(provider))
    }

    fn provider_name(&self) -> &str {
        "Mock HSM"
    }

    fn supported_algorithms(&self) -> Vec<KeyAlgorithm> {
        vec![
            KeyAlgorithm::AES256,
            KeyAlgorithm::ChaCha20,
            KeyAlgorithm::RSA2048,
            KeyAlgorithm::RSA4096,
            KeyAlgorithm::ECC256,
            KeyAlgorithm::ECC384,
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::X25519,
        ]
    }
}

// Provider implementations

impl AwsCloudHsmProvider {
    async fn new(config: HsmProviderConfig) -> Result<Self, HsmError> {
        // In a real implementation, this would initialize the AWS CloudHSM client
        Ok(Self {
            config,
            client: None,
            key_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[async_trait]
impl HsmProvider for AwsCloudHsmProvider {
    async fn generate_key(&self, algorithm: KeyAlgorithm, _policy_id: &str) -> Result<String, KeyManagementError> {
        // Simulate AWS CloudHSM key generation
        let key_id = format!("aws-hsm-{}", uuid::Uuid::new_v4());
        let key_size = self.get_key_size(&algorithm);
        
        let metadata = HsmKeyMetadata {
            key_id: key_id.clone(),
            algorithm,
            created_at: Utc::now(),
            key_size,
            usage_count: 0,
            extractable: false,
            exportable: false,
            attributes: HashMap::new(),
        };

        self.key_cache.write().await.insert(key_id.clone(), metadata);
        
        Ok(key_id)
    }

    async fn encrypt(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        // Simulate AWS CloudHSM encryption
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        // In real implementation, this would call AWS CloudHSM APIs
        let mut result = Vec::with_capacity(data.len() + 16);
        result.extend_from_slice(b"AWS-HSM-ENC:");
        result.extend_from_slice(data);
        
        // Update usage count
        if let Some(metadata) = self.key_cache.write().await.get_mut(key_id) {
            metadata.usage_count += 1;
        }

        Ok(result)
    }

    async fn decrypt(&self, key_id: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        // Simulate AWS CloudHSM decryption
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        if !encrypted_data.starts_with(b"AWS-HSM-ENC:") {
            return Err(KeyManagementError::DecryptionFailed { 
                reason: "Invalid ciphertext format".to_string() 
            });
        }

        let plaintext = &encrypted_data[12..]; // Remove prefix
        
        // Update usage count
        if let Some(metadata) = self.key_cache.write().await.get_mut(key_id) {
            metadata.usage_count += 1;
        }

        Ok(plaintext.to_vec())
    }

    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        // Simulate signing
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(b"AWS-HSM-SIG:");
        signature.extend_from_slice(&data[..std::cmp::min(data.len(), 52)]);
        
        Ok(signature)
    }

    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        // Simulate verification
        if !signature.starts_with(b"AWS-HSM-SIG:") {
            return Ok(false);
        }

        let expected_suffix = &data[..std::cmp::min(data.len(), 52)];
        let signature_suffix = &signature[12..];
        
        Ok(signature_suffix == expected_suffix)
    }

    async fn derive_key(&self, master_key_id: &str, context: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(master_key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: master_key_id.to_string() });
        }

        // Simulate key derivation
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(master_key_id.as_bytes());
        hasher.update(context);
        
        Ok(hasher.finalize().to_vec())
    }

    async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        // Simulate public key extraction
        Ok(format!("AWS-HSM-PUBKEY-{}", key_id).into_bytes())
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), KeyManagementError> {
        self.key_cache.write().await.remove(key_id);
        Ok(())
    }
}

impl AwsCloudHsmProvider {
    fn get_key_size(&self, algorithm: &KeyAlgorithm) -> usize {
        match algorithm {
            KeyAlgorithm::AES256 => 256,
            KeyAlgorithm::RSA2048 => 2048,
            KeyAlgorithm::RSA4096 => 4096,
            KeyAlgorithm::ECC256 => 256,
            KeyAlgorithm::ECC384 => 384,
            _ => 256,
        }
    }
}

// Similar implementations for other providers...

impl AzureDedicatedHsmProvider {
    async fn new(config: HsmProviderConfig) -> Result<Self, HsmError> {
        Ok(Self {
            config,
            client: None,
            key_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[async_trait]
impl HsmProvider for AzureDedicatedHsmProvider {
    async fn generate_key(&self, algorithm: KeyAlgorithm, _policy_id: &str) -> Result<String, KeyManagementError> {
        let key_id = format!("azure-hsm-{}", uuid::Uuid::new_v4());
        let key_size = self.get_key_size(&algorithm);
        
        let metadata = HsmKeyMetadata {
            key_id: key_id.clone(),
            algorithm,
            created_at: Utc::now(),
            key_size,
            usage_count: 0,
            extractable: false,
            exportable: false,
            attributes: HashMap::new(),
        };

        self.key_cache.write().await.insert(key_id.clone(), metadata);
        Ok(key_id)
    }

    async fn encrypt(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        let mut result = Vec::with_capacity(data.len() + 16);
        result.extend_from_slice(b"AZURE-HSM-ENC:");
        result.extend_from_slice(data);
        
        Ok(result)
    }

    async fn decrypt(&self, key_id: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        if !encrypted_data.starts_with(b"AZURE-HSM-ENC:") {
            return Err(KeyManagementError::DecryptionFailed { 
                reason: "Invalid ciphertext format".to_string() 
            });
        }

        Ok(encrypted_data[14..].to_vec())
    }

    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(b"AZURE-HSM-SIG:");
        signature.extend_from_slice(&data[..std::cmp::min(data.len(), 49)]);
        
        Ok(signature)
    }

    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        if !signature.starts_with(b"AZURE-HSM-SIG:") {
            return Ok(false);
        }

        let expected_suffix = &data[..std::cmp::min(data.len(), 49)];
        let signature_suffix = &signature[14..];
        
        Ok(signature_suffix == expected_suffix)
    }

    async fn derive_key(&self, master_key_id: &str, context: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(master_key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: master_key_id.to_string() });
        }

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"AZURE-HSM-KDF:");
        hasher.update(master_key_id.as_bytes());
        hasher.update(context);
        
        Ok(hasher.finalize().to_vec())
    }

    async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        Ok(format!("AZURE-HSM-PUBKEY-{}", key_id).into_bytes())
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), KeyManagementError> {
        self.key_cache.write().await.remove(key_id);
        Ok(())
    }
}

impl AzureDedicatedHsmProvider {
    fn get_key_size(&self, algorithm: &KeyAlgorithm) -> usize {
        match algorithm {
            KeyAlgorithm::AES256 => 256,
            KeyAlgorithm::RSA2048 => 2048,
            KeyAlgorithm::RSA4096 => 4096,
            KeyAlgorithm::ECC256 => 256,
            _ => 256,
        }
    }
}

impl SafeNetLunaProvider {
    async fn new(config: HsmProviderConfig) -> Result<Self, HsmError> {
        // In real implementation, initialize PKCS#11 session
        Ok(Self {
            config,
            session_handle: Some(12345), // Mock session handle
            key_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[async_trait]
impl HsmProvider for SafeNetLunaProvider {
    async fn generate_key(&self, algorithm: KeyAlgorithm, _policy_id: &str) -> Result<String, KeyManagementError> {
        let key_id = format!("luna-hsm-{}", uuid::Uuid::new_v4());
        
        let metadata = HsmKeyMetadata {
            key_id: key_id.clone(),
            algorithm: algorithm.clone(),
            created_at: Utc::now(),
            key_size: self.get_key_size(&algorithm),
            usage_count: 0,
            extractable: false,
            exportable: false,
            attributes: HashMap::new(),
        };

        self.key_cache.write().await.insert(key_id.clone(), metadata);
        Ok(key_id)
    }

    async fn encrypt(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        let mut result = Vec::with_capacity(data.len() + 16);
        result.extend_from_slice(b"LUNA-HSM-ENC:");
        result.extend_from_slice(data);
        
        Ok(result)
    }

    async fn decrypt(&self, key_id: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        if !encrypted_data.starts_with(b"LUNA-HSM-ENC:") {
            return Err(KeyManagementError::DecryptionFailed { 
                reason: "Invalid ciphertext format".to_string() 
            });
        }

        Ok(encrypted_data[13..].to_vec())
    }

    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(b"LUNA-HSM-SIG:");
        signature.extend_from_slice(&data[..std::cmp::min(data.len(), 50)]);
        
        Ok(signature)
    }

    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        if !signature.starts_with(b"LUNA-HSM-SIG:") {
            return Ok(false);
        }

        let expected_suffix = &data[..std::cmp::min(data.len(), 50)];
        let signature_suffix = &signature[13..];
        
        Ok(signature_suffix == expected_suffix)
    }

    async fn derive_key(&self, master_key_id: &str, context: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(master_key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: master_key_id.to_string() });
        }

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"LUNA-HSM-KDF:");
        hasher.update(master_key_id.as_bytes());
        hasher.update(context);
        
        Ok(hasher.finalize().to_vec())
    }

    async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, KeyManagementError> {
        if !self.key_cache.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        Ok(format!("LUNA-HSM-PUBKEY-{}", key_id).into_bytes())
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), KeyManagementError> {
        self.key_cache.write().await.remove(key_id);
        Ok(())
    }
}

impl SafeNetLunaProvider {
    fn get_key_size(&self, algorithm: &KeyAlgorithm) -> usize {
        match algorithm {
            KeyAlgorithm::AES256 => 256,
            KeyAlgorithm::ChaCha20 => 256,
            KeyAlgorithm::RSA2048 => 2048,
            KeyAlgorithm::RSA4096 => 4096,
            KeyAlgorithm::ECC256 => 256,
            KeyAlgorithm::ECC384 => 384,
            _ => 256,
        }
    }
}

impl SoftHsmProvider {
    fn new(config: HsmProviderConfig) -> Result<Self, HsmError> {
        Ok(Self {
            config,
            keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[async_trait]
impl HsmProvider for SoftHsmProvider {
    async fn generate_key(&self, algorithm: KeyAlgorithm, _policy_id: &str) -> Result<String, KeyManagementError> {
        let key_id = format!("softhsm-{}", uuid::Uuid::new_v4());
        
        // Generate actual key material
        let key_material = self.generate_key_material(&algorithm)?;
        
        let metadata = HsmKeyMetadata {
            key_id: key_id.clone(),
            algorithm: algorithm.clone(),
            created_at: Utc::now(),
            key_size: key_material.len() * 8,
            usage_count: 0,
            extractable: true,
            exportable: true,
            attributes: HashMap::new(),
        };

        let soft_key = SoftHsmKey {
            id: key_id.clone(),
            algorithm,
            key_material,
            metadata,
        };

        self.keys.write().await.insert(key_id.clone(), soft_key);
        Ok(key_id)
    }

    async fn encrypt(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        let keys = self.keys.read().await;
        let key = keys.get(key_id)
            .ok_or_else(|| KeyManagementError::KeyNotFound { key_id: key_id.to_string() })?;

        // Simple XOR encryption for demo purposes
        let mut result = Vec::with_capacity(data.len());
        for (i, byte) in data.iter().enumerate() {
            let key_byte = key.key_material[i % key.key_material.len()];
            result.push(byte ^ key_byte);
        }

        Ok(result)
    }

    async fn decrypt(&self, key_id: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        // XOR is symmetric, so decryption is the same as encryption
        self.encrypt(key_id, encrypted_data).await
    }

    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        let keys = self.keys.read().await;
        let key = keys.get(key_id)
            .ok_or_else(|| KeyManagementError::KeyNotFound { key_id: key_id.to_string() })?;

        // Simple HMAC-like signature
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&key.key_material);
        hasher.update(data);
        
        Ok(hasher.finalize().to_vec())
    }

    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, KeyManagementError> {
        let expected_signature = self.sign(key_id, data).await?;
        Ok(signature == expected_signature)
    }

    async fn derive_key(&self, master_key_id: &str, context: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        let keys = self.keys.read().await;
        let master_key = keys.get(master_key_id)
            .ok_or_else(|| KeyManagementError::KeyNotFound { key_id: master_key_id.to_string() })?;

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&master_key.key_material);
        hasher.update(context);
        
        Ok(hasher.finalize().to_vec())
    }

    async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, KeyManagementError> {
        let keys = self.keys.read().await;
        let key = keys.get(key_id)
            .ok_or_else(|| KeyManagementError::KeyNotFound { key_id: key_id.to_string() })?;

        // For symmetric keys, return a derived public component
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"PUBLIC:");
        hasher.update(&key.key_material);
        
        Ok(hasher.finalize().to_vec())
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), KeyManagementError> {
        self.keys.write().await.remove(key_id);
        Ok(())
    }
}

impl SoftHsmProvider {
    fn generate_key_material(&self, algorithm: &KeyAlgorithm) -> Result<Vec<u8>, KeyManagementError> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        
        let key_size = match algorithm {
            KeyAlgorithm::AES256 => 32,
            KeyAlgorithm::ChaCha20 => 32,
            KeyAlgorithm::RSA2048 => 256,
            KeyAlgorithm::RSA4096 => 512,
            KeyAlgorithm::ECC256 => 32,
            KeyAlgorithm::ECC384 => 48,
            KeyAlgorithm::Ed25519 => 32,
            KeyAlgorithm::X25519 => 32,
        };

        let mut key_material = vec![0u8; key_size];
        rng.fill_bytes(&mut key_material);
        
        Ok(key_material)
    }
}

impl MockHsmProvider {
    fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            operation_delay_ms: 100, // Simulate HSM latency
        }
    }
}

#[async_trait]
impl HsmProvider for MockHsmProvider {
    async fn generate_key(&self, algorithm: KeyAlgorithm, _policy_id: &str) -> Result<String, KeyManagementError> {
        // Simulate HSM operation delay
        tokio::time::sleep(tokio::time::Duration::from_millis(self.operation_delay_ms)).await;
        
        let key_id = format!("mock-hsm-{}", uuid::Uuid::new_v4());
        
        let key_material = self.generate_mock_key_material(&algorithm);
        
        let metadata = HsmKeyMetadata {
            key_id: key_id.clone(),
            algorithm: algorithm.clone(),
            created_at: Utc::now(),
            key_size: key_material.len() * 8,
            usage_count: 0,
            extractable: false,
            exportable: false,
            attributes: HashMap::new(),
        };

        let mock_key = MockHsmKey {
            id: key_id.clone(),
            algorithm,
            key_material,
            metadata,
        };

        self.keys.write().await.insert(key_id.clone(), mock_key);
        Ok(key_id)
    }

    async fn encrypt(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        tokio::time::sleep(tokio::time::Duration::from_millis(self.operation_delay_ms)).await;
        
        if !self.keys.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        let mut result = Vec::with_capacity(data.len() + 16);
        result.extend_from_slice(b"MOCK-HSM-ENC:");
        result.extend_from_slice(data);
        
        Ok(result)
    }

    async fn decrypt(&self, key_id: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        tokio::time::sleep(tokio::time::Duration::from_millis(self.operation_delay_ms)).await;
        
        if !self.keys.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        if !encrypted_data.starts_with(b"MOCK-HSM-ENC:") {
            return Err(KeyManagementError::DecryptionFailed { 
                reason: "Invalid mock ciphertext format".to_string() 
            });
        }

        Ok(encrypted_data[13..].to_vec())
    }

    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        tokio::time::sleep(tokio::time::Duration::from_millis(self.operation_delay_ms)).await;
        
        if !self.keys.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(b"MOCK-HSM-SIG:");
        signature.extend_from_slice(&data[..std::cmp::min(data.len(), 50)]);
        
        Ok(signature)
    }

    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, KeyManagementError> {
        tokio::time::sleep(tokio::time::Duration::from_millis(self.operation_delay_ms)).await;
        
        if !self.keys.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        if !signature.starts_with(b"MOCK-HSM-SIG:") {
            return Ok(false);
        }

        let expected_suffix = &data[..std::cmp::min(data.len(), 50)];
        let signature_suffix = &signature[13..];
        
        Ok(signature_suffix == expected_suffix)
    }

    async fn derive_key(&self, master_key_id: &str, context: &[u8]) -> Result<Vec<u8>, KeyManagementError> {
        tokio::time::sleep(tokio::time::Duration::from_millis(self.operation_delay_ms)).await;
        
        if !self.keys.read().await.contains_key(master_key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: master_key_id.to_string() });
        }

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"MOCK-HSM-KDF:");
        hasher.update(master_key_id.as_bytes());
        hasher.update(context);
        
        Ok(hasher.finalize().to_vec())
    }

    async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>, KeyManagementError> {
        tokio::time::sleep(tokio::time::Duration::from_millis(self.operation_delay_ms)).await;
        
        if !self.keys.read().await.contains_key(key_id) {
            return Err(KeyManagementError::KeyNotFound { key_id: key_id.to_string() });
        }

        Ok(format!("MOCK-HSM-PUBKEY-{}", key_id).into_bytes())
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), KeyManagementError> {
        tokio::time::sleep(tokio::time::Duration::from_millis(self.operation_delay_ms)).await;
        
        self.keys.write().await.remove(key_id);
        Ok(())
    }
}

impl MockHsmProvider {
    fn generate_mock_key_material(&self, algorithm: &KeyAlgorithm) -> Vec<u8> {
        let key_size = match algorithm {
            KeyAlgorithm::AES256 => 32,
            KeyAlgorithm::ChaCha20 => 32,
            KeyAlgorithm::RSA2048 => 256,
            KeyAlgorithm::RSA4096 => 512,
            KeyAlgorithm::ECC256 => 32,
            KeyAlgorithm::ECC384 => 48,
            KeyAlgorithm::Ed25519 => 32,
            KeyAlgorithm::X25519 => 32,
        };

        // Generate deterministic key material for testing
        let mut key_material = Vec::with_capacity(key_size);
        for i in 0..key_size {
            key_material.push((i % 256) as u8);
        }
        
        key_material
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hsm_factory() -> Result<(), Box<dyn std::error::Error>> {
        let factory = HsmFactory::new();
        
        let providers = factory.list_providers();
        assert!(providers.len() >= 5);
        assert!(providers.contains(&"mock".to_string()));
        
        Ok(())
    }

    #[tokio::test]
    async fn test_mock_hsm_provider() -> Result<(), Box<dyn std::error::Error>> {
        let factory = HsmFactory::new();
        let config = HsmProviderConfig {
            provider_type: HsmProviderType::Mock,
            connection_string: "mock://localhost".to_string(),
            credentials: HashMap::new(),
            partition_name: None,
            slot_id: None,
            timeout_seconds: 30,
            retry_attempts: 3,
            enable_failover: false,
            failover_providers: vec![],
        };

        let provider = factory.create_provider("mock", &config).await?;

        // Test key generation
        let key_id = provider.generate_key(KeyAlgorithm::AES256, "test-policy").await?;
        assert!(key_id.starts_with("mock-hsm-"));

        // Test encryption/decryption
        let plaintext = b"Hello, HSM World!";
        let ciphertext = provider.encrypt(&key_id, plaintext).await?;
        let decrypted = provider.decrypt(&key_id, &ciphertext).await?;
        
        assert_eq!(plaintext, &decrypted[..]);

        // Test signing/verification
        let signature = provider.sign(&key_id, plaintext).await?;
        let is_valid = provider.verify(&key_id, plaintext, &signature).await?;
        
        assert!(is_valid);

        // Test key derivation
        let context = b"test-context";
        let derived_key = provider.derive_key(&key_id, context).await?;
        assert_eq!(derived_key.len(), 32); // SHA256 output size

        Ok(())
    }

    #[tokio::test]
    async fn test_softhsm_provider() -> Result<(), Box<dyn std::error::Error>> {
        let factory = HsmFactory::new();
        let config = HsmProviderConfig {
            provider_type: HsmProviderType::SoftHsm,
            connection_string: "softhsm://slot0".to_string(),
            credentials: HashMap::new(),
            partition_name: None,
            slot_id: Some(0),
            timeout_seconds: 30,
            retry_attempts: 3,
            enable_failover: false,
            failover_providers: vec![],
        };

        let provider = factory.create_provider("softhsm", &config).await?;

        // Test key operations
        let key_id = provider.generate_key(KeyAlgorithm::AES256, "test-policy").await?;
        assert!(key_id.starts_with("softhsm-"));

        let plaintext = b"SoftHSM Test Data";
        let ciphertext = provider.encrypt(&key_id, plaintext).await?;
        let decrypted = provider.decrypt(&key_id, &ciphertext).await?;
        
        assert_eq!(plaintext, &decrypted[..]);

        Ok(())
    }
}