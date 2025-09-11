use async_trait::async_trait;
use anyhow::Result;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Storage backend types supported by the system
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum StorageType {
    #[default]
    Local,
    Sftp,
    S3Compatible,
    GoogleCloud,
    AzureBlob,
    PostgreSQL,
    Redis,
    WebDav,
    Ipfs,
    MultiCloud,
    CachedCloud,
}

impl std::str::FromStr for StorageType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local" => Ok(StorageType::Local),
            "sftp" => Ok(StorageType::Sftp),
            "s3" | "s3compatible" | "s3-compatible" => Ok(StorageType::S3Compatible),
            "gcs" | "googlecloud" | "google-cloud" => Ok(StorageType::GoogleCloud),
            "azure" | "azureblob" | "azure-blob" => Ok(StorageType::AzureBlob),
            "postgresql" | "postgres" | "pg" => Ok(StorageType::PostgreSQL),
            "redis" => Ok(StorageType::Redis),
            "webdav" | "dav" => Ok(StorageType::WebDav),
            "ipfs" => Ok(StorageType::Ipfs),
            "multicloud" | "multi-cloud" => Ok(StorageType::MultiCloud),
            "cached" | "cachedcloud" | "cached-cloud" => Ok(StorageType::CachedCloud),
            _ => Err(format!("Unknown storage type: {}", s)),
        }
    }
}

/// Metadata for a stored chunk
#[derive(Debug, Clone)]
pub struct ChunkMetadata {
    pub nonce: String,
    pub sender_public_key: String,
    pub size: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Storage backend abstraction trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Save an encrypted chunk to storage
    /// Returns the storage key/identifier for the chunk
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String>;
    
    /// Save chunk metadata (nonce, sender public key, etc.)
    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()>;
    
    /// Load an encrypted chunk from storage
    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>>;
    
    /// Load chunk metadata
    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata>;
    
    /// List all chunk hashes for a recipient
    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>>;
    
    /// Delete a chunk and its metadata
    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()>;
    
    /// Test connection/authentication to the storage backend
    async fn test_connection(&self) -> Result<()>;
    
    /// Get the backend type
    fn backend_type(&self) -> StorageType;
    
    /// Get backend-specific configuration info
    fn get_info(&self) -> HashMap<String, String> {
        HashMap::new()
    }
    
    /// Optional: Batch operations for better performance
    async fn save_chunks_batch(&self, recipient: &str, chunks: Vec<(String, Vec<u8>, ChunkMetadata)>) -> Result<Vec<String>> {
        let mut results = Vec::new();
        for (hash, data, metadata) in chunks {
            let key = self.save_chunk(recipient, &hash, &data).await?;
            self.save_metadata(recipient, &hash, &metadata).await?;
            results.push(key);
        }
        Ok(results)
    }
    
    /// Optional: Health check for monitoring
    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();
        health.insert("status".to_string(), "unknown".to_string());
        Ok(health)
    }
    
    /// Check if a chunk exists
    async fn chunk_exists(&self, recipient: &str, chunk_hash: &str) -> Result<bool> {
        match self.load_chunk(recipient, chunk_hash).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// List metadata for all chunks
    async fn list_metadata(&self, recipient: &str) -> Result<Vec<(String, ChunkMetadata)>> {
        let chunks = self.list_chunks(recipient).await?;
        let mut results = Vec::new();
        for chunk_hash in chunks {
            if let Ok(metadata) = self.load_metadata(recipient, &chunk_hash).await {
                results.push((chunk_hash, metadata));
            }
        }
        Ok(results)
    }
    
    /// Get storage backend information/statistics
    async fn get_storage_info(&self) -> Result<HashMap<String, String>> {
        Ok(self.get_info())
    }
    
    /// Cleanup old/expired data
    async fn cleanup(&self) -> Result<u64> {
        Ok(0) // Default: no cleanup performed
    }
}

/// Storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageConfig {
    pub backend_type: StorageType,
    pub local: Option<LocalConfig>,
    pub sftp: Option<SftpConfig>,
    pub s3: Option<S3Config>,
    pub gcs: Option<GcsConfig>,
    pub azure: Option<AzureConfig>,
    pub postgresql: Option<PostgreSQLConfig>,
    pub redis: Option<RedisConfig>,
    pub webdav: Option<WebDavConfig>,
    pub ipfs: Option<IpfsConfig>,
    pub replication: Option<ReplicationConfig>,
    pub cached_cloud: Option<CachedCloudConfigSimple>,
}

/// Local filesystem storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalConfig {
    pub base_path: String,
    pub create_dirs: Option<bool>,
}

/// SFTP storage configuration  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SftpConfig {
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_content: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub host_fingerprint_sha256: Option<String>,
    pub base_path: String,
    pub connection_timeout: Option<u64>,
}

/// S3-compatible storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>, // For MinIO, Cloudflare R2, etc.
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub path_prefix: Option<String>,
    pub force_path_style: Option<bool>, // For MinIO compatibility
}

/// Google Cloud Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcsConfig {
    pub bucket: String,
    pub project_id: String,
    pub service_account_key: Option<String>,
    pub service_account_path: Option<String>,
    pub path_prefix: Option<String>,
}

/// Azure Blob Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    pub account_name: String,
    pub account_key: Option<String>,
    pub sas_token: Option<String>,
    pub container: String,
    pub path_prefix: Option<String>,
}

/// PostgreSQL storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgreSQLConfig {
    pub connection_string: String,
    pub table_prefix: Option<String>,
    pub pool_size: Option<u32>,
}

/// Redis storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub cluster_mode: Option<bool>,
    pub key_prefix: Option<String>,
    pub ttl: Option<u64>, // Time to live in seconds
}

/// WebDAV storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDavConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    pub base_path: String,
    pub verify_ssl: Option<bool>,
}

/// IPFS storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsConfig {
    pub api_url: String,
    pub gateway_url: Option<String>,
    pub pin_content: Option<bool>,
}

/// Multi-cloud replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    pub primary_backend: StorageType,
    pub replica_backends: Vec<StorageType>,
    pub consistency_level: ConsistencyLevel,
    pub replication_strategy: ReplicationStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsistencyLevel {
    Eventual,
    Strong,
    Quorum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationStrategy {
    AsyncReplication,
    SyncReplication,
    QuorumWrite,
}

/// Cached cloud storage configuration (simplified for serialization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCloudConfigSimple {
    /// The backend type to use for cloud storage
    pub cloud_backend_type: StorageType,
    /// Local cache directory
    pub cache_dir: String,
    /// Maximum cache size in bytes (0 = unlimited)
    pub max_cache_size: u64,
    /// Cache eviction policy: "lru", "lfu", "fifo", "ttl_only"
    pub eviction_policy: String,
    /// Write policy: "write_through", "write_back", "write_around"
    pub write_policy: String,
    /// How long to keep items in cache without access (in seconds)
    pub ttl_seconds: Option<u64>,
    /// Whether to preload frequently accessed items
    pub enable_prefetch: bool,
}

/// Errors specific to storage operations
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Backend not found: {backend_type:?}")]
    BackendNotFound { backend_type: StorageType },
    
    #[error("Configuration error: {message}")]
    ConfigurationError { message: String },
    
    #[error("Connection failed: {message}")]
    ConnectionError { message: String },
    
    #[error("Authentication failed: {message}")]
    AuthenticationError { message: String },
    
    #[error("Chunk not found: {chunk_hash}")]
    ChunkNotFound { chunk_hash: String },
    
    #[error("Storage full or quota exceeded")]
    StorageFull,
    
    #[error("Network error: {message}")]
    NetworkError { message: String },
    
    #[error("Serialization error: {message}")]
    SerializationError { message: String },
    
    #[error("Backend-specific error: {message}")]
    BackendError { message: String },
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
}