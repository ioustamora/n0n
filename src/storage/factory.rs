use std::sync::Arc;
use anyhow::Result;
use crate::storage::backend::{StorageBackend, StorageConfig, StorageType, StorageError};
use crate::storage::backends::{LocalBackend, SftpBackend, S3Backend, GcsBackend, AzureBackend, PostgreSQLBackend, RedisBackend, WebDavBackend, IpfsBackend, MultiCloudBackend, CachedCloudBackend, CachedCloudConfig, CacheEvictionPolicy, CacheWritePolicy};
use crate::storage::encryption::{EncryptedStorageBackend, EncryptionConfig};
use crate::storage::analytics::{AnalyticsStorageBackend, QuotaConfig};

/// Storage backend factory for creating storage instances
pub struct StorageFactory;

impl StorageFactory {
    /// Create a storage backend from configuration
    pub fn create_backend(config: StorageConfig) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<dyn StorageBackend>>> + Send>> {
        Box::pin(async move {
        match config.backend_type {
            StorageType::Local => {
                let local_config = config.local.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Local storage config is required".to_string(),
                    }
                })?;
                
                let backend = LocalBackend::new(local_config).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
            
            StorageType::Sftp => {
                let sftp_config = config.sftp.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "SFTP storage config is required".to_string(),
                    }
                })?;
                
                let backend = SftpBackend::new(sftp_config).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
            
            StorageType::S3Compatible => {
                let s3_config = config.s3.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "S3 storage config is required".to_string(),
                    }
                })?;
                
                let backend = S3Backend::new(s3_config).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
            
            StorageType::GoogleCloud => {
                let gcs_config = config.gcs.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Google Cloud storage config is required".to_string(),
                    }
                })?;
                
                let backend = GcsBackend::new(gcs_config).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
            
            StorageType::AzureBlob => {
                let azure_config = config.azure.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Azure Blob storage config is required".to_string(),
                    }
                })?;
                
                let backend = AzureBackend::new(azure_config).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
            
            StorageType::PostgreSQL => {
                let pg_config = config.postgresql.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "PostgreSQL storage config is required".to_string(),
                    }
                })?;
                
                let backend = PostgreSQLBackend::new(pg_config).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
            
            StorageType::Redis => {
                let redis_config = config.redis.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Redis storage config is required".to_string(),
                    }
                })?;
                
                let backend = RedisBackend::new(redis_config).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
            
            StorageType::WebDav => {
                let webdav_config = config.webdav.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "WebDAV storage config is required".to_string(),
                    }
                })?;
                
                let backend = WebDavBackend::new(webdav_config).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
            
            StorageType::Ipfs => {
                let ipfs_config = config.ipfs.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "IPFS storage config is required".to_string(),
                    }
                })?;
                
                let backend = IpfsBackend::new(ipfs_config).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
            
            StorageType::MultiCloud => {
                let replication_config = config.replication.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Replication config is required for MultiCloud".to_string(),
                    }
                })?;
                
                // For MultiCloud, we need all the individual backend configs
                let mut all_configs = std::collections::HashMap::new();
                
                if let Some(local_config) = config.local {
                    all_configs.insert(StorageType::Local, StorageConfig { 
                        backend_type: StorageType::Local, 
                        local: Some(local_config),
                        ..Default::default() 
                    });
                }
                
                if let Some(sftp_config) = config.sftp {
                    all_configs.insert(StorageType::Sftp, StorageConfig { 
                        backend_type: StorageType::Sftp, 
                        sftp: Some(sftp_config),
                        ..Default::default() 
                    });
                }
                
                if let Some(s3_config) = config.s3 {
                    all_configs.insert(StorageType::S3Compatible, StorageConfig { 
                        backend_type: StorageType::S3Compatible, 
                        s3: Some(s3_config),
                        ..Default::default() 
                    });
                }
                
                if let Some(gcs_config) = config.gcs {
                    all_configs.insert(StorageType::GoogleCloud, StorageConfig { 
                        backend_type: StorageType::GoogleCloud, 
                        gcs: Some(gcs_config),
                        ..Default::default() 
                    });
                }
                
                if let Some(azure_config) = config.azure {
                    all_configs.insert(StorageType::AzureBlob, StorageConfig { 
                        backend_type: StorageType::AzureBlob, 
                        azure: Some(azure_config),
                        ..Default::default() 
                    });
                }
                
                if let Some(pg_config) = config.postgresql {
                    all_configs.insert(StorageType::PostgreSQL, StorageConfig { 
                        backend_type: StorageType::PostgreSQL, 
                        postgresql: Some(pg_config),
                        ..Default::default() 
                    });
                }
                
                if let Some(redis_config) = config.redis {
                    all_configs.insert(StorageType::Redis, StorageConfig { 
                        backend_type: StorageType::Redis, 
                        redis: Some(redis_config),
                        ..Default::default() 
                    });
                }
                
                let backend = MultiCloudBackend::new(replication_config, all_configs).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
            
            StorageType::CachedCloud => {
                let cached_config = config.cached_cloud.clone().ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Cached cloud storage config is required".to_string(),
                    }
                })?;
                
                // Parse eviction policy
                let eviction_policy = match cached_config.eviction_policy.as_str() {
                    "lru" => CacheEvictionPolicy::Lru,
                    "lfu" => CacheEvictionPolicy::Lfu,
                    "fifo" => CacheEvictionPolicy::Fifo,
                    "ttl_only" => CacheEvictionPolicy::TtlOnly,
                    _ => return Err(StorageError::ConfigurationError {
                        message: format!("Invalid eviction policy: {}", cached_config.eviction_policy),
                    }.into()),
                };
                
                // Parse write policy
                let write_policy = match cached_config.write_policy.as_str() {
                    "write_through" => CacheWritePolicy::WriteThrough,
                    "write_back" => CacheWritePolicy::WriteBack,
                    "write_around" => CacheWritePolicy::WriteAround,
                    _ => return Err(StorageError::ConfigurationError {
                        message: format!("Invalid write policy: {}", cached_config.write_policy),
                    }.into()),
                };
                
                // Create cloud backend configuration
                let mut cloud_config = config.clone();
                cloud_config.backend_type = cached_config.cloud_backend_type;
                cloud_config.cached_cloud = None; // Prevent recursion
                
                let cached_cloud_config = CachedCloudConfig {
                    cloud_config,
                    cache_dir: cached_config.cache_dir,
                    max_cache_size: cached_config.max_cache_size,
                    eviction_policy,
                    write_policy,
                    ttl_seconds: cached_config.ttl_seconds,
                    enable_prefetch: cached_config.enable_prefetch,
                };
                
                let backend = CachedCloudBackend::new(cached_cloud_config).await?;
                Ok(Arc::new(backend) as Arc<dyn StorageBackend>)
            }
        }
        })
    }
    
    /// Get a list of available backend types
    pub fn available_backends() -> Vec<StorageType> {
        vec![
            StorageType::Local,
            StorageType::Sftp,
            StorageType::S3Compatible,
            StorageType::GoogleCloud,
            StorageType::AzureBlob,
            StorageType::PostgreSQL,
            StorageType::Redis,
            StorageType::WebDav,
            StorageType::Ipfs,
            StorageType::MultiCloud,
            StorageType::CachedCloud,
        ]
    }
    
    /// Create an encrypted storage backend wrapper around any backend
    pub async fn create_encrypted_backend(
        config: StorageConfig, 
        encryption_config: EncryptionConfig
    ) -> Result<Arc<dyn StorageBackend>> {
        let base_backend = Self::create_backend(config).await?;
        let encrypted_backend = EncryptedStorageBackend::new(base_backend, encryption_config)
            .map_err(|e| StorageError::EncryptionFailed(e.to_string()))?;
        Ok(Arc::new(encrypted_backend))
    }
    
    /// Create an analytics-enabled storage backend wrapper around any backend
    pub async fn create_analytics_backend(
        config: StorageConfig,
        quota_config: QuotaConfig,
        stats_file_path: Option<String>
    ) -> Result<Arc<dyn StorageBackend>> {
        let base_backend = Self::create_backend(config).await?;
        let analytics_backend = AnalyticsStorageBackend::new(base_backend, quota_config, stats_file_path);
        Ok(Arc::new(analytics_backend))
    }
    
    /// Create a fully featured backend with both encryption and analytics
    pub async fn create_enhanced_backend(
        config: StorageConfig,
        encryption_config: Option<EncryptionConfig>,
        quota_config: Option<QuotaConfig>,
        stats_file_path: Option<String>
    ) -> Result<Arc<dyn StorageBackend>> {
        let mut backend = Self::create_backend(config).await?;
        
        // Add encryption layer if requested
        if let Some(enc_config) = encryption_config {
            let encrypted_backend = EncryptedStorageBackend::new(backend, enc_config)
                .map_err(|e| StorageError::EncryptionFailed(e.to_string()))?;
            backend = Arc::new(encrypted_backend);
        }
        
        // Add analytics layer if requested
        if let Some(quota_config) = quota_config {
            let analytics_backend = AnalyticsStorageBackend::new(backend, quota_config, stats_file_path);
            backend = Arc::new(analytics_backend);
        }
        
        Ok(backend)
    }
    
    /// Validate a storage configuration without creating the backend
    pub async fn validate_config(config: &StorageConfig) -> Result<()> {
        match config.backend_type {
            StorageType::Local => {
                let _local_config = config.local.as_ref().ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Local storage config is required".to_string(),
                    }
                })?;
                
                // Validate local config
                Ok(())
            }
            
            StorageType::Sftp => {
                let _sftp_config = config.sftp.as_ref().ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "SFTP storage config is required".to_string(),
                    }
                })?;
                
                // Validate SFTP config
                Ok(())
            }
            
            StorageType::S3Compatible => {
                let _s3_config = config.s3.as_ref().ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "S3 storage config is required".to_string(),
                    }
                })?;
                
                // Validate S3 config
                Ok(())
            }
            
            StorageType::GoogleCloud => {
                let _gcs_config = config.gcs.as_ref().ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Google Cloud storage config is required".to_string(),
                    }
                })?;
                
                // Validate GCS config
                Ok(())
            }
            
            StorageType::AzureBlob => {
                let _azure_config = config.azure.as_ref().ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Azure Blob storage config is required".to_string(),
                    }
                })?;
                
                // Validate Azure config
                Ok(())
            }
            
            StorageType::WebDav => {
                let _webdav_config = config.webdav.as_ref().ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "WebDAV storage config is required".to_string(),
                    }
                })?;
                
                // Validate WebDAV config
                Ok(())
            }
            
            StorageType::Ipfs => {
                let _ipfs_config = config.ipfs.as_ref().ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "IPFS storage config is required".to_string(),
                    }
                })?;
                
                // Validate IPFS config
                Ok(())
            }
            
            StorageType::CachedCloud => {
                let _cached_config = config.cached_cloud.as_ref().ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Cached cloud storage config is required".to_string(),
                    }
                })?;
                
                // Validate cached cloud config
                Ok(())
            }
            
            _ => {
                Err(anyhow::anyhow!("Backend type {:?} not yet supported", config.backend_type))
            }
        }
    }
}

/// Storage manager that maintains multiple backend instances
pub struct StorageManager {
    backends: std::collections::HashMap<String, Arc<dyn StorageBackend>>,
    primary_backend_id: Option<String>,
}

impl StorageManager {
    pub fn new() -> Self {
        Self {
            backends: std::collections::HashMap::new(),
            primary_backend_id: None,
        }
    }
    
    /// Register a storage backend with an identifier
    pub async fn register_backend(&mut self, id: String, config: StorageConfig) -> Result<()> {
        let backend = StorageFactory::create_backend(config).await?;
        
        // Test the connection before registering
        backend.test_connection().await?;
        
        if self.primary_backend_id.is_none() {
            self.primary_backend_id = Some(id.clone());
        }
        
        self.backends.insert(id, backend);
        Ok(())
    }
    
    /// Get a storage backend by ID
    pub fn get_backend(&self, id: &str) -> Option<Arc<dyn StorageBackend>> {
        self.backends.get(id).cloned()
    }
    
    /// Get the primary storage backend
    pub fn get_primary_backend(&self) -> Option<Arc<dyn StorageBackend>> {
        if let Some(id) = &self.primary_backend_id {
            self.get_backend(id)
        } else {
            None
        }
    }
    
    /// List all registered backend IDs
    pub fn list_backends(&self) -> Vec<String> {
        self.backends.keys().cloned().collect()
    }
    
    /// Set the primary backend
    pub fn set_primary_backend(&mut self, id: String) -> Result<()> {
        if self.backends.contains_key(&id) {
            self.primary_backend_id = Some(id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Backend '{}' not found", id))
        }
    }
    
    /// Remove a backend
    pub fn remove_backend(&mut self, id: &str) -> Option<Arc<dyn StorageBackend>> {
        if Some(id) == self.primary_backend_id.as_deref() {
            self.primary_backend_id = None;
        }
        self.backends.remove(id)
    }
}

impl Default for StorageManager {
    fn default() -> Self {
        Self::new()
    }
}