use std::sync::Arc;
use anyhow::Result;
use crate::storage::backend::{StorageBackend, StorageConfig, StorageType, StorageError};
use crate::storage::backends::{LocalBackend, SftpBackend, S3Backend, GcsBackend, PostgreSQLBackend, RedisBackend, MultiCloudBackend};

/// Storage backend factory for creating storage instances
pub struct StorageFactory;

impl StorageFactory {
    /// Create a storage backend from configuration
    pub async fn create_backend(config: StorageConfig) -> Result<Arc<dyn StorageBackend>> {
        match config.backend_type {
            StorageType::Local => {
                let local_config = config.local.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Local storage config is required".to_string(),
                    }
                })?;
                
                let backend = LocalBackend::new(local_config).await?;
                Ok(Arc::new(backend))
            }
            
            StorageType::Sftp => {
                let sftp_config = config.sftp.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "SFTP storage config is required".to_string(),
                    }
                })?;
                
                let backend = SftpBackend::new(sftp_config).await?;
                Ok(Arc::new(backend))
            }
            
            StorageType::S3Compatible => {
                let s3_config = config.s3.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "S3 storage config is required".to_string(),
                    }
                })?;
                
                let backend = S3Backend::new(s3_config).await?;
                Ok(Arc::new(backend))
            }
            
            StorageType::GoogleCloud => {
                let gcs_config = config.gcs.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Google Cloud storage config is required".to_string(),
                    }
                })?;
                
                let backend = GcsBackend::new(gcs_config).await?;
                Ok(Arc::new(backend))
            }
            
            StorageType::AzureBlob => {
                let _azure_config = config.azure.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Azure Blob storage config is required".to_string(),
                    }
                })?;
                
                // TODO: Implement AzureBackend
                Err(anyhow::anyhow!("Azure Blob backend not yet implemented"))
            }
            
            StorageType::PostgreSQL => {
                let pg_config = config.postgresql.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "PostgreSQL storage config is required".to_string(),
                    }
                })?;
                
                let backend = PostgreSQLBackend::new(pg_config).await?;
                Ok(Arc::new(backend))
            }
            
            StorageType::Redis => {
                let redis_config = config.redis.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Redis storage config is required".to_string(),
                    }
                })?;
                
                let backend = RedisBackend::new(redis_config).await?;
                Ok(Arc::new(backend))
            }
            
            StorageType::WebDav => {
                let _webdav_config = config.webdav.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "WebDAV storage config is required".to_string(),
                    }
                })?;
                
                // TODO: Implement WebDavBackend
                Err(anyhow::anyhow!("WebDAV backend not yet implemented"))
            }
            
            StorageType::Ipfs => {
                let _ipfs_config = config.ipfs.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "IPFS storage config is required".to_string(),
                    }
                })?;
                
                // TODO: Implement IpfsBackend
                Err(anyhow::anyhow!("IPFS backend not yet implemented"))
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
                Ok(Arc::new(backend))
            }
            
            StorageType::CachedCloud => {
                // TODO: Implement CachedCloudBackend
                Err(anyhow::anyhow!("CachedCloud backend not yet implemented"))
            }
        }
    }
    
    /// Get a list of available backend types
    pub fn available_backends() -> Vec<StorageType> {
        vec![
            StorageType::Local,
            StorageType::Sftp,
            StorageType::S3Compatible,
            StorageType::GoogleCloud,
            StorageType::PostgreSQL,
            StorageType::Redis,
            StorageType::MultiCloud,
            // Future backends:
            // StorageType::AzureBlob,
            // StorageType::WebDav,
            // StorageType::Ipfs,
            // StorageType::CachedCloud,
        ]
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