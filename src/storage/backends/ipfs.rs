use async_trait::async_trait;
// Note: IPFS client is not Send, so this implementation is temporarily disabled
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::io::Cursor;
use chrono::{DateTime, Utc};
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient, TryFromUri};

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, IpfsConfig, StorageError};

/// IPFS storage backend
/// Stores chunks and metadata on the InterPlanetary File System (IPFS)
pub struct IpfsBackend {
    client: std::sync::Arc<IpfsClient>,
    config: IpfsConfig,
    api_url: String,
    pin_content: bool,
}

impl IpfsBackend {
    pub async fn new(config: IpfsConfig) -> Result<Self> {
        // Validate configuration
        if config.api_url.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "IPFS API URL cannot be empty".to_string(),
            }.into());
        }

        // Create IPFS client
        let client = IpfsClient::from_str(&config.api_url)
            .map_err(|e| StorageError::ConfigurationError {
                message: format!("Failed to create IPFS client: {}", e),
            })?;

        let pin_content = config.pin_content.unwrap_or(true);
        let api_url = config.api_url.clone();

        Ok(Self {
            client: std::sync::Arc::new(client),
            config,
            api_url,
            pin_content,
        })
    }

    /// Convert IPFS error to our storage error
    fn map_ipfs_error(err: ipfs_api_backend_hyper::Error) -> StorageError {
        match err {
            ipfs_api_backend_hyper::Error::Api(api_err) => {
                StorageError::BackendError {
                    message: format!("IPFS API error: {}", api_err.message),
                }
            }
            ipfs_api_backend_hyper::Error::Http(http_err) => {
                StorageError::NetworkError {
                    message: format!("IPFS HTTP error: {}", http_err),
                }
            }
            // Note: Parse variant might not exist in current version
            // ipfs_api_backend_hyper::Error::Parse(parse_err) => {
            //     StorageError::SerializationError {
            //         message: format!("IPFS parse error: {}", parse_err),
            //     }
            // }
            _ => StorageError::BackendError {
                message: format!("IPFS error: {}", err),
            }
        }
    }

    /// Save mapping between chunk_hash and ipfs_hash
    async fn save_path_mapping(&self, recipient: &str, chunk_hash: &str, ipfs_hash: &str) -> Result<()> {
        // In a real implementation, this would save the mapping to a persistent store
        // For now, we'll just log it
        log::debug!("IPFS mapping: {}:{} -> {}", recipient, chunk_hash, ipfs_hash);
        Ok(())
    }

    /// Get IPFS hash for a chunk
    async fn get_ipfs_hash_for_chunk(&self, _recipient: &str, _chunk_hash: &str) -> Result<String> {
        // In a real implementation, this would retrieve the mapping from a persistent store
        // For now, we'll just return an error
        Err(anyhow!("IPFS mapping not implemented"))
    }
}

// IPFS implementation temporarily disabled due to Send trait issues
// TODO: Fix Send trait issues with ipfs-api-backend-hyper library
#[async_trait]
impl StorageBackend for IpfsBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let _ = (recipient, chunk_hash, data);
        Err(anyhow!("IPFS backend temporarily disabled due to Send trait issues with ipfs-api-backend-hyper library"))
    }

    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        let _ = (recipient, chunk_hash, metadata);
        Err(anyhow!("IPFS backend temporarily disabled due to Send trait issues"))
    }

    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let _ = (recipient, chunk_hash);
        Err(anyhow!("IPFS backend temporarily disabled due to Send trait issues"))
    }

    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let _ = (recipient, chunk_hash);
        Err(anyhow!("IPFS backend temporarily disabled due to Send trait issues"))
    }

    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        let _ = recipient;
        Err(anyhow!("IPFS backend temporarily disabled due to Send trait issues"))
    }

    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let _ = (recipient, chunk_hash);
        Err(anyhow!("IPFS backend temporarily disabled due to Send trait issues"))
    }

    async fn test_connection(&self) -> Result<()> {
        Err(anyhow!("IPFS backend temporarily disabled due to Send trait issues"))
    }

    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();
        health.insert("status".to_string(), "disabled".to_string());
        health.insert("reason".to_string(), "Send trait issues with ipfs-api-backend-hyper".to_string());
        health.insert("url".to_string(), self.api_url.clone());
        Ok(health)
    }

    fn backend_type(&self) -> StorageType {
        StorageType::Ipfs
    }
}