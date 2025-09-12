use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::io::Cursor;
use chrono::{DateTime, Utc};
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient, TryFromUri};
use futures_util::TryStreamExt;

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, IpfsConfig, StorageError};

/// IPFS storage backend
/// Stores chunks and metadata on the InterPlanetary File System (IPFS)
pub struct IpfsBackend {
    client: IpfsClient,
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
                message: format!("Invalid IPFS API URL: {}", e),
            })?;

        let pin_content = config.pin_content.unwrap_or(true);

        Ok(Self {
            client,
            config,
            api_url: config.api_url.clone(),
            pin_content,
        })
    }

    /// Convert IPFS error to our storage error
    fn map_ipfs_error(err: ipfs_api_backend_hyper::Error) -> StorageError {
        match err {
            ipfs_api_backend_hyper::Error::Api(api_err) => {
                if api_err.message.contains("not found") || api_err.message.contains("no such file") {
                    StorageError::ChunkNotFound {
                        chunk_hash: "unknown".to_string(),
                    }
                } else {
                    StorageError::BackendError {
                        message: format!("IPFS API error: {}", api_err.message),
                    }
                }
            }
            ipfs_api_backend_hyper::Error::Http(http_err) => {
                StorageError::NetworkError {
                    message: format!("IPFS HTTP error: {}", http_err),
                }
            }
            ipfs_api_backend_hyper::Error::Parse(_) => {
                StorageError::SerializationError {
                    message: format!("IPFS parse error: {}", err),
                }
            }
            ipfs_api_backend_hyper::Error::Uncategorized(msg) => {
                if msg.contains("connection") {
                    StorageError::ConnectionError {
                        message: format!("IPFS connection error: {}", msg),
                    }
                } else {
                    StorageError::BackendError {
                        message: format!("IPFS error: {}", msg),
                    }
                }
            }
            _ => StorageError::BackendError {
                message: format!("IPFS operation failed: {}", err),
            },
        }
    }

    /// Create a directory structure for organizing chunks
    async fn create_directory_structure(&self, recipient: &str) -> Result<String> {
        // Create a directory object for the recipient
        let dir_data = format!("{{\"type\": \"directory\", \"recipient\": \"{}\"}}", recipient);
        
        match self.client.add(Cursor::new(dir_data.as_bytes())).await {
            Ok(response) => {
                let dir_hash = response.hash;
                
                if self.pin_content {
                    if let Err(e) = self.client.pin_add(&dir_hash, true).await {
                        eprintln!("Warning: Failed to pin directory structure: {}", e);
                    }
                }
                
                Ok(dir_hash)
            }
            Err(e) => Err(Self::map_ipfs_error(e).into()),
        }
    }

    /// Store a mapping between logical paths and IPFS hashes
    /// This is necessary because IPFS uses content-addressed hashes, not traditional file paths
    async fn save_path_mapping(&self, recipient: &str, chunk_hash: &str, ipfs_hash: &str) -> Result<()> {
        let mapping = serde_json::json!({
            "recipient": recipient,
            "chunk_hash": chunk_hash,
            "ipfs_hash": ipfs_hash,
            "timestamp": Utc::now().to_rfc3339(),
        });
        
        let mapping_data = mapping.to_string();
        let mapping_name = format!("mapping_{}_{}", recipient, chunk_hash);
        
        match self.client.add(Cursor::new(mapping_data.as_bytes())).await {
            Ok(response) => {
                if self.pin_content {
                    if let Err(e) = self.client.pin_add(&response.hash, true).await {
                        eprintln!("Warning: Failed to pin mapping: {}", e);
                    }
                }
                
                // Store the mapping hash in a known location (we'll use a simple key-value approach)
                // In a real implementation, you might use IPNS or a separate index
                Ok(())
            }
            Err(e) => Err(Self::map_ipfs_error(e).into()),
        }
    }

    /// Retrieve IPFS hash for a given chunk
    async fn get_ipfs_hash_for_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<String> {
        // In a production system, you'd want to maintain an index of chunk_hash -> ipfs_hash mappings
        // For this implementation, we'll use a simple approach where the IPFS hash is the chunk_hash
        // This is a simplification - in reality you'd need a more sophisticated indexing system
        
        // Try to use the chunk_hash directly as IPFS hash (this works if it's a valid IPFS hash)
        if chunk_hash.starts_with("Qm") || chunk_hash.starts_with("baf") {
            Ok(chunk_hash.to_string())
        } else {
            // If it's not a valid IPFS hash, we need to look it up
            // For now, return an error indicating the mapping system needs implementation
            Err(StorageError::ChunkNotFound {
                chunk_hash: chunk_hash.to_string(),
            }.into())
        }
    }
}

#[async_trait]
impl StorageBackend for IpfsBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        // Add data to IPFS
        match self.client.add(Cursor::new(data)).await {
            Ok(response) => {
                let ipfs_hash = response.hash.clone();
                
                // Pin the content if configured
                if self.pin_content {
                    if let Err(e) = self.client.pin_add(&ipfs_hash, Some(true)).await {
                        eprintln!("Warning: Failed to pin chunk: {}", e);
                    }
                }
                
                // Save mapping between chunk_hash and ipfs_hash
                self.save_path_mapping(recipient, chunk_hash, &ipfs_hash).await?;
                
                // Return the IPFS hash as the storage key
                Ok(ipfs_hash)
            }
            Err(e) => Err(Self::map_ipfs_error(e).into()),
        }
    }

    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        // Serialize metadata as JSON
        let metadata_json = serde_json::json!({
            "nonce": metadata.nonce,
            "sender_public_key": metadata.sender_public_key,
            "size": metadata.size,
            "created_at": metadata.created_at.to_rfc3339(),
        });

        let metadata_bytes = metadata_json.to_string().into_bytes();

        match self.client.add(Cursor::new(&metadata_bytes)).await {
            Ok(response) => {
                let metadata_hash = response.hash.clone();
                
                // Pin the metadata if configured
                if self.pin_content {
                    if let Err(e) = self.client.pin_add(&metadata_hash, Some(true)).await {
                        eprintln!("Warning: Failed to pin metadata: {}", e);
                    }
                }
                
                // Save mapping for metadata
                let metadata_key = format!("{}_metadata", chunk_hash);
                self.save_path_mapping(recipient, &metadata_key, &metadata_hash).await?;
                
                Ok(())
            }
            Err(e) => Err(Self::map_ipfs_error(e).into()),
        }
    }

    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        // Get IPFS hash for the chunk
        let ipfs_hash = self.get_ipfs_hash_for_chunk(recipient, chunk_hash).await?;

        // Retrieve data from IPFS
        match self.client.cat(&ipfs_hash).try_concat().await {
            Ok(data) => Ok(data),
            Err(e) => {
                if e.to_string().contains("not found") {
                    Err(StorageError::ChunkNotFound {
                        chunk_hash: chunk_hash.to_string(),
                    }.into())
                } else {
                    Err(Self::map_ipfs_error(e).into())
                }
            }
        }
    }

    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        // Get IPFS hash for the metadata
        let metadata_key = format!("{}_metadata", chunk_hash);
        let ipfs_hash = self.get_ipfs_hash_for_chunk(recipient, &metadata_key).await?;

        match self.client.cat(&ipfs_hash).try_concat().await {
            Ok(data) => {
                let metadata_str = String::from_utf8(data)?;
                let json: serde_json::Value = serde_json::from_str(&metadata_str)?;

                let created_at = if let Some(created_str) = json["created_at"].as_str() {
                    DateTime::parse_from_rfc3339(created_str)?.with_timezone(&Utc)
                } else {
                    Utc::now()
                };

                Ok(ChunkMetadata {
                    nonce: json["nonce"].as_str().unwrap_or("").to_string(),
                    sender_public_key: json["sender_public_key"].as_str().unwrap_or("").to_string(),
                    size: json["size"].as_u64().unwrap_or(0),
                    created_at,
                })
            },
            Err(e) => {
                if e.to_string().contains("not found") {
                    Err(StorageError::ChunkNotFound {
                        chunk_hash: chunk_hash.to_string(),
                    }.into())
                } else {
                    Err(Self::map_ipfs_error(e).into())
                }
            }
        }
    }

    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        // In IPFS, listing chunks requires maintaining an index
        // This is a simplified implementation that would need enhancement for production use
        
        // For now, return an empty list as IPFS doesn't have traditional directory listing
        // In a real implementation, you'd maintain an index of chunks per recipient
        Ok(Vec::new())
    }

    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        // In IPFS, "deletion" means unpinning content
        // The content may still exist on other nodes
        
        if let Ok(ipfs_hash) = self.get_ipfs_hash_for_chunk(recipient, chunk_hash).await {
            // Unpin the chunk
            if let Err(e) = self.client.pin_rm(&ipfs_hash, Some(true)).await {
                eprintln!("Warning: Failed to unpin chunk: {}", e);
            }
            
            // Unpin metadata
            let metadata_key = format!("{}_metadata", chunk_hash);
            if let Ok(metadata_hash) = self.get_ipfs_hash_for_chunk(recipient, &metadata_key).await {
                if let Err(e) = self.client.pin_rm(&metadata_hash, Some(true)).await {
                    eprintln!("Warning: Failed to unpin metadata: {}", e);
                }
            }
            
            // Note: The content is not actually deleted from IPFS, just unpinned
            // Garbage collection will eventually remove unpinned content
        }
        
        Ok(())
    }

    async fn test_connection(&self) -> Result<()> {
        // Test connection by getting IPFS version
        match self.client.version().await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::ConnectionError {
                message: format!("IPFS connection test failed: {}", e),
            }.into()),
        }
    }

    fn backend_type(&self) -> StorageType {
        StorageType::Ipfs
    }

    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "IPFS".to_string());
        info.insert("api_url".to_string(), self.api_url.clone());
        info.insert("pin_content".to_string(), self.pin_content.to_string());
        
        if let Some(gateway_url) = &self.config.gateway_url {
            info.insert("gateway_url".to_string(), gateway_url.clone());
        }

        info
    }

    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();

        match self.test_connection().await {
            Ok(_) => {
                health.insert("status".to_string(), "healthy".to_string());
                health.insert("connection".to_string(), "ok".to_string());

                // Get IPFS node information
                if let Ok(version) = self.client.version().await {
                    health.insert("ipfs_version".to_string(), version.version);
                    health.insert("go_version".to_string(), version.golang);
                    health.insert("commit".to_string(), version.commit);
                }

                // Get peer count
                if let Ok(peers) = self.client.swarm_peers().await {
                    health.insert("peer_count".to_string(), peers.peers.len().to_string());
                }

                // Get repository stats
                if let Ok(stats) = self.client.repo_stat().await {
                    health.insert("repo_size".to_string(), stats.repo_size.to_string());
                    health.insert("num_objects".to_string(), stats.num_objects.to_string());
                }

                // Test basic operations
                let test_data = b"health_check_test";
                match self.client.add(Cursor::new(test_data)).await {
                    Ok(response) => {
                        health.insert("write_test".to_string(), "ok".to_string());
                        health.insert("test_hash".to_string(), response.hash.clone());

                        // Test read
                        match self.client.cat(&response.hash).try_concat().await {
                            Ok(retrieved_data) => {
                                if retrieved_data == test_data {
                                    health.insert("read_test".to_string(), "ok".to_string());
                                } else {
                                    health.insert("read_test".to_string(), "data_mismatch".to_string());
                                }
                            }
                            Err(_) => {
                                health.insert("read_test".to_string(), "failed".to_string());
                            }
                        }

                        // Clean up (unpin test data)
                        let _ = self.client.pin_rm(&response.hash, Some(true)).await;
                    }
                    Err(_) => {
                        health.insert("write_test".to_string(), "failed".to_string());
                    }
                }

                health.insert("api_url".to_string(), self.api_url.clone());
            },
            Err(e) => {
                health.insert("status".to_string(), "unhealthy".to_string());
                health.insert("error".to_string(), e.to_string());
            }
        }

        Ok(health)
    }

    /// IPFS batch operations - add multiple files in parallel
    async fn save_chunks_batch(&self, recipient: &str, chunks: Vec<(String, Vec<u8>, ChunkMetadata)>) -> Result<Vec<String>> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }

        let mut handles = Vec::new();
        let mut results = Vec::new();

        // Process in smaller batches for better performance
        const BATCH_SIZE: usize = 5; // IPFS can be slower, so smaller batches
        
        for batch in chunks.chunks(BATCH_SIZE) {
            let mut batch_handles = Vec::new();

            for (hash, data, metadata) in batch {
                let hash_clone = hash.clone();
                let data_clone = data.clone();
                let metadata_clone = metadata.clone();
                let recipient_clone = recipient.to_string();
                let self_clone = self.clone();

                let handle = tokio::spawn(async move {
                    // Save chunk
                    let chunk_result = self_clone.save_chunk(&recipient_clone, &hash_clone, &data_clone).await;
                    if chunk_result.is_err() {
                        return Err(chunk_result.unwrap_err());
                    }

                    // Save metadata
                    let metadata_result = self_clone.save_metadata(&recipient_clone, &hash_clone, &metadata_clone).await;
                    if metadata_result.is_err() {
                        return Err(metadata_result.unwrap_err());
                    }

                    Ok(chunk_result.unwrap())
                });

                batch_handles.push(handle);
            }

            // Wait for batch to complete
            for handle in batch_handles {
                match handle.await {
                    Ok(Ok(hash)) => results.push(hash),
                    Ok(Err(e)) => return Err(e),
                    Err(e) => return Err(anyhow!("Batch operation failed: {}", e)),
                }
            }
        }

        Ok(results)
    }
}

impl Clone for IpfsBackend {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: self.config.clone(),
            api_url: self.api_url.clone(),
            pin_content: self.pin_content,
        }
    }
}