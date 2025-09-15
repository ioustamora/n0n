use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::io::Cursor;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient, TryFromUri};
use tokio::task;
use futures_util::TryStreamExt;

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

// IPFS backend implementation using spawn_blocking to handle Send trait issues
#[async_trait]
impl StorageBackend for IpfsBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let client = self.client.clone();
        let data_vec = data.to_vec();
        let pin_content = self.pin_content;
        let recipient = recipient.to_string();
        let chunk_hash = chunk_hash.to_string();

        // Use spawn_blocking to handle the non-Send IPFS client
        let ipfs_hash = task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                let cursor = Cursor::new(data_vec);

                // Add the chunk to IPFS
                let add_result = client.add(cursor).await
                    .map_err(Self::map_ipfs_error)?;

                let ipfs_hash = add_result.hash;

                // Pin the content if configured
                if pin_content {
                    client.pin_add(&ipfs_hash, false).await
                        .map_err(Self::map_ipfs_error)?;
                }

                Ok::<String, anyhow::Error>(ipfs_hash)
            })
        }).await.map_err(|e| StorageError::BackendError {
            message: format!("Task join error: {}", e),
        })??;

        // Save the mapping for future retrieval
        self.save_path_mapping(&recipient, &chunk_hash, &ipfs_hash).await?;

        log::debug!("Saved chunk {} for {} to IPFS: {}", chunk_hash, recipient, ipfs_hash);
        Ok(ipfs_hash)
    }

    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        let client = self.client.clone();
        let pin_content = self.pin_content;
        let recipient = recipient.to_string();
        let chunk_hash = chunk_hash.to_string();

        // Serialize metadata to JSON
        let metadata_json = serde_json::to_vec(metadata)
            .map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            })?;

        // Use spawn_blocking to handle the non-Send IPFS client
        let metadata_hash = task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                let cursor = Cursor::new(metadata_json);

                // Add metadata to IPFS
                let add_result = client.add(cursor).await
                    .map_err(Self::map_ipfs_error)?;

                let metadata_hash = add_result.hash;

                // Pin the metadata if configured
                if pin_content {
                    client.pin_add(&metadata_hash, false).await
                        .map_err(Self::map_ipfs_error)?;
                }

                Ok::<String, anyhow::Error>(metadata_hash)
            })
        }).await.map_err(|e| StorageError::BackendError {
            message: format!("Task join error: {}", e),
        })??;

        // Save mapping for metadata
        let metadata_key = format!("{}_metadata", chunk_hash);
        self.save_path_mapping(&recipient, &metadata_key, &metadata_hash).await?;

        log::debug!("Saved metadata for chunk {} for {} to IPFS: {}", chunk_hash, recipient, metadata_hash);
        Ok(())
    }

    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        // Get IPFS hash for this chunk
        let ipfs_hash = self.get_ipfs_hash_for_chunk(recipient, chunk_hash).await?;
        let ipfs_hash_clone = ipfs_hash.clone();
        let client = self.client.clone();

        // Use spawn_blocking to handle the non-Send IPFS client
        let data = task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                // Retrieve the chunk from IPFS
                let data_stream = client.cat(&ipfs_hash_clone);

                // Collect all bytes from the stream
                let mut data = Vec::new();
                let stream = data_stream;
                use futures_util::pin_mut;
                pin_mut!(stream);

                while let Some(chunk) = stream.try_next().await.map_err(|e| StorageError::BackendError {
                    message: format!("Failed to retrieve chunk from IPFS: {}", e),
                })? {
                    data.extend_from_slice(&chunk);
                }

                Ok::<Vec<u8>, anyhow::Error>(data)
            })
        }).await.map_err(|e| StorageError::BackendError {
            message: format!("Task join error: {}", e),
        })??;

        log::debug!("Retrieved chunk {} for {} from IPFS ({})", chunk_hash, recipient, &ipfs_hash);
        Ok(data)
    }

    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        // Get IPFS hash for metadata
        let metadata_key = format!("{}_metadata", chunk_hash);
        let ipfs_hash = self.get_ipfs_hash_for_chunk(recipient, &metadata_key).await?;
        let ipfs_hash_clone = ipfs_hash.clone();
        let client = self.client.clone();

        // Use spawn_blocking to handle the non-Send IPFS client
        let metadata = task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                // Retrieve the metadata from IPFS
                let data_stream = client.cat(&ipfs_hash_clone);

                // Collect all bytes from the stream
                let mut data = Vec::new();
                let stream = data_stream;
                use futures_util::pin_mut;
                pin_mut!(stream);

                while let Some(chunk) = stream.try_next().await.map_err(|e| StorageError::BackendError {
                    message: format!("Failed to retrieve metadata from IPFS: {}", e),
                })? {
                    data.extend_from_slice(&chunk);
                }

                // Deserialize metadata
                let metadata: ChunkMetadata = serde_json::from_slice(&data)
                    .map_err(|e| StorageError::SerializationError {
                        message: format!("Failed to deserialize metadata: {}", e),
                    })?;

                Ok::<ChunkMetadata, anyhow::Error>(metadata)
            })
        }).await.map_err(|e| StorageError::BackendError {
            message: format!("Task join error: {}", e),
        })??;

        log::debug!("Retrieved metadata for chunk {} for {} from IPFS ({})", chunk_hash, recipient, &ipfs_hash);
        Ok(metadata)
    }

    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        // Note: IPFS doesn't have native directory/indexing support
        // In a real implementation, you would need to maintain an index
        // This could be done by storing an index file on IPFS itself
        // or using a separate database to track the mappings

        log::warn!("list_chunks for recipient {} - IPFS requires separate indexing mechanism", recipient);

        // For now, return empty list as a placeholder
        // TODO: Implement proper indexing mechanism for IPFS chunks
        Ok(vec![])
    }

    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        // Get IPFS hash for this chunk
        let ipfs_hash = self.get_ipfs_hash_for_chunk(recipient, chunk_hash).await?;
        let client = self.client.clone();
        let pin_content = self.pin_content;
        let ipfs_hash_for_log = ipfs_hash.clone();

        // Use spawn_blocking to handle the non-Send IPFS client
        task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                // Unpin the content if it was pinned
                if pin_content {
                    // Note: IPFS pin_rm might fail if content is not pinned, which is fine
                    let _ = client.pin_rm(&ipfs_hash, false).await;
                }

                Ok::<(), anyhow::Error>(())
            })
        }).await.map_err(|e| StorageError::BackendError {
            message: format!("Task join error: {}", e),
        })??;

        // Also try to remove metadata
        let metadata_key = format!("{}_metadata", chunk_hash);
        if let Ok(metadata_hash) = self.get_ipfs_hash_for_chunk(recipient, &metadata_key).await {
            let client = self.client.clone();
            let pin_content = self.pin_content;
            task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async {
                    if pin_content {
                        let _ = client.pin_rm(&metadata_hash, false).await;
                    }
                    Ok::<(), anyhow::Error>(())
                })
            }).await.map_err(|e| StorageError::BackendError {
            message: format!("Task join error: {}", e),
        })??;
        }

        // Note: IPFS doesn't actually "delete" content, it just unpins it
        // The content remains accessible by hash until garbage collected
        log::debug!("Unpinned chunk {} for {} from IPFS ({})", chunk_hash, recipient, ipfs_hash_for_log);
        Ok(())
    }

    async fn test_connection(&self) -> Result<()> {
        let client = self.client.clone();

        // Use spawn_blocking to handle the non-Send IPFS client
        let version_info = task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                client.version().await
                    .map_err(Self::map_ipfs_error)
            })
        }).await.map_err(|e| StorageError::BackendError {
            message: format!("Task join error: {}", e),
        })??;

        log::info!("IPFS connection successful - Version: {}", version_info.version);
        Ok(())
    }

    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();
        health.insert("url".to_string(), self.api_url.clone());
        health.insert("pin_content".to_string(), self.pin_content.to_string());

        let client = self.client.clone();

        // Try to get version info to test connection
        match task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                client.version().await
                    .map_err(Self::map_ipfs_error)
            })
        }).await {
            Ok(Ok(version_info)) => {
                health.insert("status".to_string(), "healthy".to_string());
                health.insert("version".to_string(), version_info.version);
                health.insert("commit".to_string(), version_info.commit);
            }
            Ok(Err(e)) => {
                health.insert("status".to_string(), "error".to_string());
                health.insert("error".to_string(), format!("{}", e));
            }
            Err(e) => {
                health.insert("status".to_string(), "error".to_string());
                health.insert("error".to_string(), format!("Task join error: {}", e));
            }
        }

        Ok(health)
    }

    fn backend_type(&self) -> StorageType {
        StorageType::Ipfs
    }
}