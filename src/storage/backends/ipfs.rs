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
use tokio::sync::RwLock;

pub struct IpfsBackend {
    client: std::sync::Arc<IpfsClient>,
    config: IpfsConfig,
    api_url: String,
    pin_content: bool,
    recipient_keys: std::sync::Arc<RwLock<HashMap<String, String>>>,
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
            recipient_keys: std::sync::Arc::new(RwLock::new(HashMap::new())),
        })
    }

    async fn get_or_create_ipns_key(&self, recipient: &str) -> Result<String> {
        let mut keys = self.recipient_keys.write().await;
        if let Some(key) = keys.get(recipient) {
            return Ok(key.clone());
        }

        // Key not found, create a new one
        let key_name = format!("n0n-{}", recipient);
        let new_key = self.client.key_gen(&key_name, "rsa", 2048).await.map_err(Self::map_ipfs_error)?;

        keys.insert(recipient.to_string(), new_key.id.clone());

        Ok(new_key.id)
    }

    async fn get_index(&self, recipient: &str) -> Result<HashMap<String, String>> {
        let key_id = self.get_or_create_ipns_key(recipient).await?;

        // Resolve the IPNS name to get the root hash of the index
        let resolved = self.client.name_resolve(&key_id, false, false).await.map_err(Self::map_ipfs_error)?;
        let index_hash = resolved.path;

        // Get the content of the index
        let index_content_stream = self.client.cat(&index_hash);
        let index_content: Vec<u8> = index_content_stream
            .try_fold(Vec::new(), |mut acc, chunk| async move {
                acc.extend_from_slice(&chunk);
                Ok(acc)
            })
            .await
            .map_err(Self::map_ipfs_error)?;

        // Deserialize the index
        let index: HashMap<String, String> = if index_content.is_empty() {
            HashMap::new()
        } else {
            serde_json::from_slice(&index_content).map_err(|e| StorageError::SerializationError {
                message: format!("Failed to deserialize index: {}", e),
            })?
        };

        Ok(index)
    }

    async fn update_index(&self, recipient: &str, chunk_hash: &str, ipfs_hash: &str) -> Result<()> {
        let mut index = self.get_index(recipient).await.unwrap_or_default();
        index.insert(chunk_hash.to_string(), ipfs_hash.to_string());

        // Serialize the index
        let index_content = serde_json::to_vec(&index).map_err(|e| StorageError::SerializationError {
            message: format!("Failed to serialize index: {}", e),
        })?;

        // Add the updated index to IPFS
        let cursor = Cursor::new(index_content);
        let add_result = self.client.add(cursor).await.map_err(Self::map_ipfs_error)?;
        let new_index_hash = add_result.hash;

        // Publish the new index hash to IPNS
        let key_id = self.get_or_create_ipns_key(recipient).await?;
        self.client
            .name_publish(&new_index_hash, &key_id, None, None)
            .await
            .map_err(Self::map_ipfs_error)?;

        Ok(())
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
        self.update_index(&recipient, &chunk_hash, &ipfs_hash).await?;

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
        self.update_index(&recipient, &metadata_key, &metadata_hash).await?;

        log::debug!("Saved metadata for chunk {} for {} to IPFS: {}", chunk_hash, recipient, metadata_hash);
        Ok(())
    }

    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        // Get IPFS hash for this chunk
        let index = self.get_index(recipient).await?;
        let ipfs_hash = index.get(chunk_hash).ok_or_else(|| StorageError::ChunkNotFound {
            chunk_hash: chunk_hash.to_string(),
        })?.clone();
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
        let index = self.get_index(recipient).await?;
        let ipfs_hash = index.get(&metadata_key).ok_or_else(|| StorageError::ChunkNotFound {
            chunk_hash: chunk_hash.to_string(),
        })?.clone();
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
        let index = self.get_index(recipient).await?;
        Ok(index.keys().cloned().collect())
    }

    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let mut index = self.get_index(recipient).await?;
        if let Some(ipfs_hash) = index.remove(chunk_hash) {
            // Update the index
            let index_content = serde_json::to_vec(&index).map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize index: {}", e),
            })?;

            let cursor = Cursor::new(index_content);
            let add_result = self.client.add(cursor).await.map_err(Self::map_ipfs_error)?;
            let new_index_hash = add_result.hash;

            let key_id = self.get_or_create_ipns_key(recipient).await?;
            self.client
                .name_publish(&new_index_hash, &key_id, None, None)
                .await
                .map_err(Self::map_ipfs_error)?;

            // Unpin the content
            let client = self.client.clone();
            let pin_content = self.pin_content;
            task::spawn_blocking(move || {
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async move {
                    if pin_content {
                        let _ = client.pin_rm(&ipfs_hash, false).await;
                    }
                    Ok::<(), anyhow::Error>(())
                })
            }).await.map_err(|e| StorageError::BackendError {
                message: format!("Task join error: {}", e),
            })??;

            // Also try to remove metadata
            let metadata_key = format!("{}_metadata", chunk_hash);
            if let Some(metadata_hash) = index.remove(&metadata_key) {
                let client = self.client.clone();
                let pin_content = self.pin_content;
                task::spawn_blocking(move || {
                    let rt = tokio::runtime::Handle::current();
                    rt.block_on(async move {
                        if pin_content {
                            let _ = client.pin_rm(&metadata_hash, false).await;
                        }
                        Ok::<(), anyhow::Error>(())
                    })
                }).await.map_err(|e| StorageError::BackendError {
                message: format!("Task join error: {}", e),
            })??;
            }
        }

        log::debug!("Deleted chunk {} for {} from IPFS", chunk_hash, recipient);
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