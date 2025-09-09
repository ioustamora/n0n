use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use azure_storage::prelude::*;
use azure_storage_blobs::prelude::*;
use azure_core::auth::TokenCredential;

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, AzureConfig, StorageError};

/// Azure Blob Storage backend
/// Stores chunks and metadata in Azure containers with proper authentication and error handling
pub struct AzureBackend {
    client: BlobServiceClient,
    config: AzureConfig,
    container: String,
    path_prefix: String,
}

impl AzureBackend {
    pub async fn new(config: AzureConfig) -> Result<Self> {
        // Validate configuration
        if config.account_name.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "Azure storage account name cannot be empty".to_string(),
            }.into());
        }

        if config.container.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "Azure container name cannot be empty".to_string(),
            }.into());
        }

        // Setup authentication
        let client = if let Some(account_key) = &config.account_key {
            // Use account key authentication
            let storage_credentials = StorageCredentials::access_key(
                config.account_name.clone(),
                account_key.clone(),
            );
            BlobServiceClient::new(config.account_name.clone(), storage_credentials)
        } else if let Some(sas_token) = &config.sas_token {
            // Use SAS token authentication
            let storage_credentials = StorageCredentials::sas_token(sas_token.clone())
                .map_err(|e| StorageError::AuthenticationError {
                    message: format!("Invalid SAS token: {}", e),
                })?;
            BlobServiceClient::new(config.account_name.clone(), storage_credentials)
        } else {
            return Err(StorageError::ConfigurationError {
                message: "Either account_key or sas_token must be provided for Azure authentication".to_string(),
            }.into());
        };

        let path_prefix = config.path_prefix.clone()
            .unwrap_or_else(|| "n0n".to_string());

        Ok(Self {
            client,
            config,
            container: config.container.clone(),
            path_prefix,
        })
    }

    /// Get the Azure blob name for a chunk
    fn get_chunk_path(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}/chunks/{}/{}", self.path_prefix, recipient, chunk_hash)
    }

    /// Get the Azure blob name for chunk metadata
    fn get_metadata_path(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}/metadata/{}/{}.json", self.path_prefix, recipient, chunk_hash)
    }

    /// Get the Azure blob prefix for listing chunks
    fn get_chunk_list_prefix(&self, recipient: &str) -> String {
        format!("{}/chunks/{}/", self.path_prefix, recipient)
    }

    /// Convert Azure error to our storage error
    fn map_azure_error(err: azure_core::error::Error) -> StorageError {
        let err_str = err.to_string();
        
        if err_str.contains("404") || err_str.contains("BlobNotFound") {
            StorageError::ChunkNotFound {
                chunk_hash: "unknown".to_string(),
            }
        } else if err_str.contains("401") || err_str.contains("403") || err_str.contains("AuthenticationFailed") {
            StorageError::AuthenticationError {
                message: format!("Azure authentication failed: {}", err),
            }
        } else if err_str.contains("413") || err_str.contains("RequestEntityTooLarge") {
            StorageError::StorageFull
        } else if err_str.contains("network") || err_str.contains("timeout") {
            StorageError::NetworkError {
                message: format!("Azure network error: {}", err),
            }
        } else {
            StorageError::BackendError {
                message: format!("Azure operation failed: {}", err),
            }
        }
    }
}

#[async_trait]
impl StorageBackend for AzureBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let blob_name = self.get_chunk_path(recipient, chunk_hash);
        
        let blob_client = self.client
            .container_client(&self.container)
            .blob_client(&blob_name);

        match blob_client.put_block_blob(data)
            .content_type("application/octet-stream")
            .await {
            Ok(_) => Ok(chunk_hash.to_string()),
            Err(e) => Err(Self::map_azure_error(e).into()),
        }
    }

    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        let blob_name = self.get_metadata_path(recipient, chunk_hash);

        let metadata_json = serde_json::json!({
            "nonce": metadata.nonce,
            "sender_public_key": metadata.sender_public_key,
            "size": metadata.size,
            "created_at": metadata.created_at.to_rfc3339(),
        });

        let metadata_bytes = metadata_json.to_string().into_bytes();
        
        let blob_client = self.client
            .container_client(&self.container)
            .blob_client(&blob_name);

        match blob_client.put_block_blob(&metadata_bytes)
            .content_type("application/json")
            .await {
            Ok(_) => Ok(()),
            Err(e) => Err(Self::map_azure_error(e).into()),
        }
    }

    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let blob_name = self.get_chunk_path(recipient, chunk_hash);
        
        let blob_client = self.client
            .container_client(&self.container)
            .blob_client(&blob_name);

        match blob_client.get_content().await {
            Ok(data) => Ok(data),
            Err(e) => {
                if e.to_string().contains("404") || e.to_string().contains("BlobNotFound") {
                    Err(StorageError::ChunkNotFound {
                        chunk_hash: chunk_hash.to_string(),
                    }.into())
                } else {
                    Err(Self::map_azure_error(e).into())
                }
            }
        }
    }

    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let blob_name = self.get_metadata_path(recipient, chunk_hash);
        
        let blob_client = self.client
            .container_client(&self.container)
            .blob_client(&blob_name);

        match blob_client.get_content().await {
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
                if e.to_string().contains("404") || e.to_string().contains("BlobNotFound") {
                    Err(StorageError::ChunkNotFound {
                        chunk_hash: chunk_hash.to_string(),
                    }.into())
                } else {
                    Err(Self::map_azure_error(e).into())
                }
            }
        }
    }

    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        let prefix = self.get_chunk_list_prefix(recipient);
        
        let container_client = self.client.container_client(&self.container);

        let mut chunk_hashes = Vec::new();
        let mut stream = container_client.list_blobs()
            .prefix(prefix.clone())
            .into_stream();

        while let Some(result) = futures::StreamExt::next(&mut stream).await {
            match result {
                Ok(list_blobs_response) => {
                    for blob in list_blobs_response.blobs.blobs() {
                        // Extract chunk hash from blob name
                        // Format: {prefix}/chunks/{recipient}/{chunk_hash}
                        if let Some(hash) = blob.name.strip_prefix(&prefix) {
                            chunk_hashes.push(hash.to_string());
                        }
                    }
                },
                Err(e) => return Err(Self::map_azure_error(e).into()),
            }
        }

        Ok(chunk_hashes)
    }

    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let chunk_path = self.get_chunk_path(recipient, chunk_hash);
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);

        let container_client = self.client.container_client(&self.container);

        // Delete chunk data
        let chunk_blob_client = container_client.blob_client(&chunk_path);
        if let Err(e) = chunk_blob_client.delete().await {
            if !e.to_string().contains("404") && !e.to_string().contains("BlobNotFound") {
                return Err(Self::map_azure_error(e).into());
            }
        }

        // Delete metadata
        let metadata_blob_client = container_client.blob_client(&metadata_path);
        if let Err(e) = metadata_blob_client.delete().await {
            if !e.to_string().contains("404") && !e.to_string().contains("BlobNotFound") {
                return Err(Self::map_azure_error(e).into());
            }
        }

        Ok(())
    }

    async fn test_connection(&self) -> Result<()> {
        // Test by trying to get container properties
        let container_client = self.client.container_client(&self.container);
        
        match container_client.get_properties().await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::ConnectionError {
                message: format!("Azure connection test failed: {}", e),
            }.into()),
        }
    }

    fn backend_type(&self) -> StorageType {
        StorageType::AzureBlob
    }

    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "AzureBlob".to_string());
        info.insert("account_name".to_string(), self.config.account_name.clone());
        info.insert("container".to_string(), self.config.container.clone());
        info.insert("path_prefix".to_string(), self.path_prefix.clone());

        if self.config.account_key.is_some() {
            info.insert("auth_method".to_string(), "account_key".to_string());
        } else if self.config.sas_token.is_some() {
            info.insert("auth_method".to_string(), "sas_token".to_string());
        }

        info
    }

    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();

        match self.test_connection().await {
            Ok(_) => {
                health.insert("status".to_string(), "healthy".to_string());
                health.insert("connection".to_string(), "ok".to_string());

                // Test write/read operations
                let test_blob = format!("{}/health_check.txt", self.path_prefix);
                let test_data = b"health_check_test";

                let container_client = self.client.container_client(&self.container);
                let test_blob_client = container_client.blob_client(&test_blob);

                match test_blob_client.put_block_blob(test_data)
                    .content_type("text/plain")
                    .await {
                    Ok(_) => {
                        health.insert("write_test".to_string(), "ok".to_string());

                        // Test read
                        match test_blob_client.get_content().await {
                            Ok(data) => {
                                if data == test_data {
                                    health.insert("read_test".to_string(), "ok".to_string());
                                } else {
                                    health.insert("read_test".to_string(), "data_mismatch".to_string());
                                }
                            },
                            Err(_) => {
                                health.insert("read_test".to_string(), "failed".to_string());
                            }
                        }

                        // Clean up test blob
                        let _ = test_blob_client.delete().await;
                    },
                    Err(_) => {
                        health.insert("write_test".to_string(), "failed".to_string());
                    }
                }

                health.insert("account".to_string(), self.config.account_name.clone());
                health.insert("container".to_string(), self.container.clone());
            },
            Err(e) => {
                health.insert("status".to_string(), "unhealthy".to_string());
                health.insert("error".to_string(), e.to_string());
            }
        }

        Ok(health)
    }

    /// Azure batch operations using concurrent uploads
    async fn save_chunks_batch(&self, recipient: &str, chunks: Vec<(String, Vec<u8>, ChunkMetadata)>) -> Result<Vec<String>> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }

        let mut handles = Vec::new();
        let mut results = Vec::new();

        // Process in smaller batches to avoid overwhelming the API
        const BATCH_SIZE: usize = 20;
        
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

                    Ok(hash_clone)
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

impl Clone for AzureBackend {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: self.config.clone(),
            container: self.container.clone(),
            path_prefix: self.path_prefix.clone(),
        }
    }
}