use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use google_cloud_storage::client::{Client, ClientConfig};
use google_cloud_storage::http::objects::{
    download::Range,
    upload::{Media, UploadObjectRequest, UploadType},
    get::GetObjectRequest,
    delete::DeleteObjectRequest,
    list::ListObjectsRequest,
    Object,
};
use google_cloud_auth::credentials::CredentialsFile;

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, GcsConfig, StorageError};

/// Google Cloud Storage backend
/// Stores chunks and metadata in GCS buckets with proper authentication and error handling
pub struct GcsBackend {
    client: Client,
    config: GcsConfig,
    bucket: String,
    path_prefix: String,
}

impl GcsBackend {
    pub async fn new(config: GcsConfig) -> Result<Self> {
        // Validate configuration
        if config.bucket.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "GCS bucket name cannot be empty".to_string(),
            }.into());
        }

        if config.project_id.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "GCS project ID cannot be empty".to_string(),
            }.into());
        }

        // Setup authentication
        let client_config = if let Some(service_account_key) = &config.service_account_key {
            // Use service account key directly
            let credentials = CredentialsFile::from_json(service_account_key)
                .map_err(|e| StorageError::AuthenticationError {
                    message: format!("Invalid service account key: {}", e),
                })?;
            ClientConfig::default().with_credentials(credentials).await
                .map_err(|e| StorageError::AuthenticationError {
                    message: format!("Failed to setup GCS credentials: {}", e),
                })?
        } else if let Some(service_account_path) = &config.service_account_path {
            // Use service account key from file
            ClientConfig::default().with_auth().await
                .map_err(|e| StorageError::AuthenticationError {
                    message: format!("Failed to authenticate with GCS: {}", e),
                })?
        } else {
            // Use default credentials (ADC)
            ClientConfig::default().with_auth().await
                .map_err(|e| StorageError::AuthenticationError {
                    message: format!("Failed to authenticate with GCS using default credentials: {}", e),
                })?
        };

        let client = Client::new(client_config);

        let path_prefix = config.path_prefix.clone()
            .unwrap_or_else(|| "n0n".to_string());

        Ok(Self {
            client,
            config,
            bucket: config.bucket.clone(),
            path_prefix,
        })
    }

    /// Get the GCS object name for a chunk
    fn get_chunk_path(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}/chunks/{}/{}", self.path_prefix, recipient, chunk_hash)
    }

    /// Get the GCS object name for chunk metadata
    fn get_metadata_path(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}/metadata/{}/{}.json", self.path_prefix, recipient, chunk_hash)
    }

    /// Get the GCS object prefix for listing chunks
    fn get_chunk_list_prefix(&self, recipient: &str) -> String {
        format!("{}/chunks/{}/", self.path_prefix, recipient)
    }

    /// Convert GCS error to our storage error
    fn map_gcs_error(err: google_cloud_storage::http::Error) -> StorageError {
        match err {
            google_cloud_storage::http::Error::HttpClient(ref http_err) => {
                if http_err.to_string().contains("404") {
                    StorageError::ChunkNotFound {
                        chunk_hash: "unknown".to_string(),
                    }
                } else if http_err.to_string().contains("401") || http_err.to_string().contains("403") {
                    StorageError::AuthenticationError {
                        message: format!("GCS authentication failed: {}", err),
                    }
                } else if http_err.to_string().contains("413") {
                    StorageError::StorageFull
                } else {
                    StorageError::NetworkError {
                        message: format!("GCS network error: {}", err),
                    }
                }
            }
            google_cloud_storage::http::Error::TokenSource(ref token_err) => {
                StorageError::AuthenticationError {
                    message: format!("GCS token error: {}", token_err),
                }
            }
            _ => StorageError::BackendError {
                message: format!("GCS operation failed: {}", err),
            },
        }
    }
}

#[async_trait]
impl StorageBackend for GcsBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let object_name = self.get_chunk_path(recipient, chunk_hash);

        let upload_type = UploadType::Simple(Media::new(object_name.clone()));
        let request = UploadObjectRequest {
            bucket: self.bucket.clone(),
            ..Default::default()
        };

        match self.client.upload_object(&request, data.to_vec(), &upload_type).await {
            Ok(_) => Ok(chunk_hash.to_string()),
            Err(e) => Err(Self::map_gcs_error(e).into()),
        }
    }

    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        let object_name = self.get_metadata_path(recipient, chunk_hash);

        let metadata_json = serde_json::json!({
            "nonce": metadata.nonce,
            "sender_public_key": metadata.sender_public_key,
            "size": metadata.size,
            "created_at": metadata.created_at.to_rfc3339(),
        });

        let metadata_bytes = metadata_json.to_string().into_bytes();

        let upload_type = UploadType::Simple(Media::new(object_name));
        let request = UploadObjectRequest {
            bucket: self.bucket.clone(),
            ..Default::default()
        };

        match self.client.upload_object(&request, metadata_bytes, &upload_type).await {
            Ok(_) => Ok(()),
            Err(e) => Err(Self::map_gcs_error(e).into()),
        }
    }

    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let object_name = self.get_chunk_path(recipient, chunk_hash);

        let request = GetObjectRequest {
            bucket: self.bucket.clone(),
            object: object_name,
            ..Default::default()
        };

        match self.client.download_object(&request, &Range::default()).await {
            Ok(data) => Ok(data),
            Err(e) => {
                if e.to_string().contains("404") {
                    Err(StorageError::ChunkNotFound {
                        chunk_hash: chunk_hash.to_string(),
                    }.into())
                } else {
                    Err(Self::map_gcs_error(e).into())
                }
            }
        }
    }

    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let object_name = self.get_metadata_path(recipient, chunk_hash);

        let request = GetObjectRequest {
            bucket: self.bucket.clone(),
            object: object_name,
            ..Default::default()
        };

        match self.client.download_object(&request, &Range::default()).await {
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
                if e.to_string().contains("404") {
                    Err(StorageError::ChunkNotFound {
                        chunk_hash: chunk_hash.to_string(),
                    }.into())
                } else {
                    Err(Self::map_gcs_error(e).into())
                }
            }
        }
    }

    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        let prefix = self.get_chunk_list_prefix(recipient);

        let request = ListObjectsRequest {
            bucket: self.bucket.clone(),
            prefix: Some(prefix.clone()),
            ..Default::default()
        };

        match self.client.list_objects(&request).await {
            Ok(list_response) => {
                let mut chunk_hashes = Vec::new();
                
                if let Some(objects) = list_response.items {
                    for object in objects {
                        if let Some(name) = object.name {
                            // Extract chunk hash from object name
                            // Format: {prefix}/chunks/{recipient}/{chunk_hash}
                            if let Some(hash) = name.strip_prefix(&prefix) {
                                chunk_hashes.push(hash.to_string());
                            }
                        }
                    }
                }

                Ok(chunk_hashes)
            },
            Err(e) => Err(Self::map_gcs_error(e).into()),
        }
    }

    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let chunk_path = self.get_chunk_path(recipient, chunk_hash);
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);

        // Delete chunk data
        let chunk_request = DeleteObjectRequest {
            bucket: self.bucket.clone(),
            object: chunk_path,
            ..Default::default()
        };

        if let Err(e) = self.client.delete_object(&chunk_request).await {
            if !e.to_string().contains("404") {
                return Err(Self::map_gcs_error(e).into());
            }
        }

        // Delete metadata
        let metadata_request = DeleteObjectRequest {
            bucket: self.bucket.clone(),
            object: metadata_path,
            ..Default::default()
        };

        if let Err(e) = self.client.delete_object(&metadata_request).await {
            if !e.to_string().contains("404") {
                return Err(Self::map_gcs_error(e).into());
            }
        }

        Ok(())
    }

    async fn test_connection(&self) -> Result<()> {
        // Test by trying to list objects with a very small page size
        let request = ListObjectsRequest {
            bucket: self.bucket.clone(),
            max_results: Some(1),
            ..Default::default()
        };

        match self.client.list_objects(&request).await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::ConnectionError {
                message: format!("GCS connection test failed: {}", e),
            }.into()),
        }
    }

    fn backend_type(&self) -> StorageType {
        StorageType::GoogleCloud
    }

    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "GoogleCloud".to_string());
        info.insert("bucket".to_string(), self.config.bucket.clone());
        info.insert("project_id".to_string(), self.config.project_id.clone());
        info.insert("path_prefix".to_string(), self.path_prefix.clone());

        if self.config.service_account_key.is_some() {
            info.insert("auth_method".to_string(), "service_account_key".to_string());
        } else if self.config.service_account_path.is_some() {
            info.insert("auth_method".to_string(), "service_account_file".to_string());
        } else {
            info.insert("auth_method".to_string(), "default_credentials".to_string());
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
                let test_object = format!("{}/health_check.txt", self.path_prefix);
                let test_data = b"health_check_test";

                let upload_type = UploadType::Simple(Media::new(test_object.clone()));
                let request = UploadObjectRequest {
                    bucket: self.bucket.clone(),
                    ..Default::default()
                };

                match self.client.upload_object(&request, test_data.to_vec(), &upload_type).await {
                    Ok(_) => {
                        health.insert("write_test".to_string(), "ok".to_string());

                        // Test read
                        let get_request = GetObjectRequest {
                            bucket: self.bucket.clone(),
                            object: test_object.clone(),
                            ..Default::default()
                        };

                        match self.client.download_object(&get_request, &Range::default()).await {
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

                        // Clean up test object
                        let delete_request = DeleteObjectRequest {
                            bucket: self.bucket.clone(),
                            object: test_object,
                            ..Default::default()
                        };
                        let _ = self.client.delete_object(&delete_request).await;
                    },
                    Err(_) => {
                        health.insert("write_test".to_string(), "failed".to_string());
                    }
                }

                // Get bucket info if possible
                health.insert("bucket".to_string(), self.bucket.clone());
                health.insert("project".to_string(), self.config.project_id.clone());
            },
            Err(e) => {
                health.insert("status".to_string(), "unhealthy".to_string());
                health.insert("error".to_string(), e.to_string());
            }
        }

        Ok(health)
    }

    /// GCS batch operations using concurrent uploads
    async fn save_chunks_batch(&self, recipient: &str, chunks: Vec<(String, Vec<u8>, ChunkMetadata)>) -> Result<Vec<String>> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }

        let mut handles = Vec::new();
        let mut results = Vec::new();

        // Process in smaller batches to avoid overwhelming the API
        const BATCH_SIZE: usize = 10;
        
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

impl Clone for GcsBackend {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: self.config.clone(),
            bucket: self.bucket.clone(),
            path_prefix: self.path_prefix.clone(),
        }
    }
}