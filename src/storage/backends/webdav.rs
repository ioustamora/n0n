use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use reqwest::Client;
use reqwest_dav::{Auth, ClientBuilder, Depth};

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, WebDavConfig, StorageError};

/// WebDAV storage backend
/// Stores chunks and metadata on WebDAV-compatible servers (Nextcloud, ownCloud, etc.)
pub struct WebDavBackend {
    client: reqwest_dav::Client,
    config: WebDavConfig,
    base_url: String,
    path_prefix: String,
}

impl WebDavBackend {
    pub async fn new(config: WebDavConfig) -> Result<Self> {
        // Validate configuration
        if config.url.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "WebDAV URL cannot be empty".to_string(),
            }.into());
        }

        if config.username.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "WebDAV username cannot be empty".to_string(),
            }.into());
        }

        // Setup authentication
        let auth = Auth::Basic(config.username.clone(), config.password.clone());
        
        // Create HTTP client with optional SSL verification
        let http_client = if let Some(verify_ssl) = config.verify_ssl {
            if verify_ssl {
                Client::new()
            } else {
                Client::builder()
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true)
                    .build()
                    .map_err(|e| StorageError::ConfigurationError {
                        message: format!("Failed to create HTTP client: {}", e),
                    })?
            }
        } else {
            Client::new()
        };

        // Create WebDAV client
        let client = ClientBuilder::new()
            .set_host(config.url.clone())
            .set_auth(auth)
            .set_client(http_client)
            .build()
            .map_err(|e| StorageError::ConfigurationError {
                message: format!("Failed to create WebDAV client: {}", e),
            })?;

        let path_prefix = config.base_path.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            config: config.clone(),
            base_url: config.url,
            path_prefix,
        })
    }

    /// Get the WebDAV path for a chunk
    fn get_chunk_path(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}/chunks/{}/{}", self.path_prefix, recipient, chunk_hash)
    }

    /// Get the WebDAV path for chunk metadata
    fn get_metadata_path(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}/metadata/{}/{}.json", self.path_prefix, recipient, chunk_hash)
    }

    /// Get the WebDAV path prefix for listing chunks
    fn get_chunk_list_path(&self, recipient: &str) -> String {
        format!("{}/chunks/{}/", self.path_prefix, recipient)
    }

    /// Convert WebDAV error to our storage error
    fn map_webdav_error(err: reqwest_dav::Error) -> StorageError {
        match err {
            reqwest_dav::Error::Reqwest(reqwest_err) => {
                if let Some(status) = reqwest_err.status() {
                    match status.as_u16() {
                        404 => StorageError::ChunkNotFound {
                            chunk_hash: "unknown".to_string(),
                        },
                        401 | 403 => StorageError::AuthenticationError {
                            message: format!("WebDAV authentication failed: {}", reqwest_err),
                        },
                        413 => StorageError::StorageFull,
                        _ => StorageError::NetworkError {
                            message: format!("WebDAV HTTP error: {}", reqwest_err),
                        },
                    }
                } else if reqwest_err.is_connect() {
                    StorageError::ConnectionError {
                        message: format!("WebDAV connection failed: {}", reqwest_err),
                    }
                } else {
                    StorageError::NetworkError {
                        message: format!("WebDAV network error: {}", reqwest_err),
                    }
                }
            }
            reqwest_dav::Error::Utf8(_) => StorageError::SerializationError {
                message: format!("WebDAV UTF-8 error: {}", err),
            },
            reqwest_dav::Error::Xml(_) => StorageError::SerializationError {
                message: format!("WebDAV XML error: {}", err),
            },
            _ => StorageError::BackendError {
                message: format!("WebDAV operation failed: {}", err),
            },
        }
    }

    /// Ensure a directory exists on the WebDAV server
    async fn ensure_directory(&self, path: &str) -> Result<()> {
        // Create directory structure recursively
        let path_parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let mut current_path = String::new();
        
        for part in path_parts {
            if !part.is_empty() {
                current_path.push('/');
                current_path.push_str(part);
                
                // Try to create directory (will succeed if it already exists)
                if let Err(e) = self.client.mkcol(&current_path).await {
                    // Ignore errors for existing directories
                    if !matches!(e, reqwest_dav::Error::Reqwest(ref req_err) if req_err.status() == Some(reqwest::StatusCode::METHOD_NOT_ALLOWED)) {
                        return Err(Self::map_webdav_error(e).into());
                    }
                }
            }
        }
        
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for WebDavBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let chunk_path = self.get_chunk_path(recipient, chunk_hash);
        
        // Ensure the directory exists
        let dir_path = format!("{}/chunks/{}", self.path_prefix, recipient);
        self.ensure_directory(&dir_path).await?;
        
        // Upload the chunk data
        match self.client.put(&chunk_path, data.to_vec()).await {
            Ok(_) => Ok(chunk_hash.to_string()),
            Err(e) => Err(Self::map_webdav_error(e).into()),
        }
    }

    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);
        
        // Ensure the directory exists
        let dir_path = format!("{}/metadata/{}", self.path_prefix, recipient);
        self.ensure_directory(&dir_path).await?;
        
        // Serialize metadata as JSON
        let metadata_json = serde_json::json!({
            "nonce": metadata.nonce,
            "sender_public_key": metadata.sender_public_key,
            "size": metadata.size,
            "created_at": metadata.created_at.to_rfc3339(),
        });

        let metadata_bytes = metadata_json.to_string().into_bytes();

        match self.client.put(&metadata_path, metadata_bytes).await {
            Ok(_) => Ok(()),
            Err(e) => Err(Self::map_webdav_error(e).into()),
        }
    }

    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let chunk_path = self.get_chunk_path(recipient, chunk_hash);

        match self.client.get(&chunk_path).await {
            Ok(data) => Ok(data),
            Err(e) => {
                if matches!(e, reqwest_dav::Error::Reqwest(ref req_err) if req_err.status() == Some(reqwest::StatusCode::NOT_FOUND)) {
                    Err(StorageError::ChunkNotFound {
                        chunk_hash: chunk_hash.to_string(),
                    }.into())
                } else {
                    Err(Self::map_webdav_error(e).into())
                }
            }
        }
    }

    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);

        match self.client.get(&metadata_path).await {
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
                if matches!(e, reqwest_dav::Error::Reqwest(ref req_err) if req_err.status() == Some(reqwest::StatusCode::NOT_FOUND)) {
                    Err(StorageError::ChunkNotFound {
                        chunk_hash: chunk_hash.to_string(),
                    }.into())
                } else {
                    Err(Self::map_webdav_error(e).into())
                }
            }
        }
    }

    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        let list_path = self.get_chunk_list_path(recipient);

        match self.client.list(&list_path, Depth::Number(1)).await {
            Ok(list) => {
                let mut chunk_hashes = Vec::new();
                
                for item in list {
                    if let Some(href) = item.href {
                        // Extract filename from href
                        if let Some(filename) = href.split('/').last() {
                            if !filename.is_empty() && filename != recipient {
                                chunk_hashes.push(filename.to_string());
                            }
                        }
                    }
                }

                Ok(chunk_hashes)
            },
            Err(e) => {
                if matches!(e, reqwest_dav::Error::Reqwest(ref req_err) if req_err.status() == Some(reqwest::StatusCode::NOT_FOUND)) {
                    Ok(Vec::new()) // Directory doesn't exist yet
                } else {
                    Err(Self::map_webdav_error(e).into())
                }
            }
        }
    }

    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let chunk_path = self.get_chunk_path(recipient, chunk_hash);
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);

        // Delete chunk data
        if let Err(e) = self.client.delete(&chunk_path).await {
            if !matches!(e, reqwest_dav::Error::Reqwest(ref req_err) if req_err.status() == Some(reqwest::StatusCode::NOT_FOUND)) {
                return Err(Self::map_webdav_error(e).into());
            }
        }

        // Delete metadata
        if let Err(e) = self.client.delete(&metadata_path).await {
            if !matches!(e, reqwest_dav::Error::Reqwest(ref req_err) if req_err.status() == Some(reqwest::StatusCode::NOT_FOUND)) {
                return Err(Self::map_webdav_error(e).into());
            }
        }

        Ok(())
    }

    async fn test_connection(&self) -> Result<()> {
        // Test by trying to list the base directory
        match self.client.list(&self.path_prefix, Depth::Number(0)).await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::ConnectionError {
                message: format!("WebDAV connection test failed: {}", e),
            }.into()),
        }
    }

    fn backend_type(&self) -> StorageType {
        StorageType::WebDav
    }

    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "WebDAV".to_string());
        info.insert("url".to_string(), self.base_url.clone());
        info.insert("username".to_string(), self.config.username.clone());
        info.insert("base_path".to_string(), self.path_prefix.clone());
        
        if let Some(verify_ssl) = self.config.verify_ssl {
            info.insert("verify_ssl".to_string(), verify_ssl.to_string());
        } else {
            info.insert("verify_ssl".to_string(), "true".to_string());
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
                let test_path = format!("{}/health_check.txt", self.path_prefix);
                let test_data = b"health_check_test";

                match self.client.put(&test_path, test_data.to_vec()).await {
                    Ok(_) => {
                        health.insert("write_test".to_string(), "ok".to_string());

                        // Test read
                        match self.client.get(&test_path).await {
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

                        // Clean up test file
                        let _ = self.client.delete(&test_path).await;
                    },
                    Err(_) => {
                        health.insert("write_test".to_string(), "failed".to_string());
                    }
                }

                health.insert("url".to_string(), self.base_url.clone());
                health.insert("base_path".to_string(), self.path_prefix.clone());
            },
            Err(e) => {
                health.insert("status".to_string(), "unhealthy".to_string());
                health.insert("error".to_string(), e.to_string());
            }
        }

        Ok(health)
    }

    /// WebDAV batch operations using concurrent uploads
    async fn save_chunks_batch(&self, recipient: &str, chunks: Vec<(String, Vec<u8>, ChunkMetadata)>) -> Result<Vec<String>> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }

        // Ensure directories exist first
        let chunk_dir = format!("{}/chunks/{}", self.path_prefix, recipient);
        let metadata_dir = format!("{}/metadata/{}", self.path_prefix, recipient);
        self.ensure_directory(&chunk_dir).await?;
        self.ensure_directory(&metadata_dir).await?;

        let mut handles = Vec::new();
        let mut results = Vec::new();

        // Process in smaller batches to avoid overwhelming the server
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

impl Clone for WebDavBackend {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: self.config.clone(),
            base_url: self.base_url.clone(),
            path_prefix: self.path_prefix.clone(),
        }
    }
}