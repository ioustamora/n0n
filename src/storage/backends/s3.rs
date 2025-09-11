use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{Client, Error as S3Error};
use aws_sdk_s3::primitives::{ByteStream};
use aws_sdk_s3::types::{ObjectCannedAcl};
use aws_sdk_s3::primitives::ByteStreamError;
use chrono::{DateTime, Utc};

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, S3Config, StorageError};

/// S3-compatible storage backend
/// Supports AWS S3, MinIO, Cloudflare R2, DigitalOcean Spaces, and other S3-compatible services
pub struct S3Backend {
    client: Client,
    config: S3Config,
}

impl S3Backend {
    pub async fn new(config: S3Config) -> Result<Self> {
        // Validate configuration
        if config.bucket.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "S3 bucket name cannot be empty".to_string(),
            }.into());
        }
        
        if config.access_key_id.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "S3 access key ID cannot be empty".to_string(),
            }.into());
        }
        
        if config.secret_access_key.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "S3 secret access key cannot be empty".to_string(),
            }.into());
        }
        
        // Build AWS config
        let mut aws_config_builder = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()));
        
        // Set custom endpoint if provided (for MinIO, R2, etc.)
        if let Some(endpoint) = &config.endpoint {
            aws_config_builder = aws_config_builder.endpoint_url(endpoint);
        }
        
        let aws_config = aws_config_builder.load().await;
        
        // Create S3 client with custom config
        let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&aws_config)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                &config.access_key_id,
                &config.secret_access_key,
                config.session_token.clone(),
                None,
                "n0n-s3-backend"
            ));
        
        // Enable path-style addressing if specified (required for MinIO)
        if config.force_path_style.unwrap_or(false) {
            s3_config_builder = s3_config_builder.force_path_style(true);
        }
        
        let s3_config = s3_config_builder.build();
        let client = Client::from_conf(s3_config);
        
        Ok(Self {
            client,
            config,
        })
    }
    
    /// Get the S3 object key for a chunk
    fn get_chunk_key(&self, recipient: &str, chunk_hash: &str) -> String {
        let prefix = self.config.path_prefix.as_deref().unwrap_or("");
        if prefix.is_empty() {
            format!("{}/chunks/{}", recipient, chunk_hash)
        } else {
            format!("{}/{}/chunks/{}", prefix.trim_end_matches('/'), recipient, chunk_hash)
        }
    }
    
    /// Get the S3 object key for chunk metadata
    fn get_metadata_key(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}.meta", self.get_chunk_key(recipient, chunk_hash))
    }
    
    /// Convert S3 error to our storage error
    fn map_s3_error(err: &str) -> StorageError {
        if err.contains("NoSuchBucket") {
            StorageError::ConfigurationError {
                message: "S3 bucket does not exist".to_string(),
            }
        } else if err.contains("NoSuchKey") || err.contains("NotFound") {
            StorageError::ChunkNotFound {
                chunk_hash: "unknown".to_string(),
            }
        } else {
            StorageError::BackendError {
                message: format!("S3 operation failed: {}", err),
            }
        }
    }
    
    /// Check if the bucket exists and is accessible
    async fn check_bucket_access(&self) -> Result<()> {
        match self.client.head_bucket()
            .bucket(&self.config.bucket)
            .send()
            .await {
            Ok(_) => Ok(()),
            Err(e) => {
                Err(Self::map_s3_error(&e.to_string()).into())
            }
        }
    }
}

#[async_trait]
impl StorageBackend for S3Backend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let key = self.get_chunk_key(recipient, chunk_hash);
        let body = ByteStream::from(data.to_vec());
        
        match self.client
            .put_object()
            .bucket(&self.config.bucket)
            .key(&key)
            .body(body)
            .content_type("application/octet-stream")
            .acl(ObjectCannedAcl::Private) // Ensure chunks are private
            .send()
            .await {
            Ok(_) => Ok(chunk_hash.to_string()),
            Err(e) => {
                Err(Self::map_s3_error(&e.to_string()).into())
            }
        }
    }
    
    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        let key = self.get_metadata_key(recipient, chunk_hash);
        
        // Create metadata JSON
        let metadata_json = serde_json::json!({
            "nonce": metadata.nonce,
            "sender_public_key": metadata.sender_public_key,
            "size": metadata.size,
            "created_at": metadata.created_at.to_rfc3339(),
        });
        
        let body = ByteStream::from(metadata_json.to_string().into_bytes());
        
        match self.client
            .put_object()
            .bucket(&self.config.bucket)
            .key(&key)
            .body(body)
            .content_type("application/json")
            .acl(ObjectCannedAcl::Private)
            .send()
            .await {
            Ok(_) => Ok(()),
            Err(e) => {
                Err(Self::map_s3_error(&e.to_string()).into())
            }
        }
    }
    
    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let key = self.get_chunk_key(recipient, chunk_hash);
        
        match self.client
            .get_object()
            .bucket(&self.config.bucket)
            .key(&key)
            .send()
            .await {
            Ok(response) => {
                let body = response.body.collect().await
                    .map_err(|e: ByteStreamError| anyhow!("Failed to read S3 object body: {}", e))?;
                Ok(body.into_bytes().to_vec())
            },
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("NoSuchKey") || error_str.contains("NotFound") {
                    Err(StorageError::ChunkNotFound {
                        chunk_hash: chunk_hash.to_string(),
                    }.into())
                } else {
                    Err(Self::map_s3_error(&error_str).into())
                }
            }
        }
    }
    
    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let key = self.get_metadata_key(recipient, chunk_hash);
        
        match self.client
            .get_object()
            .bucket(&self.config.bucket)
            .key(&key)
            .send()
            .await {
            Ok(response) => {
                let body = response.body.collect().await
                    .map_err(|e: ByteStreamError| anyhow!("Failed to read S3 metadata body: {}", e))?;
                
                let content = String::from_utf8(body.into_bytes().to_vec())?;
                let json: serde_json::Value = serde_json::from_str(&content)?;
                
                let created_at = if let Some(created_str) = json["created_at"].as_str() {
                    DateTime::parse_from_rfc3339(created_str)?.with_timezone(&Utc)
                } else {
                    // Fallback to S3 object last modified time if available
                    if let Some(last_modified) = response.last_modified {
                        // Convert AWS SDK DateTime to chrono DateTime
                        DateTime::from_timestamp(last_modified.secs(), 0).unwrap_or_else(|| Utc::now())
                    } else {
                        Utc::now()
                    }
                };
                
                Ok(ChunkMetadata {
                    nonce: json["nonce"].as_str().unwrap_or("").to_string(),
                    sender_public_key: json["sender_public_key"].as_str().unwrap_or("").to_string(),
                    size: json["size"].as_u64().unwrap_or(0),
                    created_at,
                })
            },
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("NoSuchKey") || error_str.contains("NotFound") {
                    Err(StorageError::ChunkNotFound {
                        chunk_hash: chunk_hash.to_string(),
                    }.into())
                } else {
                    Err(Self::map_s3_error(&error_str).into())
                }
            }
        }
    }
    
    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        let prefix = if let Some(path_prefix) = &self.config.path_prefix {
            format!("{}/{}/chunks/", path_prefix.trim_end_matches('/'), recipient)
        } else {
            format!("{}/chunks/", recipient)
        };
        
        let mut chunks = Vec::new();
        let mut continuation_token: Option<String> = None;
        
        loop {
            let mut request = self.client
                .list_objects_v2()
                .bucket(&self.config.bucket)
                .prefix(&prefix)
                .max_keys(1000); // AWS default maximum
            
            if let Some(token) = continuation_token {
                request = request.continuation_token(token);
            }
            
            match request.send().await {
                Ok(response) => {
                    if let Some(contents) = response.contents {
                        for object in contents {
                            if let Some(key) = object.key {
                                // Extract chunk hash from key
                                if !key.ends_with(".meta") {
                                    if let Some(filename) = key.split('/').last() {
                                        chunks.push(filename.to_string());
                                    }
                                }
                            }
                        }
                    }
                    
                    // Check if there are more results
                    if response.is_truncated == Some(true) {
                        continuation_token = response.next_continuation_token;
                    } else {
                        break;
                    }
                },
                Err(e) => {
                    return Err(Self::map_s3_error(&e.to_string()).into());
                }
            }
        }
        
        Ok(chunks)
    }
    
    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let chunk_key = self.get_chunk_key(recipient, chunk_hash);
        let metadata_key = self.get_metadata_key(recipient, chunk_hash);
        
        // Delete both chunk and metadata
        let chunk_delete = self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(&chunk_key)
            .send();
        
        let metadata_delete = self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(&metadata_key)
            .send();
        
        // Wait for both deletions to complete
        let (chunk_result, metadata_result) = tokio::try_join!(chunk_delete, metadata_delete)?;
        
        // S3 delete operations succeed even if the object doesn't exist
        // so we don't need to check for NoSuchKey errors here
        
        Ok(())
    }
    
    async fn test_connection(&self) -> Result<()> {
        self.check_bucket_access().await
    }
    
    fn backend_type(&self) -> StorageType {
        StorageType::S3Compatible
    }
    
    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "S3Compatible".to_string());
        info.insert("bucket".to_string(), self.config.bucket.clone());
        info.insert("region".to_string(), self.config.region.clone());
        
        if let Some(endpoint) = &self.config.endpoint {
            info.insert("endpoint".to_string(), endpoint.clone());
            info.insert("service_type".to_string(), 
                if endpoint.contains("minio") { "MinIO".to_string() }
                else if endpoint.contains("r2.cloudflarestorage.com") { "Cloudflare R2".to_string() }
                else if endpoint.contains("digitaloceanspaces.com") { "DigitalOcean Spaces".to_string() }
                else { "S3-Compatible".to_string() }
            );
        } else {
            info.insert("service_type".to_string(), "AWS S3".to_string());
        }
        
        if let Some(prefix) = &self.config.path_prefix {
            info.insert("path_prefix".to_string(), prefix.clone());
        }
        
        info.insert("force_path_style".to_string(), 
            self.config.force_path_style.unwrap_or(false).to_string()
        );
        
        info
    }
    
    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();
        
        match self.test_connection().await {
            Ok(_) => {
                health.insert("status".to_string(), "healthy".to_string());
                health.insert("bucket_access".to_string(), "ok".to_string());
                
                // Try to get bucket location for additional info
                match self.client.get_bucket_location()
                    .bucket(&self.config.bucket)
                    .send()
                    .await {
                    Ok(response) => {
                        if let Some(constraint) = response.location_constraint {
                            health.insert("bucket_region".to_string(), constraint.as_str().to_string());
                        }
                    },
                    Err(_) => {
                        // Ignore errors for bucket location - not all S3-compatible services support this
                    }
                }
            },
            Err(e) => {
                health.insert("status".to_string(), "unhealthy".to_string());
                health.insert("error".to_string(), e.to_string());
            }
        }
        
        health.insert("bucket".to_string(), self.config.bucket.clone());
        health.insert("region".to_string(), self.config.region.clone());
        
        Ok(health)
    }
    
    /// Batch upload optimization for S3
    async fn save_chunks_batch(&self, recipient: &str, chunks: Vec<(String, Vec<u8>, ChunkMetadata)>) -> Result<Vec<String>> {
        // For now, we'll use parallel uploads rather than multipart upload
        // In a production system, you might want to use S3's multipart upload for very large batches
        
        let upload_tasks = chunks.into_iter().map(|(hash, data, metadata)| {
            let hash_clone = hash.clone();
            let backend = self; // We need to be careful about borrowing here
            
            async move {
                // Upload chunk
                self.save_chunk(recipient, &hash, &data).await?;
                // Upload metadata
                self.save_metadata(recipient, &hash, &metadata).await?;
                Ok::<String, anyhow::Error>(hash_clone)
            }
        });
        
        // Execute all uploads concurrently with a reasonable concurrency limit
        let results = futures::future::try_join_all(upload_tasks).await?;
        
        Ok(results)
    }
}