use async_trait::async_trait;
use anyhow::Result;
use std::collections::HashMap;
use redis::{Client, AsyncCommands, RedisError};
use redis::aio::MultiplexedConnection as ConnectionManager;
use chrono::{DateTime, Utc};

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, RedisConfig, StorageError};

/// Redis storage backend
/// Stores chunks and metadata in Redis with optional TTL and cluster support
pub struct RedisBackend {
    manager: ConnectionManager,
    config: RedisConfig,
    key_prefix: String,
}

impl RedisBackend {
    pub async fn new(config: RedisConfig) -> Result<Self> {
        // Validate configuration
        if config.url.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "Redis URL cannot be empty".to_string(),
            }.into());
        }
        
        // Create Redis client
        let client = Client::open(config.url.clone())
            .map_err(|e| StorageError::ConfigurationError {
                message: format!("Invalid Redis URL: {}", e),
            })?;
        
        // Create connection manager for connection pooling
        let (manager, _) = ConnectionManager::new(client)
            .await
            .map_err(|e| StorageError::ConnectionError {
                message: format!("Failed to connect to Redis: {}", e),
            })?;
        
        let key_prefix = config.key_prefix.clone()
            .unwrap_or_else(|| "n0n".to_string());
        
        Ok(Self {
            manager,
            config,
            key_prefix,
        })
    }
    
    /// Get the Redis key for a chunk
    fn get_chunk_key(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}:chunk:{}:{}", self.key_prefix, recipient, chunk_hash)
    }
    
    /// Get the Redis key for chunk metadata
    fn get_metadata_key(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}:meta:{}:{}", self.key_prefix, recipient, chunk_hash)
    }
    
    /// Get the Redis key for recipient chunk list
    fn get_recipient_list_key(&self, recipient: &str) -> String {
        format!("{}:list:{}", self.key_prefix, recipient)
    }
    
    /// Convert Redis error to our storage error
    fn map_redis_error(err: RedisError) -> StorageError {
        match err.kind() {
            redis::ErrorKind::TypeError => StorageError::SerializationError {
                message: format!("Redis type error: {}", err),
            },
            redis::ErrorKind::AuthenticationFailed => StorageError::AuthenticationError {
                message: "Redis authentication failed".to_string(),
            },
            redis::ErrorKind::ConnectionRefused => StorageError::ConnectionError {
                message: "Redis connection refused".to_string(),
            },
            _ => StorageError::BackendError {
                message: format!("Redis operation failed: {}", err),
            },
        }
    }
    
    /// Get a mutable connection from the manager
    async fn get_connection(&self) -> Result<ConnectionManager> {
        Ok(self.manager.clone())
    }
}

#[async_trait]
impl StorageBackend for RedisBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let mut conn = self.get_connection().await?;
        let chunk_key = self.get_chunk_key(recipient, chunk_hash);
        let list_key = self.get_recipient_list_key(recipient);
        
        // Use a pipeline for better performance
        let mut pipe = redis::pipe();
        pipe.atomic();
        
        // Store the chunk data
        if let Some(ttl) = self.config.ttl {
            pipe.set_ex(&chunk_key, data, ttl);
        } else {
            pipe.set(&chunk_key, data);
        }
        
        // Add chunk hash to recipient's list (if not already present)
        pipe.sadd(&list_key, chunk_hash);
        
        // Set TTL on the list as well if configured
        if let Some(ttl) = self.config.ttl {
            pipe.expire(&list_key, ttl as usize);
        }
        
        match pipe.query_async(&mut conn).await {
            Ok(_) => Ok(chunk_hash.to_string()),
            Err(e) => Err(Self::map_redis_error(e).into()),
        }
    }
    
    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let metadata_key = self.get_metadata_key(recipient, chunk_hash);
        
        // Serialize metadata as JSON
        let metadata_json = serde_json::json!({
            "nonce": metadata.nonce,
            "sender_public_key": metadata.sender_public_key,
            "size": metadata.size,
            "created_at": metadata.created_at.to_rfc3339(),
        });
        
        let metadata_str = metadata_json.to_string();
        
        match if let Some(ttl) = self.config.ttl {
            conn.set_ex(&metadata_key, &metadata_str, ttl).await
        } else {
            conn.set(&metadata_key, &metadata_str).await
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(Self::map_redis_error(e).into()),
        }
    }
    
    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let mut conn = self.get_connection().await?;
        let chunk_key = self.get_chunk_key(recipient, chunk_hash);
        
        match conn.get::<_, Option<Vec<u8>>>(&chunk_key).await {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Err(StorageError::ChunkNotFound {
                chunk_hash: chunk_hash.to_string(),
            }.into()),
            Err(e) => Err(Self::map_redis_error(e).into()),
        }
    }
    
    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let mut conn = self.get_connection().await?;
        let metadata_key = self.get_metadata_key(recipient, chunk_hash);
        
        match conn.get::<_, Option<String>>(&metadata_key).await {
            Ok(Some(metadata_str)) => {
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
            Ok(None) => Err(StorageError::ChunkNotFound {
                chunk_hash: chunk_hash.to_string(),
            }.into()),
            Err(e) => Err(Self::map_redis_error(e).into()),
        }
    }
    
    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        let mut conn = self.get_connection().await?;
        let list_key = self.get_recipient_list_key(recipient);
        
        match conn.smembers::<_, Vec<String>>(&list_key).await {
            Ok(chunks) => Ok(chunks),
            Err(e) => Err(Self::map_redis_error(e).into()),
        }
    }
    
    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let chunk_key = self.get_chunk_key(recipient, chunk_hash);
        let metadata_key = self.get_metadata_key(recipient, chunk_hash);
        let list_key = self.get_recipient_list_key(recipient);
        
        // Use a pipeline to delete all related keys
        let mut pipe = redis::pipe();
        pipe.atomic();
        
        // Delete chunk data
        pipe.del(&chunk_key);
        
        // Delete metadata
        pipe.del(&metadata_key);
        
        // Remove from recipient's list
        pipe.srem(&list_key, chunk_hash);
        
        match pipe.query_async(&mut conn).await {
            Ok(_) => Ok(()),
            Err(e) => Err(Self::map_redis_error(e).into()),
        }
    }
    
    async fn test_connection(&self) -> Result<()> {
        let mut conn = self.get_connection().await?;
        
        match conn.ping::<String>().await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::ConnectionError {
                message: format!("Redis ping failed: {}", e),
            }.into()),
        }
    }
    
    fn backend_type(&self) -> StorageType {
        StorageType::Redis
    }
    
    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "Redis".to_string());
        info.insert("key_prefix".to_string(), self.key_prefix.clone());
        
        if let Some(ttl) = self.config.ttl {
            info.insert("ttl_seconds".to_string(), ttl.to_string());
        } else {
            info.insert("ttl_seconds".to_string(), "none".to_string());
        }
        
        info.insert("cluster_mode".to_string(), 
            self.config.cluster_mode.unwrap_or(false).to_string());
        
        // Extract connection info from URL (safely)
        if let Ok(parsed) = self.config.url.parse::<url::Url>() {
            if let Some(host) = parsed.host_str() {
                info.insert("host".to_string(), host.to_string());
            }
            if let Some(port) = parsed.port() {
                info.insert("port".to_string(), port.to_string());
            }
            if !parsed.path().is_empty() && parsed.path() != "/" {
                // Redis databases are indicated by path like /0, /1, etc.
                info.insert("database".to_string(), parsed.path().trim_start_matches('/').to_string());
            }
        }
        
        info
    }
    
    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();
        
        match self.test_connection().await {
            Ok(_) => {
                health.insert("status".to_string(), "healthy".to_string());
                health.insert("connection".to_string(), "ok".to_string());
                
                // Get Redis info
                let mut conn = self.get_connection().await?;
                
                // Get server info
                if let Ok(info_str) = conn.info::<String>("server").await {
                    // Parse Redis version from info string
                    for line in info_str.lines() {
                        if line.starts_with("redis_version:") {
                            let version = line.split(':').nth(1).unwrap_or("unknown");
                            health.insert("redis_version".to_string(), version.to_string());
                            break;
                        }
                    }
                }
                
                // Get memory info
                if let Ok(info_str) = conn.info::<String>("memory").await {
                    for line in info_str.lines() {
                        if line.starts_with("used_memory_human:") {
                            let memory = line.split(':').nth(1).unwrap_or("unknown");
                            health.insert("used_memory".to_string(), memory.to_string());
                        } else if line.starts_with("maxmemory_human:") {
                            let max_memory = line.split(':').nth(1).unwrap_or("unknown");
                            health.insert("max_memory".to_string(), max_memory.to_string());
                        }
                    }
                }
                
                // Check if we can write/read a test key
                let test_key = format!("{}:health_check", self.key_prefix);
                if let Ok(_) = conn.set_ex::<_, _, ()>(&test_key, "test", 1).await {
                    health.insert("write_test".to_string(), "ok".to_string());
                    let _ = conn.del::<_, ()>(&test_key).await; // Clean up
                } else {
                    health.insert("write_test".to_string(), "failed".to_string());
                }
            },
            Err(e) => {
                health.insert("status".to_string(), "unhealthy".to_string());
                health.insert("error".to_string(), e.to_string());
            }
        }
        
        Ok(health)
    }
    
    /// Redis batch operations can be very efficient with pipelines
    async fn save_chunks_batch(&self, recipient: &str, chunks: Vec<(String, Vec<u8>, ChunkMetadata)>) -> Result<Vec<String>> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }
        
        let mut conn = self.get_connection().await?;
        let mut pipe = redis::pipe();
        pipe.atomic();
        
        let list_key = self.get_recipient_list_key(recipient);
        let mut results = Vec::new();
        
        for (hash, data, metadata) in chunks {
            let chunk_key = self.get_chunk_key(recipient, &hash);
            let metadata_key = self.get_metadata_key(recipient, &hash);
            
            // Store chunk data
            if let Some(ttl) = self.config.ttl {
                pipe.set_ex(&chunk_key, &data, ttl);
            } else {
                pipe.set(&chunk_key, &data);
            }
            
            // Store metadata
            let metadata_json = serde_json::json!({
                "nonce": metadata.nonce,
                "sender_public_key": metadata.sender_public_key,
                "size": metadata.size,
                "created_at": metadata.created_at.to_rfc3339(),
            });
            
            if let Some(ttl) = self.config.ttl {
                pipe.set_ex(&metadata_key, &metadata_json.to_string(), ttl);
            } else {
                pipe.set(&metadata_key, &metadata_json.to_string());
            }
            
            // Add to recipient list
            pipe.sadd(&list_key, &hash);
            
            results.push(hash);
        }
        
        // Set TTL on the list if configured
        if let Some(ttl) = self.config.ttl {
            pipe.expire(&list_key, ttl as usize);
        }
        
        match pipe.query_async(&mut conn).await {
            Ok(_) => Ok(results),
            Err(e) => Err(Self::map_redis_error(e).into()),
        }
    }
}