use async_trait::async_trait;
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use chrono::{DateTime, Utc};

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, LocalConfig, StorageError};
use crate::utils::{compute_sha256, create_dir_if_not_exists};

/// Local filesystem storage backend
pub struct LocalBackend {
    config: LocalConfig,
    base_path: PathBuf,
}

impl LocalBackend {
    pub async fn new(config: LocalConfig) -> Result<Self> {
        let base_path = PathBuf::from(&config.base_path);
        
        // Create base directory if needed
        if config.create_dirs.unwrap_or(true) {
            create_dir_if_not_exists(&base_path)?;
        }
        
        // Verify base path exists and is accessible
        if !base_path.exists() {
            return Err(StorageError::ConfigurationError {
                message: format!("Base path does not exist: {}", base_path.display()),
            }.into());
        }
        
        if !base_path.is_dir() {
            return Err(StorageError::ConfigurationError {
                message: format!("Base path is not a directory: {}", base_path.display()),
            }.into());
        }
        
        Ok(Self {
            config,
            base_path,
        })
    }
    
    fn get_recipient_path(&self, recipient: &str) -> PathBuf {
        self.base_path.join(recipient)
    }
    
    fn get_chunks_path(&self, recipient: &str) -> PathBuf {
        self.get_recipient_path(recipient).join("chunks")
    }
    
    fn get_chunk_path(&self, recipient: &str, chunk_hash: &str) -> PathBuf {
        self.get_chunks_path(recipient).join(chunk_hash)
    }
    
    fn get_metadata_path(&self, recipient: &str, chunk_hash: &str) -> PathBuf {
        self.get_chunks_path(recipient).join(format!("{}.meta", chunk_hash))
    }
    
    async fn ensure_recipient_dirs(&self, recipient: &str) -> Result<()> {
        let chunks_path = self.get_chunks_path(recipient);
        fs::create_dir_all(&chunks_path).await?;
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for LocalBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        self.ensure_recipient_dirs(recipient).await?;
        
        let chunk_path = self.get_chunk_path(recipient, chunk_hash);
        
        // Write to temporary file first, then rename for atomicity
        let temp_path = chunk_path.with_extension("tmp");
        
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(data).await?;
        file.flush().await?;
        drop(file);
        
        fs::rename(&temp_path, &chunk_path).await?;
        
        // Return the chunk hash as the storage key
        Ok(chunk_hash.to_string())
    }
    
    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        self.ensure_recipient_dirs(recipient).await?;
        
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);
        
        // Create metadata JSON
        let metadata_json = serde_json::json!({
            "nonce": metadata.nonce,
            "sender_public_key": metadata.sender_public_key,
            "size": metadata.size,
            "created_at": metadata.created_at.to_rfc3339(),
        });
        
        let temp_path = metadata_path.with_extension("tmp");
        fs::write(&temp_path, metadata_json.to_string()).await?;
        fs::rename(&temp_path, &metadata_path).await?;
        
        Ok(())
    }
    
    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let chunk_path = self.get_chunk_path(recipient, chunk_hash);
        
        if !chunk_path.exists() {
            return Err(StorageError::ChunkNotFound {
                chunk_hash: chunk_hash.to_string(),
            }.into());
        }
        
        let data = fs::read(&chunk_path).await?;
        Ok(data)
    }
    
    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);
        
        if !metadata_path.exists() {
            return Err(StorageError::ChunkNotFound {
                chunk_hash: chunk_hash.to_string(),
            }.into());
        }
        
        let content = fs::read_to_string(&metadata_path).await?;
        let json: serde_json::Value = serde_json::from_str(&content)?;
        
        let created_at = if let Some(created_str) = json["created_at"].as_str() {
            DateTime::parse_from_rfc3339(created_str)?.with_timezone(&Utc)
        } else {
            // Fallback to file modification time
            let file_metadata = fs::metadata(&metadata_path).await?;
            file_metadata.modified()?.into()
        };
        
        Ok(ChunkMetadata {
            nonce: json["nonce"].as_str().unwrap_or("").to_string(),
            sender_public_key: json["sender_public_key"].as_str().unwrap_or("").to_string(),
            size: json["size"].as_u64().unwrap_or(0),
            created_at,
        })
    }
    
    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        let chunks_path = self.get_chunks_path(recipient);
        
        if !chunks_path.exists() {
            return Ok(Vec::new());
        }
        
        let mut chunks = Vec::new();
        let mut entries = fs::read_dir(&chunks_path).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            
            // Skip metadata files and temp files
            if !name_str.ends_with(".meta") && !name_str.ends_with(".tmp") {
                chunks.push(name_str.to_string());
            }
        }
        
        Ok(chunks)
    }
    
    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let chunk_path = self.get_chunk_path(recipient, chunk_hash);
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);
        
        // Delete both chunk and metadata files
        if chunk_path.exists() {
            fs::remove_file(&chunk_path).await?;
        }
        
        if metadata_path.exists() {
            fs::remove_file(&metadata_path).await?;
        }
        
        Ok(())
    }
    
    async fn test_connection(&self) -> Result<()> {
        // Test by creating and deleting a test file
        let test_path = self.base_path.join(".test_write");
        
        fs::write(&test_path, b"test").await?;
        fs::remove_file(&test_path).await?;
        
        Ok(())
    }
    
    fn backend_type(&self) -> StorageType {
        StorageType::Local
    }
    
    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "Local".to_string());
        info.insert("base_path".to_string(), self.config.base_path.clone());
        
        // Add filesystem info if possible
        if let Ok(metadata) = std::fs::metadata(&self.base_path) {
            info.insert("readable".to_string(), metadata.permissions().readonly().to_string());
        }
        
        info
    }
    
    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();
        
        // Check if base path exists and is writable
        match self.test_connection().await {
            Ok(_) => {
                health.insert("status".to_string(), "healthy".to_string());
                health.insert("writable".to_string(), "true".to_string());
            }
            Err(e) => {
                health.insert("status".to_string(), "unhealthy".to_string());
                health.insert("error".to_string(), e.to_string());
            }
        }
        
        // Add storage info
        if let Ok(metadata) = fs::metadata(&self.base_path).await {
            health.insert("exists".to_string(), "true".to_string());
            health.insert("is_directory".to_string(), metadata.is_dir().to_string());
        } else {
            health.insert("exists".to_string(), "false".to_string());
        }
        
        Ok(health)
    }
}