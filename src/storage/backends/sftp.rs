use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::path::Path;
use std::io::{Read, Write};
use chrono::{DateTime, Utc};
use tokio::task;
use ssh2::Session;
use std::net::TcpStream;

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, SftpConfig, StorageError};

/// SFTP storage backend
/// Note: This is a simplified implementation that would need proper async SFTP client
pub struct SftpBackend {
    config: SftpConfig,
    connection_info: String,
}

impl SftpBackend {
    pub async fn new(config: SftpConfig) -> Result<Self> {
        // Validate configuration
        if config.host.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "SFTP host cannot be empty".to_string(),
            }.into());
        }
        
        if config.username.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "SFTP username cannot be empty".to_string(),
            }.into());
        }
        
        // Check that we have some form of authentication
        let has_password = config.password.is_some();
        let has_key = config.private_key_path.is_some() || config.private_key_content.is_some();
        
        if !has_password && !has_key {
            return Err(StorageError::ConfigurationError {
                message: "SFTP requires either password or private key authentication".to_string(),
            }.into());
        }
        
        let connection_info = format!("{}@{}:{}", 
            config.username, 
            config.host, 
            config.port.unwrap_or(22)
        );
        
        Ok(Self {
            config,
            connection_info: connection_info,
        })
    }
    
    fn get_remote_path(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}/{}/chunks/{}", 
            self.config.base_path.trim_end_matches('/'), 
            recipient, 
            chunk_hash
        )
    }
    
    fn get_metadata_path(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}.meta", self.get_remote_path(recipient, chunk_hash))
    }
    
    /// Create an SFTP session
    async fn create_session(&self) -> Result<Session> {
        let config = &self.config;
        let host = config.host.clone();
        let port = config.port.unwrap_or(22);
        let username = config.username.clone();
        let password = config.password.clone();
        let private_key_path = config.private_key_path.clone();
        let private_key_content = config.private_key_content.clone();
        
        task::spawn_blocking(move || {
            // Connect to the SSH server
            let tcp = TcpStream::connect(format!("{}:{}", host, port))?;
            let mut sess = Session::new()?;
            sess.set_tcp_stream(tcp);
            sess.handshake()?;
            
            // Authenticate
            if let Some(password) = password {
                sess.userauth_password(&username, &password)?;
            } else if let Some(key_content) = private_key_content {
                // Create a temporary file for the private key content
                use std::io::Write;
                let mut temp_file = tempfile::NamedTempFile::new()?;
                temp_file.write_all(key_content.as_bytes())?;
                sess.userauth_pubkey_file(&username, None, temp_file.path(), None)?;
            } else if let Some(key_path) = private_key_path {
                sess.userauth_pubkey_file(&username, None, Path::new(&key_path), None)?;
            } else {
                return Err(anyhow!("No authentication method provided"));
            }
            
            if !sess.authenticated() {
                return Err(anyhow!("Authentication failed"));
            }
            
            Ok(sess)
        }).await?
    }
    
    async fn _ensure_remote_directory(&self, path: &str) -> Result<()> {
        let path = path.to_string();
        let sess = self.create_session().await?;
        
        task::spawn_blocking(move || {
            let sftp = sess.sftp()?;
            
            // Create directory recursively
            let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            let mut current_path = String::new();
            
            for part in path_parts {
                current_path.push('/');
                current_path.push_str(part);
                
                // Try to create directory, ignore error if it already exists
                let _ = sftp.mkdir(Path::new(&current_path), 0o755);
            }
            
            Ok(())
        }).await?
    }
    
    async fn _upload_data(&self, remote_path: &str, data: &[u8]) -> Result<()> {
        let remote_path = remote_path.to_string();
        let data = data.to_vec();
        let sess = self.create_session().await?;
        
        task::spawn_blocking(move || {
            let sftp = sess.sftp()?;
            
            // Ensure parent directory exists
            if let Some(parent) = Path::new(&remote_path).parent() {
                let parent_str = parent.to_str().unwrap_or("");
                if !parent_str.is_empty() {
                    let path_parts: Vec<&str> = parent_str.split('/').filter(|s| !s.is_empty()).collect();
                    let mut current_path = String::new();
                    
                    for part in path_parts {
                        current_path.push('/');
                        current_path.push_str(part);
                        let _ = sftp.mkdir(Path::new(&current_path), 0o755);
                    }
                }
            }
            
            // Upload the file
            let mut remote_file = sftp.create(Path::new(&remote_path))?;
            remote_file.write_all(&data)?;
            remote_file.fsync()?;
            
            Ok(())
        }).await?
    }
    
    async fn _download_data(&self, remote_path: &str) -> Result<Vec<u8>> {
        let remote_path = remote_path.to_string();
        let sess = self.create_session().await?;
        
        task::spawn_blocking(move || {
            let sftp = sess.sftp()?;
            
            // Download the file
            let mut remote_file = sftp.open(Path::new(&remote_path))?;
            let mut buffer = Vec::new();
            remote_file.read_to_end(&mut buffer)?;
            
            Ok(buffer)
        }).await?
    }
    
    async fn _list_remote_files(&self, remote_dir: &str) -> Result<Vec<String>> {
        let remote_dir = remote_dir.to_string();
        let sess = self.create_session().await?;
        
        task::spawn_blocking(move || {
            let sftp = sess.sftp()?;
            
            // List directory contents
            let readdir = sftp.readdir(Path::new(&remote_dir))?;
            let mut files = Vec::new();
            
            for (path, _stat) in readdir {
                if let Some(filename) = path.file_name() {
                    if let Some(name_str) = filename.to_str() {
                        files.push(name_str.to_string());
                    }
                }
            }
            
            Ok(files)
        }).await?
    }
    
    async fn _delete_remote_file(&self, remote_path: &str) -> Result<()> {
        let remote_path = remote_path.to_string();
        let sess = self.create_session().await?;
        
        task::spawn_blocking(move || {
            let sftp = sess.sftp()?;
            
            // Delete the file
            sftp.unlink(Path::new(&remote_path))?;
            
            Ok(())
        }).await?
    }
    
    async fn _test_sftp_connection(&self) -> Result<()> {
        let sess = self.create_session().await?;
        
        task::spawn_blocking(move || {
            let sftp = sess.sftp()?;
            
            // Test basic SFTP functionality by getting the home directory
            let _home = sftp.realpath(Path::new("."))?;
            
            Ok(())
        }).await?
    }
}

#[async_trait]
impl StorageBackend for SftpBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let chunks_dir = format!("{}/{}/chunks", 
            self.config.base_path.trim_end_matches('/'), 
            recipient
        );
        
        // Ensure the remote directory exists
        self._ensure_remote_directory(&chunks_dir).await?;
        
        let remote_path = self.get_remote_path(recipient, chunk_hash);
        
        // Upload the chunk data
        self._upload_data(&remote_path, data).await?;
        
        Ok(chunk_hash.to_string())
    }
    
    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);
        
        // Create metadata JSON
        let metadata_json = serde_json::json!({
            "nonce": metadata.nonce,
            "sender_public_key": metadata.sender_public_key,
            "size": metadata.size,
            "created_at": metadata.created_at.to_rfc3339(),
        });
        
        let metadata_bytes = metadata_json.to_string().into_bytes();
        self._upload_data(&metadata_path, &metadata_bytes).await?;
        
        Ok(())
    }
    
    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let remote_path = self.get_remote_path(recipient, chunk_hash);
        
        match self._download_data(&remote_path).await {
            Ok(data) => Ok(data),
            Err(_) => Err(StorageError::ChunkNotFound {
                chunk_hash: chunk_hash.to_string(),
            }.into()),
        }
    }
    
    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);
        
        let data = match self._download_data(&metadata_path).await {
            Ok(data) => data,
            Err(_) => return Err(StorageError::ChunkNotFound {
                chunk_hash: chunk_hash.to_string(),
            }.into()),
        };
        
        let content = String::from_utf8(data)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;
        
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
    }
    
    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        let chunks_dir = format!("{}/{}/chunks", 
            self.config.base_path.trim_end_matches('/'), 
            recipient
        );
        
        let files = self._list_remote_files(&chunks_dir).await?;
        
        // Filter out metadata files
        let chunks: Vec<String> = files
            .into_iter()
            .filter(|name| !name.ends_with(".meta") && !name.ends_with(".tmp"))
            .collect();
        
        Ok(chunks)
    }
    
    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let chunk_path = self.get_remote_path(recipient, chunk_hash);
        let metadata_path = self.get_metadata_path(recipient, chunk_hash);
        
        // Delete both chunk and metadata files
        self._delete_remote_file(&chunk_path).await?;
        self._delete_remote_file(&metadata_path).await?;
        
        Ok(())
    }
    
    async fn test_connection(&self) -> Result<()> {
        self._test_sftp_connection().await
    }
    
    fn backend_type(&self) -> StorageType {
        StorageType::Sftp
    }
    
    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "SFTP".to_string());
        info.insert("host".to_string(), self.config.host.clone());
        info.insert("port".to_string(), self.config.port.unwrap_or(22).to_string());
        info.insert("username".to_string(), self.config.username.clone());
        info.insert("base_path".to_string(), self.config.base_path.clone());
        
        if self.config.private_key_path.is_some() || self.config.private_key_content.is_some() {
            info.insert("auth_method".to_string(), "private_key".to_string());
        } else {
            info.insert("auth_method".to_string(), "password".to_string());
        }
        
        info
    }
    
    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();
        
        match self.test_connection().await {
            Ok(_) => {
                health.insert("status".to_string(), "healthy".to_string());
                health.insert("connection".to_string(), "ok".to_string());
            }
            Err(e) => {
                health.insert("status".to_string(), "unhealthy".to_string());
                health.insert("error".to_string(), e.to_string());
            }
        }
        
        health.insert("host".to_string(), self.config.host.clone());
        health.insert("port".to_string(), self.config.port.unwrap_or(22).to_string());
        
        Ok(health)
    }
}

// Note: In a production implementation, you would use an async SFTP client like:
// - async-ssh2-tokio
// - tokio-sftp
// - Or implement your own using tokio and ssh2 with proper async wrappers
//
// The current implementation is a placeholder that demonstrates the interface
// but doesn't actually perform SFTP operations.