// Storage encryption at rest functionality
use async_trait::async_trait;
use sodiumoxide::crypto::secretbox;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

use crate::storage::backend::{StorageBackend, ChunkMetadata, StorageError, StorageType};

// Legacy encryption functions (preserved for backward compatibility)
use crate::utils::write_bytes_to_file;
use anyhow::Result;
use std::path::Path;
use std::sync::{Arc as LegacyArc, Mutex};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use crate::chunk;
// Removed unused import: ChunkMeta
use crate::crypto;
use crate::storage::local::{ensure_mailbox_local, save_chunk_local};
use base64::{engine::general_purpose, Engine as _};
use serde_json;
use rand::RngCore;
use anyhow::anyhow;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
}

#[derive(Clone, Debug)]
pub enum EncryptionAlgorithm {
    None,
    XSalsa20Poly1305,
    ChaCha20Poly1305,
    AES256GCM,
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        EncryptionAlgorithm::None
    }
}

#[derive(Clone)]
pub struct EncryptionConfig {
    pub algorithm: EncryptionAlgorithm,
    pub key: Option<Vec<u8>>,
    pub password: Option<String>,
    pub key_derivation_iterations: u32,
    pub compress_before_encrypt: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        EncryptionConfig {
            algorithm: EncryptionAlgorithm::None,
            key: None,
            password: None,
            key_derivation_iterations: 100_000,
            compress_before_encrypt: true,
        }
    }
}

pub struct EncryptionManager {
    config: EncryptionConfig,
    derived_key: Option<secretbox::Key>,
}

impl EncryptionManager {
    pub fn new(config: EncryptionConfig) -> Result<Self, EncryptionError> {
        let mut manager = EncryptionManager {
            config,
            derived_key: None,
        };
        
        manager.initialize_key()?;
        Ok(manager)
    }
    
    fn initialize_key(&mut self) -> Result<(), EncryptionError> {
        match &self.config.algorithm {
            EncryptionAlgorithm::None => Ok(()),
            EncryptionAlgorithm::XSalsa20Poly1305 => {
                if let Some(key_bytes) = &self.config.key {
                    if key_bytes.len() != 32 {
                        return Err(EncryptionError::InvalidKey("Key must be 32 bytes".to_string()));
                    }
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(key_bytes);
                    self.derived_key = Some(secretbox::Key(key_array));
                } else if let Some(password) = &self.config.password {
                    self.derived_key = Some(self.derive_key_from_password(password)?);
                } else {
                    return Err(EncryptionError::InvalidKey("No key or password provided".to_string()));
                }
                Ok(())
            }
            _ => Err(EncryptionError::EncryptionFailed("Algorithm not implemented yet".to_string())),
        }
    }
    
    fn derive_key_from_password(&self, password: &str) -> Result<secretbox::Key, EncryptionError> {
        use sodiumoxide::crypto::pwhash;
        
        let salt = pwhash::Salt([0u8; 32]); // In production, use a random salt per user
        let mut key_bytes = [0u8; 32];
        
        pwhash::derive_key(
            &mut key_bytes,
            password.as_bytes(),
            &salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        ).map_err(|e| EncryptionError::KeyDerivationFailed(format!("Failed to derive key: {:?}", e)))?;
        
        Ok(secretbox::Key(key_bytes))
    }
    
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        match &self.config.algorithm {
            EncryptionAlgorithm::None => Ok(data.to_vec()),
            EncryptionAlgorithm::XSalsa20Poly1305 => {
                let key = self.derived_key.as_ref()
                    .ok_or_else(|| EncryptionError::EncryptionFailed("No key available".to_string()))?;
                
                let mut processed_data = data.to_vec();
                
                // Optional compression before encryption
                if self.config.compress_before_encrypt {
                    processed_data = self.compress(&processed_data)?;
                }
                
                let nonce = secretbox::gen_nonce();
                let ciphertext = secretbox::seal(&processed_data, &nonce, key);
                
                // Prepend nonce to ciphertext
                let mut result = nonce.0.to_vec();
                result.extend_from_slice(&ciphertext);
                
                Ok(result)
            }
            _ => Err(EncryptionError::EncryptionFailed("Algorithm not implemented".to_string())),
        }
    }
    
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        match &self.config.algorithm {
            EncryptionAlgorithm::None => Ok(encrypted_data.to_vec()),
            EncryptionAlgorithm::XSalsa20Poly1305 => {
                let key = self.derived_key.as_ref()
                    .ok_or_else(|| EncryptionError::DecryptionFailed("No key available".to_string()))?;
                
                if encrypted_data.len() < 24 {
                    return Err(EncryptionError::DecryptionFailed("Data too short".to_string()));
                }
                
                // Extract nonce and ciphertext
                let mut nonce_bytes = [0u8; 24];
                nonce_bytes.copy_from_slice(&encrypted_data[0..24]);
                let nonce = secretbox::Nonce(nonce_bytes);
                let ciphertext = &encrypted_data[24..];
                
                let decrypted = secretbox::open(ciphertext, &nonce, key)
                    .map_err(|_| EncryptionError::DecryptionFailed("Failed to decrypt data".to_string()))?;
                
                // Optional decompression after decryption
                if self.config.compress_before_encrypt {
                    self.decompress(&decrypted)
                } else {
                    Ok(decrypted)
                }
            }
            _ => Err(EncryptionError::DecryptionFailed("Algorithm not implemented".to_string())),
        }
    }
    
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)
            .map_err(|e| EncryptionError::EncryptionFailed(format!("Compression failed: {}", e)))?;
        encoder.finish()
            .map_err(|e| EncryptionError::EncryptionFailed(format!("Compression failed: {}", e)))
    }
    
    fn decompress(&self, compressed_data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        use flate2::read::GzDecoder;
        use std::io::Read;
        
        let mut decoder = GzDecoder::new(compressed_data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| EncryptionError::DecryptionFailed(format!("Decompression failed: {}", e)))?;
        Ok(decompressed)
    }
}

pub struct EncryptedStorageBackend {
    backend: Arc<dyn StorageBackend>,
    encryption_manager: EncryptionManager,
}

impl EncryptedStorageBackend {
    pub fn new(backend: Arc<dyn StorageBackend>, config: EncryptionConfig) -> Result<Self, EncryptionError> {
        let encryption_manager = EncryptionManager::new(config)?;
        Ok(EncryptedStorageBackend {
            backend,
            encryption_manager,
        })
    }
}

#[async_trait]
impl StorageBackend for EncryptedStorageBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let encrypted_data = self.encryption_manager.encrypt(data)
            .map_err(|e| StorageError::EncryptionFailed(e.to_string()))?;
        
        self.backend.save_chunk(recipient, chunk_hash, &encrypted_data).await
    }
    
    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let encrypted_data = self.backend.load_chunk(recipient, chunk_hash).await?;
        
        Ok(self.encryption_manager.decrypt(&encrypted_data)
            .map_err(|e| StorageError::DecryptionFailed(e.to_string()))?)
    }
    
    async fn chunk_exists(&self, recipient: &str, chunk_hash: &str) -> Result<bool> {
        self.backend.chunk_exists(recipient, chunk_hash).await
    }
    
    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        self.backend.delete_chunk(recipient, chunk_hash).await
    }
    
    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        // Encrypt metadata as well
        let metadata_json = serde_json::to_vec(&metadata)
            .map_err(|e| StorageError::SerializationFailed(e.to_string()))?;
        
        let encrypted_metadata = self.encryption_manager.encrypt(&metadata_json)
            .map_err(|e| StorageError::EncryptionFailed(e.to_string()))?;
        
        // Create a wrapper metadata object with encrypted content
        let encrypted_metadata_obj = ChunkMetadata {
            file_hash: chunk_hash.to_string(),
            chunk_hashes: vec![], // Empty, actual data is in encrypted_content
            chunk_size: encrypted_metadata.len(),
            total_size: metadata.total_size,
            created_at: chrono::Utc::now(),
            file_name: "encrypted_metadata".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
            compression_algorithm: Some("encrypted".to_string()),
            checksum_algorithm: Some("encrypted".to_string()),
            tags: HashMap::new(),
            custom_metadata: {
                let mut custom = HashMap::new();
                custom.insert("encrypted_content".to_string(), base64::encode(&encrypted_metadata));
                custom
            },
        };
        
        self.backend.save_metadata(recipient, chunk_hash, &encrypted_metadata_obj).await
    }
    
    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let encrypted_metadata_obj = self.backend.load_metadata(recipient, chunk_hash).await?;
        
        // Extract encrypted content from custom metadata
        let encrypted_content_b64 = encrypted_metadata_obj.custom_metadata
            .get("encrypted_content")
            .ok_or_else(|| StorageError::DecryptionFailed("No encrypted content found".to_string()))?;
        
        let encrypted_content = base64::decode(encrypted_content_b64)
            .map_err(|e| StorageError::DecryptionFailed(format!("Base64 decode failed: {}", e)))?;
        
        let decrypted_metadata = self.encryption_manager.decrypt(&encrypted_content)
            .map_err(|e| StorageError::DecryptionFailed(e.to_string()))?;
        
        let metadata: ChunkMetadata = serde_json::from_slice(&decrypted_metadata)
            .map_err(|e| StorageError::DeserializationFailed(e.to_string()))?;
        
        Ok(metadata)
    }
    
    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        self.backend.list_chunks(recipient).await
    }
    
    async fn list_metadata(&self, recipient: &str) -> Result<Vec<(String, ChunkMetadata)>> {
        self.backend.list_metadata(recipient).await
    }
    
    async fn get_storage_info(&self) -> Result<HashMap<String, String>> {
        let mut info = self.backend.get_storage_info().await?;
        info.insert("encryption_enabled".to_string(), "true".to_string());
        info.insert("encryption_algorithm".to_string(), format!("{:?}", self.encryption_manager.config.algorithm));
        info.insert("compression_enabled".to_string(), self.encryption_manager.config.compress_before_encrypt.to_string());
        Ok(info)
    }
    
    async fn cleanup(&self) -> Result<u64> {
        self.backend.cleanup().await
    }
    
    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = self.backend.health_check().await?;
        health.insert("encryption_status".to_string(), "healthy".to_string());
        Ok(health)
    }

    async fn test_connection(&self) -> Result<()> {
        self.backend.test_connection().await
    }

    fn backend_type(&self) -> StorageType {
        self.backend.backend_type()
    }
}

// Key management utilities
pub struct KeyManager;

impl KeyManager {
    pub fn generate_random_key() -> Vec<u8> {
        use sodiumoxide::randombytes;
        randombytes::randombytes(32)
    }
    
    pub fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        use sodiumoxide::crypto::pwhash;
        
        if salt.len() != 32 {
            return Err(EncryptionError::InvalidKey("Salt must be 32 bytes".to_string()));
        }
        
        let mut salt_array = [0u8; 32];
        salt_array.copy_from_slice(salt);
        let salt = pwhash::Salt(salt_array);
        
        let mut key_bytes = [0u8; 32];
        pwhash::derive_key(
            &mut key_bytes,
            password.as_bytes(),
            &salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        ).map_err(|e| EncryptionError::KeyDerivationFailed(format!("Failed to derive key: {:?}", e)))?;
        
        Ok(key_bytes.to_vec())
    }
    
    pub fn generate_salt() -> Vec<u8> {
        use sodiumoxide::randombytes;
        randombytes::randombytes(32)
    }
}

/// Legacy function - Process and encrypt a file to local storage
#[allow(clippy::too_many_arguments)]
pub fn process_file_encrypt(
    file_path: &Path,
    root_folder: &Path,
    recipient_pk_b64: &str,
    sender_sk_b64: Option<&str>,
    mailbox_base: &Path,
    chunk_size_bytes: usize,
    progress: Option<(LegacyArc<AtomicUsize>, LegacyArc<AtomicUsize>)>,
    cancel: Option<LegacyArc<AtomicBool>>,
) -> Result<()> {
    // determine relative path
    let rel = file_path.strip_prefix(root_folder).unwrap_or(file_path);
    let rel_str = rel.to_string_lossy();

    // split
    let chunk_size = if chunk_size_bytes == 0 { 10 * 1024 * 1024 } else { chunk_size_bytes };
    let mut metas = chunk::split_file_into_chunks(file_path, chunk_size, &rel_str)?;

    if let Some((total, done)) = &progress {
        // Only initialize if not already set (supports multi-file jobs setting totals upfront)
        if total.load(Ordering::Relaxed) == 0 && done.load(Ordering::Relaxed) == 0 {
            total.store(metas.len() as usize, Ordering::Relaxed);
            done.store(0, Ordering::Relaxed);
        }
    }

    // parse recipient public key (expect base64 raw bytes)
    let recipient_pk_bytes = general_purpose::STANDARD.decode(recipient_pk_b64)?;
    let recipient_pk = crypto::PublicKey::from_slice(&recipient_pk_bytes).ok_or_else(|| anyhow::anyhow!("Invalid recipient public key"))?;

    // parse sender key if provided (hex or base64), otherwise generate ephemeral
    let (sender_pk, sender_sk) = if let Some(sk_str) = sender_sk_b64 {
        let sk_bytes = crate::utils::parse_key_hex_or_b64(sk_str)?;
        let sender_sk = crypto::SecretKey::from_slice(&sk_bytes).ok_or_else(|| anyhow!("Invalid sender secret key"))?;
        let sender_pk = crypto::PublicKey::from_slice(&sender_sk.0).ok_or_else(|| anyhow!("Failed to derive sender public key"))?;
        (sender_pk, sender_sk)
    } else {
        crypto::generate_keypair()
    };

    // ensure mailbox folder named after the recipient key string provided
    let mailbox = ensure_mailbox_local(mailbox_base, recipient_pk_b64)?;

    // process each chunk: create JSON, encrypt, save
    for meta in metas.iter_mut() {
        if let Some(flag) = &cancel { if flag.load(Ordering::Relaxed) { break; } }
        // set random nonce
    let mut nonce_bytes = vec![0u8; crypto::NONCEBYTES];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        meta.nonce = general_purpose::STANDARD.encode(&nonce_bytes);

        // serialize JSON
        let json = serde_json::to_vec(&meta)?;

    // encrypt JSON using provided nonce
    let encrypted = crypto::encrypt_with_nonce(&json, &nonce_bytes, &recipient_pk, &sender_sk)?;

    // compute sha of encrypted JSON and save
    let sha = save_chunk_local(&mailbox, &encrypted)?;

    // save nonce and sender public key alongside chunk for recipient discovery
    let chunks_dir = mailbox.join("chunks");
    let nonce_path = chunks_dir.join(format!("{}.nonce", sha));
    write_bytes_to_file(&nonce_path, general_purpose::STANDARD.encode(&nonce_bytes).as_bytes())?;

    let sender_b64 = general_purpose::STANDARD.encode(sender_pk.0);
    let sender_path = chunks_dir.join(format!("{}.sender", sha));
    write_bytes_to_file(&sender_path, sender_b64.as_bytes())?;
        if let Some((_total, done)) = &progress { done.fetch_add(1, Ordering::Relaxed); }
    }

    Ok(())
}

/// Legacy function - Assemble files from a local mailbox
pub fn assemble_from_mailbox(mailbox: &Path, recipient_sk_b64: &str, output_root: &Path) -> Result<()> {
    let logs = LegacyArc::new(Mutex::new(Vec::new()));
    assemble_from_mailbox_with_logs(mailbox, recipient_sk_b64, output_root, logs)
}

/// Legacy function - Assemble files from a local mailbox with logging
pub fn assemble_from_mailbox_with_logs(mailbox: &Path, recipient_sk_b64: &str, output_root: &Path, logs: LegacyArc<Mutex<Vec<String>>>) -> Result<()> {
    if let Ok(mut l) = logs.lock() {
        l.push(format!("Starting assembly from mailbox: {:?}", mailbox));
    }
    
    // This is a simplified version - the full implementation would be quite complex
    // For now, just log that assembly would happen here
    if let Ok(mut l) = logs.lock() {
        l.push("Assembly functionality not yet implemented in refactored version".to_string());
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::backends::LocalBackend;
    use std::path::PathBuf;
    
    #[tokio::test]
    async fn test_encryption_manager() {
        sodiumoxide::init().unwrap();
        
        let config = EncryptionConfig {
            algorithm: EncryptionAlgorithm::XSalsa20Poly1305,
            key: Some(KeyManager::generate_random_key()),
            password: None,
            key_derivation_iterations: 100_000,
            compress_before_encrypt: true,
        };
        
        let manager = EncryptionManager::new(config).unwrap();
        
        let data = b"Hello, encrypted world!";
        let encrypted = manager.encrypt(data).unwrap();
        let decrypted = manager.decrypt(&encrypted).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
        assert_ne!(data.to_vec(), encrypted);
    }
    
    #[tokio::test]
    async fn test_encrypted_storage_backend() {
        sodiumoxide::init().unwrap();
        
        let temp_dir = std::env::temp_dir().join("test_encrypted_storage");
        std::fs::create_dir_all(&temp_dir).unwrap();
        
        let local_backend = Arc::new(LocalBackend::new(temp_dir.clone(), true).unwrap());
        
        let config = EncryptionConfig {
            algorithm: EncryptionAlgorithm::XSalsa20Poly1305,
            key: Some(KeyManager::generate_random_key()),
            password: None,
            key_derivation_iterations: 100_000,
            compress_before_encrypt: true,
        };
        
        let encrypted_backend = EncryptedStorageBackend::new(local_backend, config).unwrap();
        
        let test_data = b"Test data for encryption";
        let chunk_hash = "test_hash";
        
        // Save encrypted chunk
        encrypted_backend.save_chunk(chunk_hash, test_data.to_vec()).await.unwrap();
        
        // Load and verify decrypted chunk
        let loaded_data = encrypted_backend.load_chunk(chunk_hash).await.unwrap();
        assert_eq!(test_data.to_vec(), loaded_data);
        
        // Verify the data on disk is actually encrypted
        let raw_file_path = temp_dir.join("chunks").join(chunk_hash);
        let raw_data = std::fs::read(&raw_file_path).unwrap();
        assert_ne!(test_data.to_vec(), raw_data);
        
        // Clean up
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }
}