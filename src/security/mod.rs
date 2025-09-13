//! # Security Module
//!
//! This module provides comprehensive security utilities for the n0n project, including:
//!
//! - **Memory Security**: Secure memory allocation and management with automatic zeroing
//! - **Input Validation**: Comprehensive input validation to prevent common security vulnerabilities
//! - **Key Derivation**: Multiple key derivation functions (PBKDF2, Scrypt, Argon2id, HKDF)
//! - **Secure Data Types**: Zero-on-drop data structures for handling sensitive information
//!
//! ## Usage Examples
//!
//! ### Secure String Handling
//! ```rust
//! use n0n::security::{SecureString, SecureBuffer};
//!
//! let mut secure_password = SecureString::from_string("my_password".to_string());
//! // Password is automatically zeroed when dropped
//! ```
//!
//! ### Input Validation
//! ```rust
//! use n0n::security::input_validation::InputValidator;
//!
//! // Validate email addresses
//! InputValidator::validate_email("user@example.com")?;
//!
//! // Validate file paths (prevents path traversal)
//! InputValidator::validate_file_path("safe/file.txt")?;
//! ```
//!
//! ### Key Derivation
//! ```rust
//! use n0n::security::key_derivation::{derive_key, KdfParams};
//!
//! let params = KdfParams::default(); // Uses Argon2id
//! let derived = derive_key(b"password", None, &params)?;
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop};
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, anyhow};

pub mod memory;
pub mod input_validation;
pub mod key_derivation;

/// Secure string that automatically zeros memory on drop
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    /// Create a new secure string from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a secure string from a regular string
    pub fn from_string(s: String) -> Self {
        Self::new(s.into_bytes())
    }

    /// Get the data as bytes (be careful with this!)
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the secure string is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Convert to string (unsafe - only use when necessary)
    pub fn to_string(&self) -> Result<String> {
        String::from_utf8(self.data.clone())
            .map_err(|e| anyhow!("Invalid UTF-8 in secure string: {}", e))
    }

    /// Clear the data immediately
    pub fn clear(&mut self) {
        self.data.zeroize();
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::from_string(s)
    }
}

impl From<Vec<u8>> for SecureString {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

/// Secure buffer for cryptographic keys and sensitive data
pub struct SecureBuffer {
    data: Vec<u8>,
    created_at: SystemTime,
    max_lifetime: std::time::Duration,
}

impl SecureBuffer {
    /// Create a new secure buffer with a maximum lifetime
    pub fn new(data: Vec<u8>, max_lifetime: std::time::Duration) -> Self {
        Self {
            data,
            created_at: SystemTime::now(),
            max_lifetime,
        }
    }

    /// Create a secure buffer with no lifetime limit (use with caution)
    pub fn permanent(data: Vec<u8>) -> Self {
        Self {
            data,
            created_at: SystemTime::now(),
            max_lifetime: std::time::Duration::from_secs(u64::MAX),
        }
    }

    /// Get the data if still within lifetime
    pub fn get_data(&self) -> Result<&[u8]> {
        if self.is_expired() {
            return Err(anyhow!("Secure buffer has expired"));
        }
        Ok(&self.data)
    }

    /// Check if the buffer has expired
    pub fn is_expired(&self) -> bool {
        if let Ok(elapsed) = self.created_at.elapsed() {
            elapsed > self.max_lifetime
        } else {
            true // Assume expired if we can't determine elapsed time
        }
    }

    /// Get the remaining lifetime
    pub fn remaining_lifetime(&self) -> Option<std::time::Duration> {
        if let Ok(elapsed) = self.created_at.elapsed() {
            if elapsed < self.max_lifetime {
                Some(self.max_lifetime - elapsed)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Refresh the lifetime (reset the creation time)
    pub fn refresh_lifetime(&mut self) {
        self.created_at = SystemTime::now();
    }

    /// Get the size of the buffer
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Clear the buffer immediately
    pub fn clear(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Secure key wrapper that ensures keys are properly zeroized
pub struct SecureKey {
    key_data: Vec<u8>,
    key_type: KeyType,
    created_at: SystemTime,
    usage_count: std::sync::atomic::AtomicU64,
    max_usage: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Encryption,
    Signing,
    Derivation,
    Authentication,
}

impl SecureKey {
    /// Create a new secure key
    pub fn new(key_data: Vec<u8>, key_type: KeyType) -> Self {
        Self {
            key_data,
            key_type,
            created_at: SystemTime::now(),
            usage_count: std::sync::atomic::AtomicU64::new(0),
            max_usage: None,
        }
    }

    /// Create a secure key with usage limit
    pub fn with_usage_limit(key_data: Vec<u8>, key_type: KeyType, max_usage: u64) -> Self {
        Self {
            key_data,
            key_type,
            created_at: SystemTime::now(),
            usage_count: std::sync::atomic::AtomicU64::new(0),
            max_usage: Some(max_usage),
        }
    }

    /// Get the key data for use (increments usage counter)
    pub fn get_key_data(&self) -> Result<&[u8]> {
        let current_usage = self.usage_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        if let Some(max) = self.max_usage {
            if current_usage >= max {
                return Err(anyhow!("Key usage limit exceeded"));
            }
        }
        
        Ok(&self.key_data)
    }

    /// Get key data without incrementing usage counter (for read-only operations)
    pub fn peek_key_data(&self) -> &[u8] {
        &self.key_data
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Get the current usage count
    pub fn usage_count(&self) -> u64 {
        self.usage_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get the maximum usage limit
    pub fn max_usage(&self) -> Option<u64> {
        self.max_usage
    }

    /// Get the age of the key
    pub fn age(&self) -> Result<std::time::Duration> {
        self.created_at.elapsed()
            .map_err(|e| anyhow!("Failed to calculate key age: {}", e))
    }

    /// Check if the key should be rotated based on age or usage
    pub fn should_rotate(&self, max_age: std::time::Duration, usage_threshold: Option<f64>) -> bool {
        // Check age-based rotation
        if let Ok(age) = self.age() {
            if age > max_age {
                return true;
            }
        }

        // Check usage-based rotation
        if let (Some(max_usage), Some(threshold)) = (self.max_usage, usage_threshold) {
            let current_usage = self.usage_count();
            let usage_ratio = current_usage as f64 / max_usage as f64;
            if usage_ratio > threshold {
                return true;
            }
        }

        false
    }

    /// Create a derived key from this key
    pub fn derive_key(&self, info: &[u8], length: usize) -> Result<SecureKey> {
        let key_data = self.get_key_data()?;
        let derived_data = crate::security::key_derivation::hkdf_derive(key_data, &[], info, length)?;
        Ok(SecureKey::new(derived_data, KeyType::Derivation))
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.key_data.zeroize();
    }
}

/// Secure session that manages temporary sensitive data
pub struct SecureSession {
    session_id: String,
    created_at: SystemTime,
    last_activity: std::sync::Mutex<SystemTime>,
    max_lifetime: std::time::Duration,
    idle_timeout: std::time::Duration,
    data: std::sync::Mutex<std::collections::HashMap<String, SecureBuffer>>,
}

impl SecureSession {
    /// Create a new secure session
    pub fn new(
        session_id: String,
        max_lifetime: std::time::Duration,
        idle_timeout: std::time::Duration,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            session_id,
            created_at: now,
            last_activity: std::sync::Mutex::new(now),
            max_lifetime,
            idle_timeout,
            data: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Get the session ID
    pub fn id(&self) -> &str {
        &self.session_id
    }

    /// Check if the session is still valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now();

        // Check absolute lifetime
        if let Ok(elapsed) = self.created_at.elapsed() {
            if elapsed > self.max_lifetime {
                return false;
            }
        } else {
            return false;
        }

        // Check idle timeout
        if let Ok(last_activity) = self.last_activity.lock() {
            if let Ok(idle_time) = last_activity.elapsed() {
                if idle_time > self.idle_timeout {
                    return false;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }

        true
    }

    /// Update the last activity timestamp
    pub fn touch(&self) {
        if let Ok(mut last_activity) = self.last_activity.lock() {
            *last_activity = SystemTime::now();
        }
    }

    /// Store secure data in the session
    pub fn store(&self, key: &str, data: SecureBuffer) -> Result<()> {
        if !self.is_valid() {
            return Err(anyhow!("Session is no longer valid"));
        }

        self.touch();
        
        if let Ok(mut session_data) = self.data.lock() {
            session_data.insert(key.to_string(), data);
            Ok(())
        } else {
            Err(anyhow!("Failed to acquire session data lock"))
        }
    }

    /// Retrieve secure data from the session
    pub fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if !self.is_valid() {
            return Err(anyhow!("Session is no longer valid"));
        }

        self.touch();

        if let Ok(session_data) = self.data.lock() {
            if let Some(buffer) = session_data.get(key) {
                if buffer.is_expired() {
                    return Ok(None);
                }
                Ok(Some(buffer.get_data()?.to_vec()))
            } else {
                Ok(None)
            }
        } else {
            Err(anyhow!("Failed to acquire session data lock"))
        }
    }

    /// Remove data from the session
    pub fn remove(&self, key: &str) -> Result<bool> {
        self.touch();

        if let Ok(mut session_data) = self.data.lock() {
            Ok(session_data.remove(key).is_some())
        } else {
            Err(anyhow!("Failed to acquire session data lock"))
        }
    }

    /// Clear all data from the session
    pub fn clear(&self) {
        if let Ok(mut session_data) = self.data.lock() {
            for (_, mut buffer) in session_data.drain() {
                buffer.clear();
            }
        }
    }

    /// Get session statistics
    pub fn stats(&self) -> SessionStats {
        let data_count = if let Ok(session_data) = self.data.lock() {
            session_data.len()
        } else {
            0
        };

        SessionStats {
            session_id: self.session_id.clone(),
            created_at: self.created_at,
            last_activity: *self.last_activity.lock().unwrap(),
            data_items: data_count,
            is_valid: self.is_valid(),
            age: self.created_at.elapsed().unwrap_or_default(),
            remaining_lifetime: self.max_lifetime.checked_sub(
                self.created_at.elapsed().unwrap_or_default()
            ),
        }
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Session statistics for monitoring
pub struct SessionStats {
    pub session_id: String,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    pub data_items: usize,
    pub is_valid: bool,
    pub age: std::time::Duration,
    pub remaining_lifetime: Option<std::time::Duration>,
}

/// Global session manager
pub struct SessionManager {
    sessions: std::sync::RwLock<std::collections::HashMap<String, SecureSession>>,
    cleanup_interval: std::time::Duration,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(cleanup_interval: std::time::Duration) -> Self {
        Self {
            sessions: std::sync::RwLock::new(std::collections::HashMap::new()),
            cleanup_interval,
        }
    }

    /// Create a new session
    pub fn create_session(
        &self,
        max_lifetime: std::time::Duration,
        idle_timeout: std::time::Duration,
    ) -> Result<String> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = SecureSession::new(session_id.clone(), max_lifetime, idle_timeout);

        if let Ok(mut sessions) = self.sessions.write() {
            sessions.insert(session_id.clone(), session);
            Ok(session_id)
        } else {
            Err(anyhow!("Failed to acquire sessions write lock"))
        }
    }

    /// Check if a session exists
    pub fn session_exists(&self, session_id: &str) -> Result<bool> {
        if let Ok(sessions) = self.sessions.read() {
            Ok(sessions.contains_key(session_id))
        } else {
            Err(anyhow!("Failed to acquire sessions read lock"))
        }
    }

    /// Remove a session
    pub fn remove_session(&self, session_id: &str) -> Result<bool> {
        if let Ok(mut sessions) = self.sessions.write() {
            if let Some(mut session) = sessions.remove(session_id) {
                session.clear();
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(anyhow!("Failed to acquire sessions write lock"))
        }
    }

    /// Clean up expired sessions
    pub fn cleanup_expired_sessions(&self) -> usize {
        let mut removed_count = 0;

        if let Ok(mut sessions) = self.sessions.write() {
            let expired_sessions: Vec<String> = sessions
                .iter()
                .filter(|(_, session)| !session.is_valid())
                .map(|(id, _)| id.clone())
                .collect();

            for session_id in expired_sessions {
                if let Some(mut session) = sessions.remove(&session_id) {
                    session.clear();
                    removed_count += 1;
                }
            }
        }

        removed_count
    }

    /// Get session statistics
    pub fn get_stats(&self) -> Vec<SessionStats> {
        if let Ok(sessions) = self.sessions.read() {
            sessions.values().map(|session| session.stats()).collect()
        } else {
            Vec::new()
        }
    }

    /// Start automatic cleanup background task
    pub fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let cleanup_interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                // Note: This is a simplified version - in practice, you'd need
                // a more sophisticated way to share the session manager
                tracing::debug!("Session cleanup task tick");
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_secure_string() {
        let mut secure_str = SecureString::from_string("sensitive data".to_string());
        
        assert_eq!(secure_str.len(), 14);
        assert!(!secure_str.is_empty());
        assert_eq!(secure_str.as_bytes(), b"sensitive data");
        
        secure_str.clear();
        assert_eq!(secure_str.len(), 14); // Length remains the same, but data is zeroed
    }

    #[test]
    fn test_secure_buffer_lifetime() {
        let data = b"temporary data".to_vec();
        let buffer = SecureBuffer::new(data, Duration::from_millis(100));
        
        assert!(!buffer.is_expired());
        assert!(buffer.get_data().is_ok());
        
        std::thread::sleep(Duration::from_millis(150));
        assert!(buffer.is_expired());
        assert!(buffer.get_data().is_err());
    }

    #[test]
    fn test_secure_key_usage_limit() {
        let key_data = b"secret key data".to_vec();
        let key = SecureKey::with_usage_limit(key_data, KeyType::Encryption, 3);
        
        // First 3 uses should work
        assert!(key.get_key_data().is_ok());
        assert!(key.get_key_data().is_ok());
        assert!(key.get_key_data().is_ok());
        
        // Fourth use should fail
        assert!(key.get_key_data().is_err());
        
        assert_eq!(key.usage_count(), 4); // Including the failed attempt
    }

    #[test]
    fn test_secure_session_validity() {
        let session = SecureSession::new(
            "test-session".to_string(),
            Duration::from_secs(60),
            Duration::from_secs(30),
        );
        
        assert!(session.is_valid());
        assert_eq!(session.id(), "test-session");
        
        session.touch(); // Should update last activity
        assert!(session.is_valid());
    }

    #[test]
    fn test_session_data_storage() {
        let session = SecureSession::new(
            "test-session".to_string(),
            Duration::from_secs(60),
            Duration::from_secs(30),
        );
        
        let buffer = SecureBuffer::new(b"session data".to_vec(), Duration::from_secs(10));
        session.store("test-key", buffer).unwrap();
        
        let retrieved = session.retrieve("test-key").unwrap();
        assert_eq!(retrieved, Some(b"session data".to_vec()));
        
        assert!(session.remove("test-key").unwrap());
        assert_eq!(session.retrieve("test-key").unwrap(), None);
    }

    #[test]
    fn test_session_manager() {
        let manager = SessionManager::new(Duration::from_secs(60));
        
        let session_id = manager.create_session(
            Duration::from_secs(300),
            Duration::from_secs(60),
        ).unwrap();
        
        assert!(manager.get_session(&session_id).unwrap().is_some());
        
        assert!(manager.remove_session(&session_id).unwrap());
        assert!(manager.get_session(&session_id).unwrap().is_none());
    }

    #[test]
    fn test_key_rotation_decision() {
        let key = SecureKey::with_usage_limit(
            b"test key".to_vec(),
            KeyType::Encryption,
            100,
        );
        
        // Should not rotate initially
        assert!(!key.should_rotate(Duration::from_secs(3600), Some(0.8)));
        
        // Use the key many times
        for _ in 0..85 {
            let _ = key.get_key_data();
        }
        
        // Should rotate based on usage threshold (85/100 = 85% > 80%)
        assert!(key.should_rotate(Duration::from_secs(3600), Some(0.8)));
    }
}