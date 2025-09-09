use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::storage::backend::StorageConfig;
use crate::storage::encryption::EncryptionConfig;
use crate::storage::analytics::QuotaConfig;

#[derive(Error, Debug)]
pub enum ProfileError {
    #[error("Profile not found: {name}")]
    ProfileNotFound { name: String },
    
    #[error("Profile already exists: {name}")]
    ProfileAlreadyExists { name: String },
    
    #[error("Invalid profile name: {name}")]
    InvalidProfileName { name: String },
    
    #[error("Profile validation failed: {message}")]
    ValidationFailed { message: String },
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// A complete configuration profile containing all settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationProfile {
    pub name: String,
    pub description: String,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub author: Option<String>,
    pub tags: Vec<String>,
    
    // Core configuration
    pub storage_config: StorageConfig,
    pub encryption_config: Option<EncryptionConfig>,
    pub quota_config: Option<QuotaConfig>,
    
    // Application settings
    pub chunk_size_mb: u32,
    pub default_output_dir: String,
    pub skip_hidden_files: bool,
    pub dry_run_mode: bool,
    pub watcher_debounce_ms: u64,
    
    // Environment-specific overrides
    pub environment_overrides: HashMap<String, EnvironmentOverride>,
    
    // Custom metadata
    pub metadata: HashMap<String, String>,
}

/// Environment-specific configuration overrides
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentOverride {
    pub storage_config: Option<StorageConfig>,
    pub encryption_config: Option<EncryptionConfig>,
    pub quota_config: Option<QuotaConfig>,
    pub chunk_size_mb: Option<u32>,
    pub default_output_dir: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl Default for ConfigurationProfile {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            description: "Default configuration profile".to_string(),
            version: "1.0.0".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            author: None,
            tags: vec!["default".to_string()],
            storage_config: StorageConfig::default(),
            encryption_config: None,
            quota_config: None,
            chunk_size_mb: 10,
            default_output_dir: "output".to_string(),
            skip_hidden_files: true,
            dry_run_mode: false,
            watcher_debounce_ms: 1000,
            environment_overrides: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
}

impl ConfigurationProfile {
    /// Create a new profile with basic information
    pub fn new(name: String, description: String) -> Self {
        let mut profile = Self::default();
        profile.name = name;
        profile.description = description;
        profile.created_at = Utc::now();
        profile.updated_at = Utc::now();
        profile
    }
    
    /// Update the profile's last modified timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
    
    /// Add a tag to the profile
    pub fn add_tag(&mut self, tag: String) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
            self.touch();
        }
    }
    
    /// Remove a tag from the profile
    pub fn remove_tag(&mut self, tag: &str) {
        if let Some(pos) = self.tags.iter().position(|t| t == tag) {
            self.tags.remove(pos);
            self.touch();
        }
    }
    
    /// Add environment override
    pub fn add_environment_override(&mut self, env: String, override_config: EnvironmentOverride) {
        self.environment_overrides.insert(env, override_config);
        self.touch();
    }
    
    /// Get configuration for a specific environment
    pub fn get_config_for_environment(&self, env: &str) -> ConfigurationProfile {
        let mut config = self.clone();
        
        if let Some(override_config) = self.environment_overrides.get(env) {
            // Apply overrides
            if let Some(ref storage) = override_config.storage_config {
                config.storage_config = storage.clone();
            }
            
            if let Some(ref encryption) = override_config.encryption_config {
                config.encryption_config = Some(encryption.clone());
            }
            
            if let Some(ref quota) = override_config.quota_config {
                config.quota_config = Some(quota.clone());
            }
            
            if let Some(chunk_size) = override_config.chunk_size_mb {
                config.chunk_size_mb = chunk_size;
            }
            
            if let Some(ref output_dir) = override_config.default_output_dir {
                config.default_output_dir = output_dir.clone();
            }
            
            // Merge metadata
            for (key, value) in &override_config.metadata {
                config.metadata.insert(key.clone(), value.clone());
            }
        }
        
        config
    }
    
    /// Validate the profile configuration
    pub fn validate(&self) -> Result<(), ProfileError> {
        // Validate name
        if self.name.is_empty() {
            return Err(ProfileError::InvalidProfileName { 
                name: self.name.clone() 
            });
        }
        
        if self.name.chars().any(|c| !c.is_alphanumeric() && c != '_' && c != '-') {
            return Err(ProfileError::InvalidProfileName { 
                name: self.name.clone() 
            });
        }
        
        // Validate chunk size
        if self.chunk_size_mb == 0 || self.chunk_size_mb > 1000 {
            return Err(ProfileError::ValidationFailed { 
                message: format!("Invalid chunk size: {} MB", self.chunk_size_mb) 
            });
        }
        
        // Validate output directory
        if self.default_output_dir.is_empty() {
            return Err(ProfileError::ValidationFailed { 
                message: "Output directory cannot be empty".to_string() 
            });
        }
        
        Ok(())
    }
}

/// Manages configuration profiles
pub struct ProfileManager {
    profiles: HashMap<String, ConfigurationProfile>,
    profiles_dir: PathBuf,
    active_profile: Option<String>,
    current_environment: String,
}

impl ProfileManager {
    /// Create a new profile manager
    pub fn new<P: AsRef<Path>>(profiles_dir: P) -> Result<Self, ProfileError> {
        let profiles_dir = profiles_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&profiles_dir)?;
        
        let mut manager = Self {
            profiles: HashMap::new(),
            profiles_dir,
            active_profile: None,
            current_environment: "development".to_string(),
        };
        
        // Load existing profiles
        manager.load_all_profiles()?;
        
        // Create default profile if none exist
        if manager.profiles.is_empty() {
            let default_profile = ConfigurationProfile::default();
            manager.save_profile(default_profile)?;
            manager.active_profile = Some("default".to_string());
        }
        
        Ok(manager)
    }
    
    /// Load all profiles from disk
    pub fn load_all_profiles(&mut self) -> Result<(), ProfileError> {
        self.profiles.clear();
        
        for entry in std::fs::read_dir(&self.profiles_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    match self.load_profile_from_file(&path) {
                        Ok(profile) => {
                            self.profiles.insert(stem.to_string(), profile);
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to load profile {}: {}", stem, e);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Load a profile from file
    fn load_profile_from_file(&self, path: &Path) -> Result<ConfigurationProfile, ProfileError> {
        let content = std::fs::read_to_string(path)?;
        let profile: ConfigurationProfile = serde_json::from_str(&content)?;
        profile.validate()?;
        Ok(profile)
    }
    
    /// Save a profile to disk
    pub fn save_profile(&mut self, mut profile: ConfigurationProfile) -> Result<(), ProfileError> {
        profile.validate()?;
        profile.touch();
        
        let file_path = self.profiles_dir.join(format!("{}.json", profile.name));
        let content = serde_json::to_string_pretty(&profile)?;
        std::fs::write(&file_path, content)?;
        
        self.profiles.insert(profile.name.clone(), profile);
        Ok(())
    }
    
    /// Create a new profile
    pub fn create_profile(&mut self, name: String, description: String) -> Result<(), ProfileError> {
        if self.profiles.contains_key(&name) {
            return Err(ProfileError::ProfileAlreadyExists { name });
        }
        
        let profile = ConfigurationProfile::new(name, description);
        self.save_profile(profile)?;
        Ok(())
    }
    
    /// Delete a profile
    pub fn delete_profile(&mut self, name: &str) -> Result<(), ProfileError> {
        if !self.profiles.contains_key(name) {
            return Err(ProfileError::ProfileNotFound { 
                name: name.to_string() 
            });
        }
        
        // Don't allow deleting the active profile
        if self.active_profile.as_ref() == Some(&name.to_string()) {
            return Err(ProfileError::ValidationFailed { 
                message: "Cannot delete active profile".to_string() 
            });
        }
        
        // Remove from disk
        let file_path = self.profiles_dir.join(format!("{}.json", name));
        if file_path.exists() {
            std::fs::remove_file(file_path)?;
        }
        
        // Remove from memory
        self.profiles.remove(name);
        Ok(())
    }
    
    /// Get a profile by name
    pub fn get_profile(&self, name: &str) -> Result<&ConfigurationProfile, ProfileError> {
        self.profiles.get(name).ok_or(ProfileError::ProfileNotFound { 
            name: name.to_string() 
        })
    }
    
    /// Get a mutable reference to a profile
    pub fn get_profile_mut(&mut self, name: &str) -> Result<&mut ConfigurationProfile, ProfileError> {
        self.profiles.get_mut(name).ok_or(ProfileError::ProfileNotFound { 
            name: name.to_string() 
        })
    }
    
    /// List all profile names
    pub fn list_profiles(&self) -> Vec<String> {
        self.profiles.keys().cloned().collect()
    }
    
    /// List profiles with their basic info
    pub fn list_profiles_info(&self) -> Vec<(String, String, DateTime<Utc>)> {
        self.profiles.iter()
            .map(|(name, profile)| (
                name.clone(), 
                profile.description.clone(), 
                profile.updated_at
            ))
            .collect()
    }
    
    /// Set the active profile
    pub fn set_active_profile(&mut self, name: String) -> Result<(), ProfileError> {
        if !self.profiles.contains_key(&name) {
            return Err(ProfileError::ProfileNotFound { name });
        }
        
        self.active_profile = Some(name);
        Ok(())
    }
    
    /// Get the active profile
    pub fn get_active_profile(&self) -> Option<&ConfigurationProfile> {
        if let Some(ref name) = self.active_profile {
            self.profiles.get(name)
        } else {
            None
        }
    }
    
    /// Get the active profile name
    pub fn get_active_profile_name(&self) -> Option<&str> {
        self.active_profile.as_deref()
    }
    
    /// Set the current environment
    pub fn set_environment(&mut self, env: String) {
        self.current_environment = env;
    }
    
    /// Get the current environment
    pub fn get_environment(&self) -> &str {
        &self.current_environment
    }
    
    /// Get the effective configuration (active profile + environment overrides)
    pub fn get_effective_config(&self) -> Option<ConfigurationProfile> {
        if let Some(profile) = self.get_active_profile() {
            Some(profile.get_config_for_environment(&self.current_environment))
        } else {
            None
        }
    }
    
    /// Clone a profile with a new name
    pub fn clone_profile(&mut self, source: &str, target: String) -> Result<(), ProfileError> {
        if self.profiles.contains_key(&target) {
            return Err(ProfileError::ProfileAlreadyExists { name: target });
        }
        
        let source_profile = self.get_profile(source)?.clone();
        let mut new_profile = source_profile;
        new_profile.name = target.clone();
        new_profile.description = format!("Cloned from {}", source);
        new_profile.created_at = Utc::now();
        new_profile.updated_at = Utc::now();
        
        self.save_profile(new_profile)?;
        Ok(())
    }
    
    /// Search profiles by tags
    pub fn find_profiles_by_tag(&self, tag: &str) -> Vec<String> {
        self.profiles.iter()
            .filter(|(_, profile)| profile.tags.contains(&tag.to_string()))
            .map(|(name, _)| name.clone())
            .collect()
    }
    
    /// Update profile metadata
    pub fn update_profile_metadata(&mut self, name: &str, key: String, value: String) -> Result<(), ProfileError> {
        let profile = self.get_profile_mut(name)?;
        profile.metadata.insert(key, value);
        profile.touch();
        
        // Save to disk
        let file_path = self.profiles_dir.join(format!("{}.json", name));
        let content = serde_json::to_string_pretty(profile)?;
        std::fs::write(&file_path, content)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_profile_creation() {
        let profile = ConfigurationProfile::new(
            "test".to_string(), 
            "Test profile".to_string()
        );
        
        assert_eq!(profile.name, "test");
        assert_eq!(profile.description, "Test profile");
        assert!(profile.validate().is_ok());
    }
    
    #[test]
    fn test_profile_validation() {
        let mut profile = ConfigurationProfile::default();
        
        // Valid profile
        assert!(profile.validate().is_ok());
        
        // Invalid name
        profile.name = "".to_string();
        assert!(profile.validate().is_err());
        
        profile.name = "invalid name!".to_string();
        assert!(profile.validate().is_err());
        
        // Invalid chunk size
        profile.name = "valid_name".to_string();
        profile.chunk_size_mb = 0;
        assert!(profile.validate().is_err());
        
        profile.chunk_size_mb = 2000;
        assert!(profile.validate().is_err());
    }
    
    #[test]
    fn test_profile_manager() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let mut manager = ProfileManager::new(temp_dir.path())?;
        
        // Should have default profile
        assert_eq!(manager.list_profiles().len(), 1);
        assert!(manager.list_profiles().contains(&"default".to_string()));
        
        // Create new profile
        manager.create_profile("test".to_string(), "Test profile".to_string())?;
        assert_eq!(manager.list_profiles().len(), 2);
        
        // Clone profile
        manager.clone_profile("test", "test2".to_string())?;
        assert_eq!(manager.list_profiles().len(), 3);
        
        // Set active profile
        manager.set_active_profile("test".to_string())?;
        assert_eq!(manager.get_active_profile_name(), Some("test"));
        
        Ok(())
    }
}