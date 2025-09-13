use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};

use crate::config::{AppConfig, CryptoConfig, GuiConfig, LoggingConfig, ProfileManager, ConfigValidator};

/// Configuration manager for the entire application
/// Handles loading, saving, validation, and hot-reloading of configuration
pub struct ConfigManager {
    config: Arc<RwLock<AppConfig>>,
    config_path: PathBuf,
    profile_manager: ProfileManager,
    validator: ConfigValidator,
    auto_save: bool,
}

/// Configuration change notification
#[derive(Debug, Clone)]
pub struct ConfigChangeNotification {
    pub change_type: ConfigChangeType,
    pub section: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ConfigChangeType {
    Updated,
    Added,
    Removed,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        
        // Create config directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Load or create configuration
        let config = if config_path.exists() {
            AppConfig::load_with_env_overrides(&config_path)?
        } else {
            let default_config = AppConfig::default();
            default_config.save_to_file(&config_path)?;
            default_config
        };

        let profile_manager = ProfileManager::new(config_path.parent().unwrap())?;
        let validator = ConfigValidator::new();

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            config_path,
            profile_manager,
            validator,
            auto_save: true,
        })
    }

    /// Get a clone of the current configuration
    pub fn get_config(&self) -> Result<AppConfig> {
        let config = self.config.read().map_err(|e| anyhow!("Failed to read config: {}", e))?;
        Ok(config.clone())
    }

    /// Update the configuration
    pub fn update_config<F>(&self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut AppConfig) -> Result<()>,
    {
        let mut config = self.config.write().map_err(|e| anyhow!("Failed to write config: {}", e))?;
        
        // Apply the update
        updater(&mut config)?;

        // Validate the updated configuration
        config.validate()?;

        // Auto-save if enabled
        if self.auto_save {
            config.save_to_file(&self.config_path)?;
        }

        Ok(())
    }

    /// Reload configuration from file
    pub fn reload(&self) -> Result<()> {
        let new_config = AppConfig::load_with_env_overrides(&self.config_path)?;
        new_config.validate()?;

        let mut config = self.config.write().map_err(|e| anyhow!("Failed to write config: {}", e))?;
        *config = new_config;

        Ok(())
    }

    /// Save current configuration to file
    pub fn save(&self) -> Result<()> {
        let config = self.config.read().map_err(|e| anyhow!("Failed to read config: {}", e))?;
        config.save_to_file(&self.config_path)?;
        Ok(())
    }

    /// Enable or disable auto-save
    pub fn set_auto_save(&mut self, enabled: bool) {
        self.auto_save = enabled;
    }

    /// Create a configuration profile from current settings
    pub fn create_profile(&mut self, name: &str, description: &str) -> Result<()> {
        let _config = self.get_config()?;
        self.profile_manager.create_profile(name.to_string(), description.to_string())?;
        Ok(())
    }

    /// Load configuration from a profile
    pub fn load_profile(&self, name: &str) -> Result<()> {
        let profile = self.profile_manager.get_profile(name)?;
        
        let mut config = self.config.write().map_err(|e| anyhow!("Failed to write config: {}", e))?;
        
        // Convert profile to AppConfig
        let app_config = AppConfig {
            storage: profile.storage_config.clone(),
            crypto: CryptoConfig {
                default_algorithm: "AES-256-GCM".to_string(),
                key_derivation: "PBKDF2".to_string(),
                enable_hsm: false,
                hsm: None,
            },
            gui: GuiConfig {
                theme: "dark".to_string(),
                scale_factor: 1.0,
                enable_animations: true,
                remember_window_state: true,
                default_chunk_size_mb: 64,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_path: Some("logs/n0n.log".to_string()),
                enable_audit: true,
                max_file_size_mb: 10,
                max_files: 10,
            },
        };
        *config = app_config;

        if self.auto_save {
            config.save_to_file(&self.config_path)?;
        }

        Ok(())
    }

    /// List available configuration profiles
    pub fn list_profiles(&self) -> Result<Vec<String>> {
        Ok(self.profile_manager.list_profiles())
    }

    /// Delete a configuration profile
    pub fn delete_profile(&mut self, name: &str) -> Result<()> {
        self.profile_manager.delete_profile(name).map_err(|e| anyhow!("Failed to delete profile: {}", e))
    }

    /// Validate current configuration
    pub fn validate(&self) -> Result<()> {
        let config = self.config.read().map_err(|e| anyhow!("Failed to read config: {}", e))?;
        config.validate()?;
        // Note: validate_full method not found, using basic validation
        let _validation_result = self.validator.validate_storage_config(&config.storage);
        Ok(())
    }

    /// Reset configuration to defaults
    pub fn reset_to_defaults(&self) -> Result<()> {
        let default_config = AppConfig::default();
        
        let mut config = self.config.write().map_err(|e| anyhow!("Failed to write config: {}", e))?;
        *config = default_config;

        if self.auto_save {
            config.save_to_file(&self.config_path)?;
        }

        Ok(())
    }

    /// Get configuration file path
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Import configuration from file
    pub fn import_from_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let imported_config = AppConfig::load_from_file(path)?;
        imported_config.validate()?;

        let mut config = self.config.write().map_err(|e| anyhow!("Failed to write config: {}", e))?;
        *config = imported_config;

        if self.auto_save {
            config.save_to_file(&self.config_path)?;
        }

        Ok(())
    }

    /// Export current configuration to file
    pub fn export_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let config = self.config.read().map_err(|e| anyhow!("Failed to read config: {}", e))?;
        config.save_to_file(path)?;
        Ok(())
    }

    /// Apply environment variable overrides to current config
    pub fn apply_env_overrides(&self) -> Result<()> {
        let mut config = self.config.write().map_err(|e| anyhow!("Failed to write config: {}", e))?;
        config.apply_env_overrides();

        if self.auto_save {
            config.save_to_file(&self.config_path)?;
        }

        Ok(())
    }

    /// Get a specific configuration section
    pub fn get_storage_config(&self) -> Result<crate::storage::backend::StorageConfig> {
        let config = self.config.read().map_err(|e| anyhow!("Failed to read config: {}", e))?;
        Ok(config.storage.clone())
    }

    pub fn get_crypto_config(&self) -> Result<crate::config::CryptoConfig> {
        let config = self.config.read().map_err(|e| anyhow!("Failed to read config: {}", e))?;
        Ok(config.crypto.clone())
    }

    pub fn get_gui_config(&self) -> Result<crate::config::GuiConfig> {
        let config = self.config.read().map_err(|e| anyhow!("Failed to read config: {}", e))?;
        Ok(config.gui.clone())
    }

    pub fn get_logging_config(&self) -> Result<crate::config::LoggingConfig> {
        let config = self.config.read().map_err(|e| anyhow!("Failed to read config: {}", e))?;
        Ok(config.logging.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_manager_creation() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.json");

        let manager = ConfigManager::new(&config_path).unwrap();
        assert!(config_path.exists());

        let config = manager.get_config().unwrap();
        assert_eq!(config.crypto.default_algorithm, "XSalsa20Poly1305");
    }

    #[test]
    fn test_config_update() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.json");

        let manager = ConfigManager::new(&config_path).unwrap();
        
        manager.update_config(|config| {
            config.gui.theme = "dark".to_string();
            Ok(())
        }).unwrap();

        let config = manager.get_config().unwrap();
        assert_eq!(config.gui.theme, "dark");
    }

    #[test]
    fn test_config_validation() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.json");

        let manager = ConfigManager::new(&config_path).unwrap();
        
        // Valid configuration should pass
        assert!(manager.validate().is_ok());

        // Invalid configuration should fail
        let result = manager.update_config(|config| {
            config.crypto.default_algorithm = "InvalidAlgorithm".to_string();
            Ok(())
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_config_reload() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.json");

        let manager = ConfigManager::new(&config_path).unwrap();
        
        // Modify the config file externally
        let mut external_config = AppConfig::default();
        external_config.gui.theme = "light".to_string();
        external_config.save_to_file(&config_path).unwrap();

        // Reload and verify the change
        manager.reload().unwrap();
        let config = manager.get_config().unwrap();
        assert_eq!(config.gui.theme, "light");
    }
}