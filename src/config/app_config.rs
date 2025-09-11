use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::Path;
use anyhow::Result;

use crate::storage::backend::{StorageConfig, StorageType};

/// Main application configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppConfig {
    pub storage: StorageConfig,
    pub crypto: CryptoConfig,
    pub gui: GuiConfig,
    pub logging: LoggingConfig,
}

/// Cryptographic configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CryptoConfig {
    /// Default encryption algorithm
    pub default_algorithm: String,
    /// Key derivation function
    pub key_derivation: String,
    /// Enable hardware security module
    pub enable_hsm: bool,
    /// HSM configuration
    pub hsm: Option<HsmSettings>,
}

/// GUI configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GuiConfig {
    /// Theme (light, dark, auto)
    pub theme: String,
    /// UI scale factor
    pub scale_factor: f32,
    /// Enable animations
    pub enable_animations: bool,
    /// Remember window state
    pub remember_window_state: bool,
    /// Default chunk size for UI (MB)
    pub default_chunk_size_mb: u32,
}

/// Logging configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoggingConfig {
    /// Log level (debug, info, warn, error)
    pub level: String,
    /// Log file path (optional, logs to console if None)
    pub file_path: Option<String>,
    /// Enable audit logging
    pub enable_audit: bool,
    /// Maximum log file size (MB)
    pub max_file_size_mb: u64,
    /// Number of log files to keep
    pub max_files: u32,
}

/// HSM settings
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HsmSettings {
    pub provider: String,
    pub endpoint: String,
    pub credentials: HashMap<String, String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            storage: StorageConfig::default(),
            crypto: CryptoConfig::default(),
            gui: GuiConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            default_algorithm: "XSalsa20Poly1305".to_string(),
            key_derivation: "Argon2".to_string(),
            enable_hsm: false,
            hsm: None,
        }
    }
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            theme: "auto".to_string(),
            scale_factor: 1.0,
            enable_animations: true,
            remember_window_state: true,
            default_chunk_size_mb: 64,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_path: None,
            enable_audit: false,
            max_file_size_mb: 10,
            max_files: 5,
        }
    }
}

impl AppConfig {
    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: AppConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Load configuration with environment variable overrides
    pub fn load_with_env_overrides<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut config = if path.as_ref().exists() {
            Self::load_from_file(path)?
        } else {
            Self::default()
        };

        // Apply environment variable overrides
        config.apply_env_overrides();
        Ok(config)
    }

    /// Apply environment variable overrides
    pub fn apply_env_overrides(&mut self) {
        // Storage overrides
        if let Ok(backend_type) = std::env::var("N0N_STORAGE_BACKEND") {
            if let Ok(storage_type) = backend_type.parse::<StorageType>() {
                self.storage.backend_type = storage_type;
            }
        }

        // Crypto overrides
        if let Ok(algorithm) = std::env::var("N0N_CRYPTO_ALGORITHM") {
            self.crypto.default_algorithm = algorithm;
        }

        // Logging overrides
        if let Ok(log_level) = std::env::var("N0N_LOG_LEVEL") {
            self.logging.level = log_level;
        }

        if let Ok(log_file) = std::env::var("N0N_LOG_FILE") {
            self.logging.file_path = Some(log_file);
        }

        // GUI overrides
        if let Ok(theme) = std::env::var("N0N_THEME") {
            self.gui.theme = theme;
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate crypto settings
        let valid_algorithms = ["XSalsa20Poly1305", "ChaCha20Poly1305", "AES256GCM"];
        if !valid_algorithms.contains(&self.crypto.default_algorithm.as_str()) {
            return Err(anyhow::anyhow!("Invalid crypto algorithm: {}", self.crypto.default_algorithm));
        }

        // Validate GUI settings
        if self.gui.scale_factor < 0.5 || self.gui.scale_factor > 3.0 {
            return Err(anyhow::anyhow!("GUI scale factor must be between 0.5 and 3.0"));
        }

        // Validate logging settings
        let valid_log_levels = ["debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&self.logging.level.as_str()) {
            return Err(anyhow::anyhow!("Invalid log level: {}", self.logging.level));
        }

        Ok(())
    }

    /// Generate default configuration file
    pub fn generate_default_config<P: AsRef<Path>>(path: P) -> Result<()> {
        let default_config = Self::default();
        default_config.save_to_file(path)?;
        Ok(())
    }

    /// Migrate configuration from older versions
    pub fn migrate_from_version(&mut self, from_version: &str) -> Result<()> {
        match from_version {
            "0.1.0" => {
                // Example migration: add new default values
                if self.gui.default_chunk_size_mb == 0 {
                    self.gui.default_chunk_size_mb = 64;
                }
            }
            _ => {
                return Err(anyhow::anyhow!("Unknown configuration version: {}", from_version));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.crypto.default_algorithm, "XSalsa20Poly1305");
        assert_eq!(config.gui.theme, "auto");
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_config_serialization() {
        let config = AppConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.crypto.default_algorithm, deserialized.crypto.default_algorithm);
    }

    #[test]
    fn test_config_file_operations() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("test_config.json");

        let config = AppConfig::default();
        config.save_to_file(&config_path).unwrap();

        let loaded_config = AppConfig::load_from_file(&config_path).unwrap();
        assert_eq!(config.crypto.default_algorithm, loaded_config.crypto.default_algorithm);
    }

    #[test]
    fn test_env_override() {
        std::env::set_var("N0N_LOG_LEVEL", "debug");
        std::env::set_var("N0N_THEME", "dark");

        let mut config = AppConfig::default();
        config.apply_env_overrides();

        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.gui.theme, "dark");

        // Clean up
        std::env::remove_var("N0N_LOG_LEVEL");
        std::env::remove_var("N0N_THEME");
    }

    #[test]
    fn test_config_validation() {
        let mut config = AppConfig::default();
        assert!(config.validate().is_ok());

        config.crypto.default_algorithm = "InvalidAlgorithm".to_string();
        assert!(config.validate().is_err());
    }
}