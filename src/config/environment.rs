use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnvironmentError {
    #[error("Environment not found: {name}")]
    EnvironmentNotFound { name: String },
    
    #[error("Environment already exists: {name}")]
    EnvironmentAlreadyExists { name: String },
    
    #[error("Invalid environment name: {name}")]
    InvalidEnvironmentName { name: String },
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Represents different deployment environments
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Environment {
    Development,
    Testing,
    Staging,
    Production,
    Custom(String),
}

impl Environment {
    pub fn as_str(&self) -> &str {
        match self {
            Environment::Development => "development",
            Environment::Testing => "testing", 
            Environment::Staging => "staging",
            Environment::Production => "production",
            Environment::Custom(name) => name,
        }
    }
    
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Environment::Development,
            "testing" | "test" => Environment::Testing,
            "staging" | "stage" => Environment::Staging,
            "production" | "prod" => Environment::Production,
            name => Environment::Custom(name.to_string()),
        }
    }
    
    /// Get default security level for this environment
    pub fn default_security_level(&self) -> SecurityLevel {
        match self {
            Environment::Development => SecurityLevel::Low,
            Environment::Testing => SecurityLevel::Medium,
            Environment::Staging => SecurityLevel::High,
            Environment::Production => SecurityLevel::High,
            Environment::Custom(_) => SecurityLevel::Medium,
        }
    }
    
    /// Check if this environment allows dangerous operations
    pub fn allows_dangerous_operations(&self) -> bool {
        matches!(self, Environment::Development | Environment::Testing)
    }
}

/// Security levels for different environments
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityLevel {
    Low,    // Development - relaxed security
    Medium, // Testing/Custom - balanced security 
    High,   // Staging/Production - strict security
}

/// Environment-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    pub name: String,
    pub environment: Environment,
    pub description: String,
    pub security_level: SecurityLevel,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    
    // Environment variables
    pub environment_variables: HashMap<String, String>,
    
    // Feature flags
    pub feature_flags: HashMap<String, bool>,
    
    // Logging configuration
    pub log_level: String,
    pub log_format: String,
    pub enable_metrics: bool,
    pub enable_tracing: bool,
    
    // Security settings
    pub require_encryption: bool,
    pub enforce_quotas: bool,
    pub allow_dangerous_operations: bool,
    pub max_concurrent_operations: u32,
    pub session_timeout_minutes: u32,
    
    // Performance tuning
    pub chunk_size_mb: Option<u32>,
    pub connection_pool_size: Option<u32>,
    pub cache_ttl_seconds: Option<u32>,
    pub retry_attempts: Option<u32>,
    pub timeout_seconds: Option<u32>,
    
    // Resource limits
    pub max_memory_mb: Option<u64>,
    pub max_disk_space_mb: Option<u64>,
    pub max_network_bandwidth_mbps: Option<u32>,
    
    // Custom metadata
    pub metadata: HashMap<String, String>,
}

impl EnvironmentConfig {
    /// Create a new environment configuration
    pub fn new(name: String, environment: Environment, description: String) -> Self {
        let security_level = environment.default_security_level();
        let allow_dangerous_ops = environment.allows_dangerous_operations();
        
        Self {
            name: name.clone(),
            environment,
            description,
            security_level: security_level.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            environment_variables: HashMap::new(),
            feature_flags: HashMap::new(),
            log_level: match security_level {
                SecurityLevel::Low => "debug".to_string(),
                SecurityLevel::Medium => "info".to_string(),
                SecurityLevel::High => "warn".to_string(),
            },
            log_format: "json".to_string(),
            enable_metrics: true,
            enable_tracing: matches!(security_level, SecurityLevel::High),
            require_encryption: !matches!(security_level, SecurityLevel::Low),
            enforce_quotas: matches!(security_level, SecurityLevel::High),
            allow_dangerous_operations: allow_dangerous_ops,
            max_concurrent_operations: match security_level {
                SecurityLevel::Low => 100,
                SecurityLevel::Medium => 50,
                SecurityLevel::High => 25,
            },
            session_timeout_minutes: match security_level {
                SecurityLevel::Low => 480, // 8 hours
                SecurityLevel::Medium => 120, // 2 hours
                SecurityLevel::High => 60,  // 1 hour
            },
            chunk_size_mb: None,
            connection_pool_size: None,
            cache_ttl_seconds: None,
            retry_attempts: None,
            timeout_seconds: None,
            max_memory_mb: None,
            max_disk_space_mb: None,
            max_network_bandwidth_mbps: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Update the last modified timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
    
    /// Set an environment variable
    pub fn set_env_var(&mut self, key: String, value: String) {
        self.environment_variables.insert(key, value);
        self.touch();
    }
    
    /// Get an environment variable
    pub fn get_env_var(&self, key: &str) -> Option<&String> {
        self.environment_variables.get(key)
    }
    
    /// Set a feature flag
    pub fn set_feature_flag(&mut self, flag: String, enabled: bool) {
        self.feature_flags.insert(flag, enabled);
        self.touch();
    }
    
    /// Check if a feature is enabled
    pub fn is_feature_enabled(&self, flag: &str) -> bool {
        self.feature_flags.get(flag).copied().unwrap_or(false)
    }
    
    /// Validate the environment configuration
    pub fn validate(&self) -> Result<(), EnvironmentError> {
        if self.name.is_empty() {
            return Err(EnvironmentError::InvalidEnvironmentName { 
                name: self.name.clone() 
            });
        }
        
        // Validate log level
        let valid_log_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&self.log_level.as_str()) {
            return Err(EnvironmentError::InvalidEnvironmentName { 
                name: format!("Invalid log level: {}", self.log_level) 
            });
        }
        
        // Validate limits
        if self.max_concurrent_operations == 0 {
            return Err(EnvironmentError::InvalidEnvironmentName { 
                name: "Max concurrent operations cannot be zero".to_string() 
            });
        }
        
        Ok(())
    }
}

/// Manages environment configurations
pub struct EnvironmentManager {
    environments: HashMap<String, EnvironmentConfig>,
    environments_dir: PathBuf,
    current_environment: String,
}

impl EnvironmentManager {
    /// Create a new environment manager
    pub fn new<P: AsRef<Path>>(environments_dir: P) -> Result<Self, EnvironmentError> {
        let environments_dir = environments_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&environments_dir)?;
        
        let mut manager = Self {
            environments: HashMap::new(),
            environments_dir,
            current_environment: "development".to_string(),
        };
        
        // Load existing environments
        manager.load_all_environments()?;
        
        // Create default environments if none exist
        if manager.environments.is_empty() {
            manager.create_default_environments()?;
        }
        
        Ok(manager)
    }
    
    /// Create default environments
    fn create_default_environments(&mut self) -> Result<(), EnvironmentError> {
        let default_envs = vec![
            ("development", Environment::Development, "Development environment"),
            ("testing", Environment::Testing, "Testing environment"),
            ("staging", Environment::Staging, "Staging environment"), 
            ("production", Environment::Production, "Production environment"),
        ];
        
        for (name, env_type, desc) in default_envs {
            let config = EnvironmentConfig::new(
                name.to_string(),
                env_type,
                desc.to_string()
            );
            self.save_environment(config)?;
        }
        
        Ok(())
    }
    
    /// Load all environments from disk
    pub fn load_all_environments(&mut self) -> Result<(), EnvironmentError> {
        self.environments.clear();
        
        for entry in std::fs::read_dir(&self.environments_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    match self.load_environment_from_file(&path) {
                        Ok(config) => {
                            self.environments.insert(stem.to_string(), config);
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to load environment {}: {}", stem, e);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Load an environment from file
    fn load_environment_from_file(&self, path: &Path) -> Result<EnvironmentConfig, EnvironmentError> {
        let content = std::fs::read_to_string(path)?;
        let config: EnvironmentConfig = serde_json::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }
    
    /// Save an environment to disk
    pub fn save_environment(&mut self, mut config: EnvironmentConfig) -> Result<(), EnvironmentError> {
        config.validate()?;
        config.touch();
        
        let file_path = self.environments_dir.join(format!("{}.json", config.name));
        let content = serde_json::to_string_pretty(&config)?;
        std::fs::write(&file_path, content)?;
        
        self.environments.insert(config.name.clone(), config);
        Ok(())
    }
    
    /// Create a new environment
    pub fn create_environment(&mut self, name: String, environment: Environment, description: String) -> Result<(), EnvironmentError> {
        if self.environments.contains_key(&name) {
            return Err(EnvironmentError::EnvironmentAlreadyExists { name });
        }
        
        let config = EnvironmentConfig::new(name, environment, description);
        self.save_environment(config)?;
        Ok(())
    }
    
    /// Delete an environment
    pub fn delete_environment(&mut self, name: &str) -> Result<(), EnvironmentError> {
        if !self.environments.contains_key(name) {
            return Err(EnvironmentError::EnvironmentNotFound { 
                name: name.to_string() 
            });
        }
        
        // Don't allow deleting the current environment
        if self.current_environment == name {
            return Err(EnvironmentError::InvalidEnvironmentName { 
                name: "Cannot delete current environment".to_string() 
            });
        }
        
        // Remove from disk
        let file_path = self.environments_dir.join(format!("{}.json", name));
        if file_path.exists() {
            std::fs::remove_file(file_path)?;
        }
        
        // Remove from memory
        self.environments.remove(name);
        Ok(())
    }
    
    /// Get an environment by name
    pub fn get_environment(&self, name: &str) -> Result<&EnvironmentConfig, EnvironmentError> {
        self.environments.get(name).ok_or(EnvironmentError::EnvironmentNotFound { 
            name: name.to_string() 
        })
    }
    
    /// Get a mutable reference to an environment
    pub fn get_environment_mut(&mut self, name: &str) -> Result<&mut EnvironmentConfig, EnvironmentError> {
        self.environments.get_mut(name).ok_or(EnvironmentError::EnvironmentNotFound { 
            name: name.to_string() 
        })
    }
    
    /// List all environment names
    pub fn list_environments(&self) -> Vec<String> {
        self.environments.keys().cloned().collect()
    }
    
    /// List environments with their basic info
    pub fn list_environments_info(&self) -> Vec<(String, Environment, String)> {
        self.environments.iter()
            .map(|(name, config)| (
                name.clone(), 
                config.environment.clone(), 
                config.description.clone()
            ))
            .collect()
    }
    
    /// Set the current environment
    pub fn set_current_environment(&mut self, name: String) -> Result<(), EnvironmentError> {
        if !self.environments.contains_key(&name) {
            return Err(EnvironmentError::EnvironmentNotFound { name });
        }
        
        self.current_environment = name;
        Ok(())
    }
    
    /// Get the current environment
    pub fn get_current_environment(&self) -> Option<&EnvironmentConfig> {
        self.environments.get(&self.current_environment)
    }
    
    /// Get the current environment name
    pub fn get_current_environment_name(&self) -> &str {
        &self.current_environment
    }
    
    /// Clone an environment with a new name
    pub fn clone_environment(&mut self, source: &str, target: String) -> Result<(), EnvironmentError> {
        if self.environments.contains_key(&target) {
            return Err(EnvironmentError::EnvironmentAlreadyExists { name: target });
        }
        
        let source_config = self.get_environment(source)?.clone();
        let mut new_config = source_config;
        new_config.name = target.clone();
        new_config.description = format!("Cloned from {}", source);
        new_config.created_at = Utc::now();
        new_config.updated_at = Utc::now();
        
        self.save_environment(new_config)?;
        Ok(())
    }
    
    /// Apply environment variables to the current process
    pub fn apply_environment_variables(&self, env_name: &str) -> Result<(), EnvironmentError> {
        let config = self.get_environment(env_name)?;
        
        for (key, value) in &config.environment_variables {
            std::env::set_var(key, value);
        }
        
        // Set standard environment variables
        std::env::set_var("N0N_ENVIRONMENT", env_name);
        std::env::set_var("N0N_LOG_LEVEL", &config.log_level);
        std::env::set_var("N0N_SECURITY_LEVEL", format!("{:?}", config.security_level));
        
        Ok(())
    }
    
    /// Get environment-specific recommendations
    pub fn get_recommendations(&self, env_name: &str) -> Result<Vec<String>, EnvironmentError> {
        let config = self.get_environment(env_name)?;
        let mut recommendations = Vec::new();
        
        match config.environment {
            Environment::Production => {
                if !config.require_encryption {
                    recommendations.push("Enable encryption for production environment".to_string());
                }
                if !config.enforce_quotas {
                    recommendations.push("Enable quota enforcement for production environment".to_string());
                }
                if config.log_level == "debug" {
                    recommendations.push("Use 'info' or 'warn' log level for production".to_string());
                }
            }
            Environment::Development => {
                if config.require_encryption {
                    recommendations.push("Consider disabling encryption for faster development".to_string());
                }
            }
            _ => {}
        }
        
        if config.max_concurrent_operations > 100 {
            recommendations.push("High concurrent operation limit may impact performance".to_string());
        }
        
        Ok(recommendations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_environment_creation() {
        let config = EnvironmentConfig::new(
            "test".to_string(),
            Environment::Development,
            "Test environment".to_string()
        );
        
        assert_eq!(config.name, "test");
        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.security_level, SecurityLevel::Low);
        assert!(config.allow_dangerous_operations);
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_environment_from_string() {
        assert_eq!(Environment::from_str("development"), Environment::Development);
        assert_eq!(Environment::from_str("dev"), Environment::Development);
        assert_eq!(Environment::from_str("production"), Environment::Production);
        assert_eq!(Environment::from_str("prod"), Environment::Production);
        assert_eq!(Environment::from_str("custom"), Environment::Custom("custom".to_string()));
    }
    
    #[test]
    fn test_environment_manager() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let mut manager = EnvironmentManager::new(temp_dir.path())?;
        
        // Should have default environments
        assert!(manager.list_environments().len() >= 4);
        assert!(manager.list_environments().contains(&"development".to_string()));
        assert!(manager.list_environments().contains(&"production".to_string()));
        
        // Create custom environment
        manager.create_environment(
            "custom".to_string(),
            Environment::Custom("custom".to_string()),
            "Custom environment".to_string()
        )?;
        assert!(manager.list_environments().contains(&"custom".to_string()));
        
        // Set current environment
        manager.set_current_environment("production".to_string())?;
        assert_eq!(manager.get_current_environment_name(), "production");
        
        Ok(())
    }
}