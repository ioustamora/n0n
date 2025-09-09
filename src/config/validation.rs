use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use thiserror::Error;
use regex::Regex;

use crate::config::profiles::ConfigurationProfile;
use crate::config::environment::EnvironmentConfig;
use crate::storage::backend::{StorageConfig, StorageType};

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Validation failed: {message}")]
    ValidationFailed { message: String },
    
    #[error("Invalid value for {field}: {value}")]
    InvalidValue { field: String, value: String },
    
    #[error("Missing required field: {field}")]
    MissingRequired { field: String },
    
    #[error("Schema validation failed: {errors:?}")]
    SchemaValidation { errors: Vec<String> },
    
    #[error("Cross-validation failed: {message}")]
    CrossValidation { message: String },
}

/// Validation result with warnings and errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            recommendations: Vec::new(),
        }
    }
    
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
        self.is_valid = false;
    }
    
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
    
    pub fn add_recommendation(&mut self, recommendation: String) {
        self.recommendations.push(recommendation);
    }
    
    pub fn merge(&mut self, other: ValidationResult) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
        self.recommendations.extend(other.recommendations);
        if !other.is_valid {
            self.is_valid = false;
        }
    }
}

/// Field validation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRule {
    pub field_name: String,
    pub field_type: FieldType,
    pub required: bool,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
    pub allowed_values: Option<Vec<String>>,
    pub custom_validator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldType {
    String,
    Integer,
    Float,
    Boolean,
    Url,
    Path,
    Email,
    Json,
    Regex,
}

/// Configuration schema for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSchema {
    pub name: String,
    pub version: String,
    pub description: String,
    pub fields: Vec<FieldRule>,
    pub cross_validations: Vec<CrossValidationRule>,
}

/// Cross-validation rules between fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossValidationRule {
    pub name: String,
    pub condition: String, // Simple condition like "field1 > field2"
    pub error_message: String,
}

/// Main configuration validator
pub struct ConfigValidator {
    schemas: HashMap<String, ConfigSchema>,
    custom_validators: HashMap<String, Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>>,
}

impl ConfigValidator {
    pub fn new() -> Self {
        let mut validator = Self {
            schemas: HashMap::new(),
            custom_validators: HashMap::new(),
        };
        
        // Register default schemas
        validator.register_default_schemas();
        validator.register_default_validators();
        
        validator
    }
    
    /// Register default validation schemas
    fn register_default_schemas(&mut self) {
        // Profile schema
        let profile_schema = ConfigSchema {
            name: "configuration_profile".to_string(),
            version: "1.0".to_string(),
            description: "Schema for configuration profiles".to_string(),
            fields: vec![
                FieldRule {
                    field_name: "name".to_string(),
                    field_type: FieldType::String,
                    required: true,
                    min_length: Some(1),
                    max_length: Some(50),
                    pattern: Some(r"^[a-zA-Z0-9_\-]+$".to_string()),
                    ..Default::default()
                },
                FieldRule {
                    field_name: "chunk_size_mb".to_string(),
                    field_type: FieldType::Integer,
                    required: true,
                    min_value: Some(1.0),
                    max_value: Some(1000.0),
                    ..Default::default()
                },
                FieldRule {
                    field_name: "default_output_dir".to_string(),
                    field_type: FieldType::Path,
                    required: true,
                    min_length: Some(1),
                    ..Default::default()
                },
                FieldRule {
                    field_name: "watcher_debounce_ms".to_string(),
                    field_type: FieldType::Integer,
                    required: false,
                    min_value: Some(100.0),
                    max_value: Some(10000.0),
                    ..Default::default()
                },
            ],
            cross_validations: vec![],
        };
        
        // Storage schema
        let storage_schema = ConfigSchema {
            name: "storage_config".to_string(),
            version: "1.0".to_string(),
            description: "Schema for storage configurations".to_string(),
            fields: vec![
                FieldRule {
                    field_name: "backend_type".to_string(),
                    field_type: FieldType::String,
                    required: true,
                    allowed_values: Some(vec![
                        "Local".to_string(),
                        "Sftp".to_string(), 
                        "S3Compatible".to_string(),
                        "GoogleCloud".to_string(),
                        "AzureBlob".to_string(),
                        "PostgreSQL".to_string(),
                        "Redis".to_string(),
                        "WebDav".to_string(),
                        "Ipfs".to_string(),
                        "MultiCloud".to_string(),
                        "CachedCloud".to_string(),
                    ]),
                    ..Default::default()
                },
            ],
            cross_validations: vec![],
        };
        
        // Environment schema
        let environment_schema = ConfigSchema {
            name: "environment_config".to_string(),
            version: "1.0".to_string(),
            description: "Schema for environment configurations".to_string(),
            fields: vec![
                FieldRule {
                    field_name: "name".to_string(),
                    field_type: FieldType::String,
                    required: true,
                    min_length: Some(1),
                    max_length: Some(30),
                    pattern: Some(r"^[a-zA-Z0-9_\-]+$".to_string()),
                    ..Default::default()
                },
                FieldRule {
                    field_name: "log_level".to_string(),
                    field_type: FieldType::String,
                    required: true,
                    allowed_values: Some(vec![
                        "trace".to_string(),
                        "debug".to_string(),
                        "info".to_string(),
                        "warn".to_string(),
                        "error".to_string(),
                    ]),
                    ..Default::default()
                },
                FieldRule {
                    field_name: "max_concurrent_operations".to_string(),
                    field_type: FieldType::Integer,
                    required: true,
                    min_value: Some(1.0),
                    max_value: Some(1000.0),
                    ..Default::default()
                },
                FieldRule {
                    field_name: "session_timeout_minutes".to_string(),
                    field_type: FieldType::Integer,
                    required: true,
                    min_value: Some(5.0),
                    max_value: Some(1440.0), // 24 hours max
                    ..Default::default()
                },
            ],
            cross_validations: vec![
                CrossValidationRule {
                    name: "production_security".to_string(),
                    condition: "environment == 'production' && !require_encryption".to_string(),
                    error_message: "Production environments must require encryption".to_string(),
                },
            ],
        };
        
        self.schemas.insert("configuration_profile".to_string(), profile_schema);
        self.schemas.insert("storage_config".to_string(), storage_schema);
        self.schemas.insert("environment_config".to_string(), environment_schema);
    }
    
    /// Register default custom validators
    fn register_default_validators(&mut self) {
        // URL validator
        self.register_validator("url".to_string(), Box::new(|value: &str| {
            url::Url::parse(value)
                .map(|_| ())
                .map_err(|e| format!("Invalid URL: {}", e))
        }));
        
        // Path validator
        self.register_validator("path".to_string(), Box::new(|value: &str| {
            if value.is_empty() {
                return Err("Path cannot be empty".to_string());
            }
            
            // Basic path validation
            if value.contains('\0') {
                return Err("Path cannot contain null bytes".to_string());
            }
            
            Ok(())
        }));
        
        // JSON validator
        self.register_validator("json".to_string(), Box::new(|value: &str| {
            serde_json::from_str::<serde_json::Value>(value)
                .map(|_| ())
                .map_err(|e| format!("Invalid JSON: {}", e))
        }));
        
        // Regex validator
        self.register_validator("regex".to_string(), Box::new(|value: &str| {
            Regex::new(value)
                .map(|_| ())
                .map_err(|e| format!("Invalid regex: {}", e))
        }));
    }
    
    /// Register a custom validator
    pub fn register_validator<F>(&mut self, name: String, validator: F)
    where
        F: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
    {
        self.custom_validators.insert(name, Box::new(validator));
    }
    
    /// Register a schema
    pub fn register_schema(&mut self, schema: ConfigSchema) {
        self.schemas.insert(schema.name.clone(), schema);
    }
    
    /// Validate a configuration profile
    pub fn validate_profile(&self, profile: &ConfigurationProfile) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        // Basic validation
        if let Some(schema) = self.schemas.get("configuration_profile") {
            result.merge(self.validate_against_schema(&serde_json::to_value(profile).unwrap(), schema));
        }
        
        // Profile-specific validations
        self.validate_profile_specific(profile, &mut result);
        
        // Storage config validation
        result.merge(self.validate_storage_config(&profile.storage_config));
        
        // Environment overrides validation
        for (env_name, override_config) in &profile.environment_overrides {
            if let Some(storage_config) = &override_config.storage_config {
                let mut env_result = self.validate_storage_config(storage_config);
                for error in &mut env_result.errors {
                    *error = format!("Environment '{}': {}", env_name, error);
                }
                result.merge(env_result);
            }
        }
        
        result
    }
    
    /// Validate against a schema
    fn validate_against_schema(&self, value: &serde_json::Value, schema: &ConfigSchema) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        for field_rule in &schema.fields {
            self.validate_field(value, field_rule, &mut result);
        }
        
        // Cross validations would go here
        for cross_validation in &schema.cross_validations {
            self.validate_cross_rule(value, cross_validation, &mut result);
        }
        
        result
    }
    
    /// Validate a single field
    fn validate_field(&self, value: &serde_json::Value, rule: &FieldRule, result: &mut ValidationResult) {
        let field_value = value.get(&rule.field_name);
        
        // Check if required field is present
        if rule.required && (field_value.is_none() || field_value.unwrap().is_null()) {
            result.add_error(format!("Missing required field: {}", rule.field_name));
            return;
        }
        
        // If field is not present and not required, skip validation
        if field_value.is_none() {
            return;
        }
        
        let field_value = field_value.unwrap();
        
        // Type validation
        match &rule.field_type {
            FieldType::String => {
                if let Some(s) = field_value.as_str() {
                    self.validate_string_field(s, rule, result);
                } else {
                    result.add_error(format!("Field '{}' must be a string", rule.field_name));
                }
            }
            FieldType::Integer => {
                if let Some(i) = field_value.as_i64() {
                    self.validate_numeric_field(i as f64, rule, result);
                } else {
                    result.add_error(format!("Field '{}' must be an integer", rule.field_name));
                }
            }
            FieldType::Float => {
                if let Some(f) = field_value.as_f64() {
                    self.validate_numeric_field(f, rule, result);
                } else {
                    result.add_error(format!("Field '{}' must be a number", rule.field_name));
                }
            }
            FieldType::Boolean => {
                if !field_value.is_boolean() {
                    result.add_error(format!("Field '{}' must be a boolean", rule.field_name));
                }
            }
            FieldType::Url => {
                if let Some(s) = field_value.as_str() {
                    if let Some(validator) = self.custom_validators.get("url") {
                        if let Err(e) = validator(s) {
                            result.add_error(format!("Field '{}': {}", rule.field_name, e));
                        }
                    }
                }
            }
            FieldType::Path => {
                if let Some(s) = field_value.as_str() {
                    if let Some(validator) = self.custom_validators.get("path") {
                        if let Err(e) = validator(s) {
                            result.add_error(format!("Field '{}': {}", rule.field_name, e));
                        }
                    }
                }
            }
            FieldType::Email => {
                if let Some(s) = field_value.as_str() {
                    if !s.contains('@') || !s.contains('.') {
                        result.add_error(format!("Field '{}' must be a valid email", rule.field_name));
                    }
                }
            }
            FieldType::Json => {
                if let Some(s) = field_value.as_str() {
                    if let Some(validator) = self.custom_validators.get("json") {
                        if let Err(e) = validator(s) {
                            result.add_error(format!("Field '{}': {}", rule.field_name, e));
                        }
                    }
                }
            }
            FieldType::Regex => {
                if let Some(s) = field_value.as_str() {
                    if let Some(validator) = self.custom_validators.get("regex") {
                        if let Err(e) = validator(s) {
                            result.add_error(format!("Field '{}': {}", rule.field_name, e));
                        }
                    }
                }
            }
        }
    }
    
    /// Validate string field constraints
    fn validate_string_field(&self, value: &str, rule: &FieldRule, result: &mut ValidationResult) {
        // Length validation
        if let Some(min_len) = rule.min_length {
            if value.len() < min_len {
                result.add_error(format!("Field '{}' must be at least {} characters", rule.field_name, min_len));
            }
        }
        
        if let Some(max_len) = rule.max_length {
            if value.len() > max_len {
                result.add_error(format!("Field '{}' must be at most {} characters", rule.field_name, max_len));
            }
        }
        
        // Pattern validation
        if let Some(pattern) = &rule.pattern {
            if let Ok(regex) = Regex::new(pattern) {
                if !regex.is_match(value) {
                    result.add_error(format!("Field '{}' does not match required pattern", rule.field_name));
                }
            }
        }
        
        // Allowed values validation
        if let Some(allowed) = &rule.allowed_values {
            if !allowed.contains(&value.to_string()) {
                result.add_error(format!("Field '{}' must be one of: {:?}", rule.field_name, allowed));
            }
        }
        
        // Custom validation
        if let Some(validator_name) = &rule.custom_validator {
            if let Some(validator) = self.custom_validators.get(validator_name) {
                if let Err(e) = validator(value) {
                    result.add_error(format!("Field '{}': {}", rule.field_name, e));
                }
            }
        }
    }
    
    /// Validate numeric field constraints
    fn validate_numeric_field(&self, value: f64, rule: &FieldRule, result: &mut ValidationResult) {
        if let Some(min_val) = rule.min_value {
            if value < min_val {
                result.add_error(format!("Field '{}' must be at least {}", rule.field_name, min_val));
            }
        }
        
        if let Some(max_val) = rule.max_value {
            if value > max_val {
                result.add_error(format!("Field '{}' must be at most {}", rule.field_name, max_val));
            }
        }
    }
    
    /// Validate cross-field rules
    fn validate_cross_rule(&self, _value: &serde_json::Value, _rule: &CrossValidationRule, _result: &mut ValidationResult) {
        // Simplified cross-validation - in a real implementation, 
        // you'd parse and evaluate the condition string
        // For now, just placeholder
    }
    
    /// Profile-specific validation logic
    fn validate_profile_specific(&self, profile: &ConfigurationProfile, result: &mut ValidationResult) {
        // Check for reasonable defaults
        if profile.chunk_size_mb > 100 {
            result.add_warning(format!("Large chunk size ({} MB) may impact performance", profile.chunk_size_mb));
        }
        
        if profile.watcher_debounce_ms < 500 {
            result.add_warning("Low debounce time may cause excessive file system events".to_string());
        }
        
        // Security recommendations
        if profile.encryption_config.is_none() {
            result.add_recommendation("Consider enabling encryption for sensitive data".to_string());
        }
        
        if profile.quota_config.is_none() {
            result.add_recommendation("Consider setting up quotas to prevent resource exhaustion".to_string());
        }
        
        // Validate tags
        for tag in &profile.tags {
            if tag.len() > 20 {
                result.add_warning(format!("Tag '{}' is very long", tag));
            }
        }
    }
    
    /// Validate storage configuration
    pub fn validate_storage_config(&self, config: &StorageConfig) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        // Validate based on backend type
        match config.backend_type {
            StorageType::Local => {
                if let Some(local_config) = &config.local {
                    if local_config.base_path.is_empty() {
                        result.add_error("Local storage base path cannot be empty".to_string());
                    }
                } else {
                    result.add_error("Local storage config is required for Local backend".to_string());
                }
            }
            StorageType::Sftp => {
                if let Some(sftp_config) = &config.sftp {
                    if sftp_config.host.is_empty() {
                        result.add_error("SFTP host cannot be empty".to_string());
                    }
                    if sftp_config.username.is_empty() {
                        result.add_error("SFTP username cannot be empty".to_string());
                    }
                } else {
                    result.add_error("SFTP config is required for SFTP backend".to_string());
                }
            }
            StorageType::S3Compatible => {
                if let Some(s3_config) = &config.s3 {
                    if s3_config.bucket.is_empty() {
                        result.add_error("S3 bucket name cannot be empty".to_string());
                    }
                    if s3_config.region.is_empty() {
                        result.add_error("S3 region cannot be empty".to_string());
                    }
                } else {
                    result.add_error("S3 config is required for S3Compatible backend".to_string());
                }
            }
            _ => {
                // Add validation for other backend types as needed
            }
        }
        
        result
    }
    
    /// Validate environment configuration
    pub fn validate_environment(&self, config: &EnvironmentConfig) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        if let Some(schema) = self.schemas.get("environment_config") {
            result.merge(self.validate_against_schema(&serde_json::to_value(config).unwrap(), schema));
        }
        
        // Environment-specific validations
        self.validate_environment_specific(config, &mut result);
        
        result
    }
    
    /// Environment-specific validation logic
    fn validate_environment_specific(&self, config: &EnvironmentConfig, result: &mut ValidationResult) {
        use crate::config::environment::{Environment, SecurityLevel};
        
        // Production environment checks
        if matches!(config.environment, Environment::Production) {
            if !config.require_encryption {
                result.add_error("Production environment must require encryption".to_string());
            }
            
            if config.allow_dangerous_operations {
                result.add_error("Production environment should not allow dangerous operations".to_string());
            }
            
            if config.log_level == "debug" {
                result.add_warning("Debug logging not recommended for production".to_string());
            }
            
            if config.session_timeout_minutes > 120 {
                result.add_warning("Long session timeout not recommended for production".to_string());
            }
        }
        
        // Development environment recommendations
        if matches!(config.environment, Environment::Development) {
            if config.require_encryption {
                result.add_recommendation("Consider disabling encryption for faster development".to_string());
            }
            
            if matches!(config.security_level, SecurityLevel::High) {
                result.add_recommendation("Consider using lower security level for development".to_string());
            }
        }
        
        // Resource limit validations
        if let Some(max_memory) = config.max_memory_mb {
            if max_memory < 512 {
                result.add_warning("Low memory limit may cause performance issues".to_string());
            }
        }
        
        // Feature flag consistency
        if config.enable_tracing && !config.enable_metrics {
            result.add_warning("Tracing is enabled but metrics are disabled - consider enabling metrics".to_string());
        }
    }
}

impl Default for FieldRule {
    fn default() -> Self {
        Self {
            field_name: String::new(),
            field_type: FieldType::String,
            required: false,
            min_value: None,
            max_value: None,
            min_length: None,
            max_length: None,
            pattern: None,
            allowed_values: None,
            custom_validator: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::backend::StorageType;
    
    #[test]
    fn test_field_validation() {
        let validator = ConfigValidator::new();
        let mut result = ValidationResult::new();
        
        let rule = FieldRule {
            field_name: "test_field".to_string(),
            field_type: FieldType::String,
            required: true,
            min_length: Some(3),
            max_length: Some(10),
            ..Default::default()
        };
        
        // Test missing required field
        let value = serde_json::json!({});
        validator.validate_field(&value, &rule, &mut result);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("Missing required field")));
        
        // Test valid field
        let mut result = ValidationResult::new();
        let value = serde_json::json!({"test_field": "valid"});
        validator.validate_field(&value, &rule, &mut result);
        assert!(result.is_valid);
        
        // Test invalid length
        let mut result = ValidationResult::new();
        let value = serde_json::json!({"test_field": "x"});
        validator.validate_field(&value, &rule, &mut result);
        assert!(!result.is_valid);
    }
    
    #[test]
    fn test_storage_config_validation() {
        let validator = ConfigValidator::new();
        
        // Test local config
        let mut config = StorageConfig::default();
        config.backend_type = StorageType::Local;
        
        let result = validator.validate_storage_config(&config);
        assert!(!result.is_valid); // Should fail because local config is missing
        
        // Test with proper local config
        config.local = Some(crate::storage::backend::LocalConfig {
            base_path: "/tmp/test".to_string(),
            create_dirs: Some(true),
        });
        
        let result = validator.validate_storage_config(&config);
        assert!(result.is_valid);
    }
}