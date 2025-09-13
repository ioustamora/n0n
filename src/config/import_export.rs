use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::io::{Read, Write};
use chrono::{DateTime, Utc};
use thiserror::Error;
use base64::{Engine as _, engine::general_purpose};

use crate::config::profiles::ConfigurationProfile;
use crate::config::environment::EnvironmentConfig;
use crate::config::validation::{ConfigValidator, ValidationResult};

#[derive(Error, Debug)]
pub enum ImportExportError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Format not supported: {format}")]
    UnsupportedFormat { format: String },
    
    #[error("Archive error: {0}")]
    ArchiveError(String),
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    
    #[error("Version mismatch: expected {expected}, found {found}")]
    VersionMismatch { expected: String, found: String },
    
    #[error("ZIP error: {0}")]
    ZipError(#[from] zip::result::ZipError),
}

/// Export format options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Yaml,
    Toml,
    Archive, // ZIP archive with multiple files
    Encrypted, // Encrypted JSON
}

/// Import/Export configuration bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBundle {
    pub metadata: BundleMetadata,
    pub profiles: HashMap<String, ConfigurationProfile>,
    pub environments: HashMap<String, EnvironmentConfig>,
    pub schemas: Option<HashMap<String, serde_json::Value>>,
    pub custom_data: HashMap<String, serde_json::Value>,
}

/// Bundle metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMetadata {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub description: Option<String>,
    pub source_system: Option<String>,
    pub export_format: ExportFormat,
    pub checksum: Option<String>,
    pub encryption_info: Option<EncryptionInfo>,
}

/// Encryption metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub algorithm: String,
    pub key_derivation: String,
    pub salt: String,
    pub iterations: u32,
}

/// Configuration exporter
pub struct ConfigExporter {
    validator: ConfigValidator,
    default_format: ExportFormat,
}

impl ConfigExporter {
    pub fn new() -> Self {
        Self {
            validator: ConfigValidator::new(),
            default_format: ExportFormat::Json,
        }
    }
    
    /// Export configuration bundle to file
    pub fn export_to_file<P: AsRef<Path>>(
        &self,
        bundle: &ConfigBundle,
        path: P,
        format: Option<ExportFormat>,
        password: Option<&str>,
    ) -> Result<(), ImportExportError> {
        let format = format.unwrap_or_else(|| self.default_format.clone());
        let path = path.as_ref();
        
        match format {
            ExportFormat::Json => {
                let json = if let Some(pwd) = password {
                    self.encrypt_bundle(bundle, pwd)?
                } else {
                    serde_json::to_string_pretty(bundle)?
                };
                std::fs::write(path, json)?;
            }
            ExportFormat::Yaml => {
                #[cfg(feature = "yaml")]
                {
                    let yaml = serde_yaml::to_string(bundle)
                        .map_err(|e| ImportExportError::SerializationError(serde_json::Error::custom(e.to_string())))?;
                    std::fs::write(path, yaml)?;
                }
                #[cfg(not(feature = "yaml"))]
                {
                    return Err(ImportExportError::UnsupportedFormat { 
                        format: "YAML".to_string() 
                    });
                }
            }
            ExportFormat::Toml => {
                #[cfg(feature = "toml")]
                {
                    let toml = toml::to_string_pretty(bundle)
                        .map_err(|e| ImportExportError::SerializationError(serde_json::Error::custom(e.to_string())))?;
                    std::fs::write(path, toml)?;
                }
                #[cfg(not(feature = "toml"))]
                {
                    return Err(ImportExportError::UnsupportedFormat { 
                        format: "TOML".to_string() 
                    });
                }
            }
            ExportFormat::Archive => {
                self.export_as_archive(bundle, path)?;
            }
            ExportFormat::Encrypted => {
                if let Some(pwd) = password {
                    let encrypted = self.encrypt_bundle(bundle, pwd)?;
                    std::fs::write(path, encrypted)?;
                } else {
                    return Err(ImportExportError::EncryptionError(
                        "Password required for encrypted export".to_string()
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    /// Export individual profile
    pub fn export_profile<P: AsRef<Path>>(
        &self,
        profile: &ConfigurationProfile,
        path: P,
        format: Option<ExportFormat>,
    ) -> Result<(), ImportExportError> {
        let bundle = ConfigBundle {
            metadata: BundleMetadata {
                version: "1.0.0".to_string(),
                created_at: Utc::now(),
                created_by: None,
                description: Some(format!("Export of profile '{}'", profile.name)),
                source_system: Some("n0n".to_string()),
                export_format: format.clone().unwrap_or_else(|| self.default_format.clone()),
                checksum: None,
                encryption_info: None,
            },
            profiles: {
                let mut profiles = HashMap::new();
                profiles.insert(profile.name.clone(), profile.clone());
                profiles
            },
            environments: HashMap::new(),
            schemas: None,
            custom_data: HashMap::new(),
        };
        
        self.export_to_file(&bundle, path, format, None)
    }
    
    /// Export individual environment
    pub fn export_environment<P: AsRef<Path>>(
        &self,
        environment: &EnvironmentConfig,
        path: P,
        format: Option<ExportFormat>,
    ) -> Result<(), ImportExportError> {
        let bundle = ConfigBundle {
            metadata: BundleMetadata {
                version: "1.0.0".to_string(),
                created_at: Utc::now(),
                created_by: None,
                description: Some(format!("Export of environment '{}'", environment.name)),
                source_system: Some("n0n".to_string()),
                export_format: format.clone().unwrap_or_else(|| self.default_format.clone()),
                checksum: None,
                encryption_info: None,
            },
            profiles: HashMap::new(),
            environments: {
                let mut environments = HashMap::new();
                environments.insert(environment.name.clone(), environment.clone());
                environments
            },
            schemas: None,
            custom_data: HashMap::new(),
        };
        
        self.export_to_file(&bundle, path, format, None)
    }
    
    /// Export as ZIP archive
    fn export_as_archive<P: AsRef<Path>>(
        &self,
        bundle: &ConfigBundle,
        path: P,
    ) -> Result<(), ImportExportError> {
        use std::fs::File;
        use zip::{ZipWriter, write::FileOptions};
        
        let file = File::create(path)?;
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);
        
        // Write metadata
        zip.start_file("metadata.json", options)?;
        zip.write_all(serde_json::to_string_pretty(&bundle.metadata)?.as_bytes())?;
        
        // Write profiles
        if !bundle.profiles.is_empty() {
            zip.add_directory("profiles/", options)?;
            for (name, profile) in &bundle.profiles {
                zip.start_file(&format!("profiles/{}.json", name), options)?;
                zip.write_all(serde_json::to_string_pretty(profile)?.as_bytes())?;
            }
        }
        
        // Write environments
        if !bundle.environments.is_empty() {
            zip.add_directory("environments/", options)?;
            for (name, env) in &bundle.environments {
                zip.start_file(&format!("environments/{}.json", name), options)?;
                zip.write_all(serde_json::to_string_pretty(env)?.as_bytes())?;
            }
        }
        
        // Write schemas if present
        if let Some(schemas) = &bundle.schemas {
            zip.add_directory("schemas/", options)?;
            for (name, schema) in schemas {
                zip.start_file(&format!("schemas/{}.json", name), options)?;
                zip.write_all(serde_json::to_string_pretty(schema)?.as_bytes())?;
            }
        }
        
        // Write custom data if present
        if !bundle.custom_data.is_empty() {
            zip.add_directory("custom/", options)?;
            for (name, data) in &bundle.custom_data {
                zip.start_file(&format!("custom/{}.json", name), options)?;
                zip.write_all(serde_json::to_string_pretty(data)?.as_bytes())?;
            }
        }
        
        zip.finish()?;
        Ok(())
    }
    
    /// Encrypt configuration bundle
    fn encrypt_bundle(&self, bundle: &ConfigBundle, password: &str) -> Result<String, ImportExportError> {
        use sodiumoxide::crypto::pwhash;
        use sodiumoxide::crypto::secretbox;
        
        if sodiumoxide::init().is_err() {
            return Err(ImportExportError::EncryptionError(
                "Failed to initialize crypto library".to_string()
            ));
        }
        
        // Serialize bundle
        let json = serde_json::to_string(bundle)?;
        
        // Generate salt
        let salt = pwhash::gen_salt();
        
        // Derive key from password
        let mut key = secretbox::Key([0; 32]);
        pwhash::derive_key(
            &mut key.0,
            password.as_bytes(),
            &salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        ).map_err(|_| ImportExportError::EncryptionError("Key derivation failed".to_string()))?;
        
        // Generate nonce and encrypt
        let nonce = secretbox::gen_nonce();
        let ciphertext = secretbox::seal(json.as_bytes(), &nonce, &key);
        
        // Create encrypted bundle
        let encrypted_bundle = EncryptedBundle {
            version: "1.0.0".to_string(),
            algorithm: "XSalsa20Poly1305".to_string(),
            salt: general_purpose::STANDARD.encode(&salt.0),
            nonce: general_purpose::STANDARD.encode(&nonce.0),
            ciphertext: general_purpose::STANDARD.encode(&ciphertext),
            iterations: pwhash::OPSLIMIT_INTERACTIVE.0 as u32,
        };
        
        Ok(serde_json::to_string_pretty(&encrypted_bundle)?)
    }
}

/// Encrypted bundle structure
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedBundle {
    version: String,
    algorithm: String,
    salt: String,
    nonce: String,
    ciphertext: String,
    iterations: u32,
}

/// Configuration importer
pub struct ConfigImporter {
    validator: ConfigValidator,
    strict_validation: bool,
}

impl ConfigImporter {
    pub fn new() -> Self {
        Self {
            validator: ConfigValidator::new(),
            strict_validation: true,
        }
    }
    
    pub fn with_validation(mut self, strict: bool) -> Self {
        self.strict_validation = strict;
        self
    }
    
    /// Import configuration bundle from file
    pub fn import_from_file<P: AsRef<Path>>(
        &self,
        path: P,
        password: Option<&str>,
    ) -> Result<(ConfigBundle, ValidationResult), ImportExportError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        
        // Detect format based on file extension or content
        let format = self.detect_format(path, &content)?;
        
        let bundle = match format {
            ExportFormat::Json => {
                if self.is_encrypted(&content) {
                    if let Some(pwd) = password {
                        self.decrypt_bundle(&content, pwd)?
                    } else {
                        return Err(ImportExportError::EncryptionError(
                            "Password required for encrypted file".to_string()
                        ));
                    }
                } else {
                    serde_json::from_str(&content)?
                }
            }
            ExportFormat::Archive => {
                self.import_from_archive(path)?
            }
            _ => {
                return Err(ImportExportError::UnsupportedFormat { 
                    format: format!("{:?}", format) 
                });
            }
        };
        
        // Validate the imported bundle
        let validation_result = self.validate_bundle(&bundle);
        
        if self.strict_validation && !validation_result.is_valid {
            return Err(ImportExportError::ValidationError(
                format!("Bundle validation failed: {:?}", validation_result.errors)
            ));
        }
        
        Ok((bundle, validation_result))
    }
    
    /// Import from ZIP archive
    fn import_from_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<ConfigBundle, ImportExportError> {
        use std::fs::File;
        use zip::ZipArchive;
        
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| ImportExportError::ArchiveError(e.to_string()))?;
        
        // Read metadata
        let metadata_content = {
            let mut metadata_file = archive.by_name("metadata.json")
                .map_err(|e| ImportExportError::ArchiveError(format!("Missing metadata: {}", e)))?;
            let mut content = String::new();
            metadata_file.read_to_string(&mut content)?;
            content
        };
        let metadata: BundleMetadata = serde_json::from_str(&metadata_content)?;
        
        // Collect all files in one pass to avoid multiple borrows
        let mut profiles = HashMap::new();
        let mut environments = HashMap::new();
        let mut schemas = HashMap::new();
        let mut custom_data = HashMap::new();
        
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)
                .map_err(|e| ImportExportError::ArchiveError(e.to_string()))?;
            let name = file.name().to_string();
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            
            if name.starts_with("profiles/") && name.ends_with(".json") {
                let profile: ConfigurationProfile = serde_json::from_str(&content)?;
                profiles.insert(profile.name.clone(), profile);
            } else if name.starts_with("environments/") && name.ends_with(".json") {
                let env: EnvironmentConfig = serde_json::from_str(&content)?;
                environments.insert(env.name.clone(), env);
            } else if name.starts_with("schemas/") && name.ends_with(".json") {
                let schema: serde_json::Value = serde_json::from_str(&content)?;
                let schema_name = name.trim_start_matches("schemas/")
                    .trim_end_matches(".json");
                schemas.insert(schema_name.to_string(), schema);
            } else if name.starts_with("custom/") && name.ends_with(".json") {
                let data: serde_json::Value = serde_json::from_str(&content)?;
                let data_name = name.trim_start_matches("custom/")
                    .trim_end_matches(".json");
                custom_data.insert(data_name.to_string(), data);
            }
        }
        
        Ok(ConfigBundle {
            metadata,
            profiles,
            environments,
            schemas: if schemas.is_empty() { None } else { Some(schemas) },
            custom_data,
        })
    }
    
    /// Detect file format
    fn detect_format<P: AsRef<Path>>(
        &self,
        path: P,
        content: &str,
    ) -> Result<ExportFormat, ImportExportError> {
        let path = path.as_ref();
        
        // Check file extension first
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            match ext.to_lowercase().as_str() {
                "json" => {
                    if self.is_encrypted(content) {
                        return Ok(ExportFormat::Encrypted);
                    }
                    return Ok(ExportFormat::Json);
                }
                "yaml" | "yml" => return Ok(ExportFormat::Yaml),
                "toml" => return Ok(ExportFormat::Toml),
                "zip" => return Ok(ExportFormat::Archive),
                _ => {}
            }
        }
        
        // Try to detect by content
        if content.trim_start().starts_with('{') {
            if self.is_encrypted(content) {
                Ok(ExportFormat::Encrypted)
            } else {
                Ok(ExportFormat::Json)
            }
        } else {
            Err(ImportExportError::UnsupportedFormat {
                format: "Unknown".to_string(),
            })
        }
    }
    
    /// Check if content is encrypted
    fn is_encrypted(&self, content: &str) -> bool {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
            value.get("algorithm").is_some() && 
            value.get("salt").is_some() && 
            value.get("ciphertext").is_some()
        } else {
            false
        }
    }
    
    /// Decrypt configuration bundle
    fn decrypt_bundle(&self, content: &str, password: &str) -> Result<ConfigBundle, ImportExportError> {
        use sodiumoxide::crypto::pwhash;
        use sodiumoxide::crypto::secretbox;
        
        if sodiumoxide::init().is_err() {
            return Err(ImportExportError::EncryptionError(
                "Failed to initialize crypto library".to_string()
            ));
        }
        
        let encrypted: EncryptedBundle = serde_json::from_str(content)?;
        
        // Decode components
        let salt_bytes = general_purpose::STANDARD.decode(&encrypted.salt)
            .map_err(|e| ImportExportError::EncryptionError(format!("Invalid salt: {}", e)))?;
        let nonce_bytes = general_purpose::STANDARD.decode(&encrypted.nonce)
            .map_err(|e| ImportExportError::EncryptionError(format!("Invalid nonce: {}", e)))?;
        let ciphertext = general_purpose::STANDARD.decode(&encrypted.ciphertext)
            .map_err(|e| ImportExportError::EncryptionError(format!("Invalid ciphertext: {}", e)))?;
        
        // Reconstruct salt and nonce
        if salt_bytes.len() != 32 {
            return Err(ImportExportError::EncryptionError("Invalid salt length".to_string()));
        }
        if nonce_bytes.len() != 24 {
            return Err(ImportExportError::EncryptionError("Invalid nonce length".to_string()));
        }
        
        let mut salt_array = [0u8; 32];
        salt_array.copy_from_slice(&salt_bytes);
        let salt = pwhash::Salt(salt_array);
        
        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&nonce_bytes);
        let nonce = secretbox::Nonce(nonce_array);
        
        // Derive key
        let mut key = secretbox::Key([0; 32]);
        pwhash::derive_key(
            &mut key.0,
            password.as_bytes(),
            &salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        ).map_err(|_| ImportExportError::EncryptionError("Key derivation failed".to_string()))?;
        
        // Decrypt
        let decrypted = secretbox::open(&ciphertext, &nonce, &key)
            .map_err(|_| ImportExportError::EncryptionError("Decryption failed".to_string()))?;
        
        let json = String::from_utf8(decrypted)
            .map_err(|e| ImportExportError::EncryptionError(format!("Invalid UTF-8: {}", e)))?;
        
        Ok(serde_json::from_str(&json)?)
    }
    
    /// Validate imported bundle
    fn validate_bundle(&self, bundle: &ConfigBundle) -> ValidationResult {
        let mut result = ValidationResult::new();
        
        // Validate version compatibility
        if bundle.metadata.version != "1.0.0" {
            result.add_warning(format!(
                "Bundle version {} may not be fully compatible", 
                bundle.metadata.version
            ));
        }
        
        // Validate profiles
        for (name, profile) in &bundle.profiles {
            let profile_result = self.validator.validate_profile(profile);
            if !profile_result.is_valid {
                for error in profile_result.errors {
                    result.add_error(format!("Profile '{}': {}", name, error));
                }
            }
            result.warnings.extend(
                profile_result.warnings.into_iter()
                    .map(|w| format!("Profile '{}': {}", name, w))
            );
        }
        
        // Validate environments
        for (name, env) in &bundle.environments {
            let env_result = self.validator.validate_environment(env);
            if !env_result.is_valid {
                for error in env_result.errors {
                    result.add_error(format!("Environment '{}': {}", name, error));
                }
            }
            result.warnings.extend(
                env_result.warnings.into_iter()
                    .map(|w| format!("Environment '{}': {}", name, w))
            );
        }
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::config::profiles::ConfigurationProfile;
    
    #[test]
    fn test_export_import_profile() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let export_path = temp_dir.path().join("test_profile.json");
        
        let profile = ConfigurationProfile::new(
            "test_profile".to_string(),
            "Test profile for import/export".to_string(),
        );
        
        // Export
        let exporter = ConfigExporter::new();
        exporter.export_profile(&profile, &export_path, None)?;
        
        // Import
        let importer = ConfigImporter::new();
        let (bundle, validation_result) = importer.import_from_file(&export_path, None)?;
        
        assert!(validation_result.is_valid);
        assert_eq!(bundle.profiles.len(), 1);
        assert!(bundle.profiles.contains_key("test_profile"));
        
        Ok(())
    }
    
    #[test]
    fn test_encrypted_export_import() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let export_path = temp_dir.path().join("encrypted_profile.json");
        
        let profile = ConfigurationProfile::new(
            "encrypted_test".to_string(),
            "Test profile for encrypted export".to_string(),
        );
        
        let bundle = ConfigBundle {
            metadata: BundleMetadata {
                version: "1.0.0".to_string(),
                created_at: Utc::now(),
                created_by: None,
                description: Some("Test bundle".to_string()),
                source_system: Some("test".to_string()),
                export_format: ExportFormat::Encrypted,
                checksum: None,
                encryption_info: None,
            },
            profiles: {
                let mut profiles = HashMap::new();
                profiles.insert(profile.name.clone(), profile);
                profiles
            },
            environments: HashMap::new(),
            schemas: None,
            custom_data: HashMap::new(),
        };
        
        let password = "test_password_123";
        
        // Export encrypted
        let exporter = ConfigExporter::new();
        exporter.export_to_file(&bundle, &export_path, Some(ExportFormat::Encrypted), Some(password))?;
        
        // Import encrypted
        let importer = ConfigImporter::new();
        let (imported_bundle, validation_result) = importer.import_from_file(&export_path, Some(password))?;
        
        assert!(validation_result.is_valid);
        assert_eq!(imported_bundle.profiles.len(), 1);
        assert!(imported_bundle.profiles.contains_key("encrypted_test"));
        
        Ok(())
    }
}