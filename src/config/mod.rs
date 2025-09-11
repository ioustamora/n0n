pub mod profiles;
pub mod environment;
pub mod validation;
pub mod import_export;
pub mod app_config;
pub mod manager;

// Re-export main configuration types
pub use profiles::{ConfigurationProfile, ProfileManager, ProfileError};
pub use environment::{Environment, EnvironmentConfig, EnvironmentManager};
pub use validation::{ConfigValidator, ValidationError, ValidationResult};
pub use import_export::{ConfigExporter, ConfigImporter, ImportExportError};
pub use app_config::{AppConfig, CryptoConfig, GuiConfig, LoggingConfig, HsmSettings};
pub use manager::{ConfigManager, ConfigChangeNotification, ConfigChangeType};