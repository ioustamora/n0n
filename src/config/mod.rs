pub mod profiles;
pub mod environment;
pub mod validation;
pub mod import_export;

// Re-export main configuration types
pub use profiles::{ConfigurationProfile, ProfileManager, ProfileError};
pub use environment::{Environment, EnvironmentConfig, EnvironmentManager};
pub use validation::{ConfigValidator, ValidationError, ValidationResult};
pub use import_export::{ConfigExporter, ConfigImporter, ImportExportError};