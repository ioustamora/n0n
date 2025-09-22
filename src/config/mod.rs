pub mod profiles;
pub mod environment;
pub mod validation;
pub mod import_export;
pub mod app_config;
pub mod manager;

// Re-export main configuration types
pub use profiles::ProfileManager;
pub use validation::ConfigValidator;
pub use app_config::{AppConfig, CryptoConfig, GuiConfig, LoggingConfig};
