pub mod local;
pub mod sftp;
pub mod encryption;
pub mod backend;
pub mod factory;
pub mod backends;
pub mod migration;
pub mod analytics;
pub mod backup;

// Re-export main functions for backward compatibility

// Re-export new storage abstractions
pub use self::backup::{BackupStrategy, BackupRecord, BackupFrequency};