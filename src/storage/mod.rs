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
pub use local::*;
pub use sftp::*;
pub use encryption::*;

// Re-export new storage abstractions
pub use backend::{StorageBackend, StorageType, StorageConfig, ChunkMetadata, StorageError};
pub use factory::{StorageFactory, StorageManager};
pub use backends::{LocalBackend, SftpBackend, S3Backend};
pub use backup::{BackupManager, BackupStrategy, BackupSchedule, BackupRecord, BackupFrequency};