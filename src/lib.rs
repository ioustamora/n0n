//! # n0n - Secure File Synchronization and Storage
//!
//! n0n is a modern, secure file synchronization and storage solution built in Rust.
//! It provides enterprise-grade security, multiple storage backends, and real-time monitoring.
//!
//! ## Features
//!
//! - **Multi-Backend Storage**: Support for AWS S3, Google Cloud, Azure, SFTP, WebDAV, and IPFS
//! - **Advanced Encryption**: AES-GCM, ChaCha20-Poly1305, with enterprise key management
//! - **Real-time Synchronization**: File watching with intelligent chunking and deduplication
//! - **Security Hardening**: Memory protection, input validation, audit logging
//! - **Performance Monitoring**: Structured logging, metrics, and tracing
//! - **Modern GUI**: Cross-platform interface with drag-and-drop support
//!
//! ## Quick Start
//!
//! ```rust
//! use n0n::config::Config;
//! use n0n::storage::StorageManager;
//! use n0n::crypto::CryptoManager;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = Config::load()?;
//!     let storage = StorageManager::new(config.storage).await?;
//!     let crypto = CryptoManager::new(config.crypto).await?;
//!     
//!     // Start file synchronization
//!     // ...
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! The n0n system is built around several key modules:
//!
//! - [`config`] - Configuration management and parsing
//! - [`storage`] - Multi-backend storage abstraction
//! - [`crypto`] - Cryptographic operations and key management
//! - [`chunk`] - File chunking and deduplication
//! - [`security`] - Security hardening and validation
//! - [`monitoring`] - Performance monitoring and metrics
//! - [`gui`] - Cross-platform graphical interface

pub mod model;
pub mod utils;
pub mod chunk;
pub mod crypto;
pub mod storage;
pub mod watcher;
pub mod search;
pub mod gui;
pub mod config;
pub mod monitoring;
pub mod access_control;
pub mod logging;
pub mod security;

// Re-export common types if needed
pub use model::{
    ChunkMeta, ProcessingOptions, FileEncryptionConfig, SftpConfig, SftpEncryptionConfig,
    SftpUploadConfig, StorageBackend as StorageBackendModel,
};
pub use utils::{
    compute_sha256, encode_base64, decode_base64, get_file_size, read_file_to_bytes,
    write_bytes_to_file, create_dir_if_not_exists, parse_key_hex_or_b64, estimate_chunks,
};
pub use chunk::{
    split_file_into_chunks, deduplicate_chunks, assemble_file_from_chunks,
    verify_file_integrity,
};
pub use crypto::CryptoService;
pub use storage::{
    StorageBackend, StorageType, StorageConfig, ChunkMetadata, StorageError, StorageFactory,
    StorageManager, LocalBackend, SftpBackend, S3Backend, BackupManager, BackupStrategy,
    BackupSchedule, BackupRecord, BackupFrequency,
};