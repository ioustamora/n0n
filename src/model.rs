use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicBool};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChunkMeta {
	pub file_name: String,
	pub file_size: u64,
	pub file_sha256: String,
	pub chunk_index: usize,
	pub chunk_count: usize,
	pub chunk_plain_sha256: String,
	pub all_chunks: Vec<String>,
	pub nonce: String,
	pub data: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum StorageBackend {
	Local(String),
	Sftp { host: String, username: String, password: String, path: String },
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProcessingOptions {
	pub chunk_size: usize,
	pub output_dir: String,
	pub recipient_public_key: String,
	pub sender_private_key: Option<String>,
	pub storage_backend: StorageBackend,
	pub auto_watch: bool,
}

/// Configuration for local file encryption
#[derive(Debug, Clone)]
pub struct FileEncryptionConfig<'a> {
	pub file_path: &'a Path,
	pub root_folder: &'a Path,
	pub recipient_pk_b64: &'a str,
	pub sender_sk_b64: Option<&'a str>,
	pub mailbox_base: &'a Path,
	pub chunk_size_bytes: usize,
	pub progress: Option<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
	pub cancel: Option<Arc<AtomicBool>>,
}

/// Configuration for SFTP operations
#[derive(Debug, Clone)]
pub struct SftpConfig<'a> {
	pub host: &'a str,
	pub username: &'a str,
	pub password: Option<&'a str>,
	pub private_key: Option<&'a str>,
	pub private_key_passphrase: Option<&'a str>,
	pub host_fingerprint: Option<&'a str>,
	pub remote_base: &'a str,
}

/// Configuration for SFTP file encryption
#[derive(Debug, Clone)]
pub struct SftpEncryptionConfig<'a> {
	pub file_path: &'a Path,
	pub root_folder: &'a Path,
	pub recipient_pk_b64: &'a str,
	pub sender_sk_b64: Option<&'a str>,
	pub sftp: SftpConfig<'a>,
	pub chunk_size_bytes: usize,
	pub progress: Option<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
	pub cancel: Option<Arc<AtomicBool>>,
}

/// Configuration for SFTP chunk upload
#[derive(Debug, Clone)]
pub struct SftpUploadConfig<'a> {
	pub host: &'a str,
	pub username: &'a str,
	pub password: &'a str,
	pub remote_base: &'a str,
	pub recipient: &'a str,
	pub sha: &'a str,
	pub data: &'a [u8],
	pub nonce_b64: &'a str,
	pub sender_b64: &'a str,
}
