use serde::{Deserialize, Serialize};

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
