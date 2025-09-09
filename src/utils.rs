use sha2::{Digest, Sha256};
use base64::{Engine as _, engine::general_purpose};
use std::fs;
use std::path::Path;
use anyhow::Result;

pub fn compute_sha256(data: &[u8]) -> String {
	let mut hasher = Sha256::new();
	hasher.update(data);
	format!("{:x}", hasher.finalize())
}

pub fn encode_base64(data: &[u8]) -> String {
	general_purpose::STANDARD.encode(data)
}

pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
	Ok(general_purpose::STANDARD.decode(data)?)
}

#[allow(dead_code)]
pub fn get_file_size(path: &Path) -> Result<u64> {
	let metadata = fs::metadata(path)?;
	Ok(metadata.len())
}

pub fn read_file_to_bytes(path: &Path) -> Result<Vec<u8>> {
	Ok(fs::read(path)?)
}

pub fn write_bytes_to_file(path: &Path, data: &[u8]) -> Result<()> {
	fs::write(path, data)?;
	Ok(())
}

pub fn create_dir_if_not_exists(path: &Path) -> Result<()> {
	if !path.exists() {
		fs::create_dir_all(path)?;
	}
	Ok(())
}

pub fn parse_key_hex_or_b64(s: &str) -> Result<Vec<u8>> {
	// try hex first
	if let Ok(bytes) = hex::decode(s) {
		return Ok(bytes);
	}
	// else try base64
	Ok(general_purpose::STANDARD.decode(s)?)
}

/// Estimate number of chunks given file size and chunk size in bytes.
/// Always returns at least 1.
pub fn estimate_chunks(file_size_bytes: usize, chunk_bytes: usize) -> usize {
	if chunk_bytes == 0 { return 1; }
	let chunks = file_size_bytes.div_ceil(chunk_bytes);
	chunks.max(1)
}
