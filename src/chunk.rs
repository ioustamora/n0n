use crate::model::ChunkMeta;
use crate::utils::{compute_sha256, encode_base64, read_file_to_bytes};
use std::path::Path;
use anyhow::Result;
use rayon::prelude::*;

/// Split file into chunks with optimized memory usage
pub fn split_file_into_chunks(file_path: &Path, chunk_size: usize, relative_path: &str) -> Result<Vec<ChunkMeta>> {
	let file_data = read_file_to_bytes(file_path)?;
	let file_size = file_data.len() as u64;
	let file_sha256 = compute_sha256(&file_data);

	// Pre-calculate all chunk hashes in parallel for better performance
	let chunk_hashes: Vec<String> = file_data
		.par_chunks(chunk_size)
		.map(|chunk| compute_sha256(chunk))
		.collect();

	let chunks: Vec<Vec<u8>> = file_data
		.chunks(chunk_size)
		.map(|chunk| chunk.to_vec())
		.collect();

	let chunk_count = chunks.len();

	let chunk_metas: Vec<ChunkMeta> = chunks
		.into_par_iter()
		.enumerate()
		.map(|(index, chunk)| {
			let chunk_plain_sha256 = chunk_hashes[index].clone(); // Use pre-calculated hash
			let data_b64 = encode_base64(&chunk);

			ChunkMeta {
				file_name: relative_path.to_string(),
				file_size,
				file_sha256: file_sha256.clone(),
				chunk_index: index,
				chunk_count,
				chunk_plain_sha256,
				all_chunks: chunk_hashes.clone(),
				nonce: String::new(), // Will be set during encryption
				data: data_b64,
			}
		})
		.collect();

	Ok(chunk_metas)
}

/// Deduplicate chunks based on their hash, keeping only unique chunks
/// Returns (unique_chunks, deduplication_map) where the map shows original_index -> unique_index
pub fn deduplicate_chunks(chunks: Vec<ChunkMeta>) -> (Vec<ChunkMeta>, Vec<usize>) {
	let mut unique_chunks = Vec::new();
	let mut deduplication_map = Vec::with_capacity(chunks.len());
	let mut hash_to_index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
	
	for (original_index, chunk) in chunks.into_iter().enumerate() {
		if let Some(&existing_index) = hash_to_index.get(&chunk.chunk_plain_sha256) {
			// Chunk already exists, map to existing index
			deduplication_map.push(existing_index);
		} else {
			// New unique chunk
			let unique_index = unique_chunks.len();
			hash_to_index.insert(chunk.chunk_plain_sha256.clone(), unique_index);
			unique_chunks.push(chunk);
			deduplication_map.push(unique_index);
		}
	}
	
	log::info!("Deduplication: {} chunks reduced to {} unique chunks ({:.1}% reduction)", 
		deduplication_map.len(), unique_chunks.len(),
		100.0 * (1.0 - unique_chunks.len() as f64 / deduplication_map.len() as f64));
	
	(unique_chunks, deduplication_map)
}

/// Optimized file assembly from chunks with capacity pre-allocation
pub fn assemble_file_from_chunks(chunk_metas: &[ChunkMeta]) -> Result<Vec<u8>> {
	if chunk_metas.is_empty() {
		return Ok(Vec::new());
	}

	let mut sorted_chunks = chunk_metas.to_vec();
	sorted_chunks.sort_by_key(|chunk| chunk.chunk_index);

	// Pre-allocate capacity based on expected file size for better performance
	let expected_size = if let Some(first_chunk) = sorted_chunks.first() {
		first_chunk.file_size as usize
	} else {
		0
	};
	let mut file_data = Vec::with_capacity(expected_size);
	
	for chunk in sorted_chunks {
		let chunk_data = crate::utils::decode_base64(&chunk.data)?;
		file_data.extend(chunk_data);
	}

	Ok(file_data)
}

#[allow(dead_code)]
pub fn verify_chunk_integrity(chunk: &ChunkMeta) -> Result<()> {
	let chunk_data = crate::utils::decode_base64(&chunk.data)?;
	let computed_sha = compute_sha256(&chunk_data);

	if computed_sha != chunk.chunk_plain_sha256 {
		return Err(anyhow::anyhow!("Chunk SHA256 mismatch"));
	}

	Ok(())
}

pub fn verify_file_integrity(chunks: &[ChunkMeta], assembled_data: &[u8]) -> Result<()> {
	let computed_file_sha = compute_sha256(assembled_data);
	if let Some(first_chunk) = chunks.first() {
		if computed_file_sha != first_chunk.file_sha256 {
			return Err(anyhow::anyhow!("File SHA256 mismatch"));
		}
	}
	Ok(())
}
