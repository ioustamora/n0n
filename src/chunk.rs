use crate::model::ChunkMeta;
use crate::utils::{compute_sha256, encode_base64, read_file_to_bytes};
use std::path::Path;
use anyhow::Result;
use rayon::prelude::*;

pub fn split_file_into_chunks(file_path: &Path, chunk_size: usize, relative_path: &str) -> Result<Vec<ChunkMeta>> {
	let file_data = read_file_to_bytes(file_path)?;
	let file_size = file_data.len() as u64;
	let file_sha256 = compute_sha256(&file_data);

	let chunks: Vec<Vec<u8>> = file_data
		.chunks(chunk_size)
		.map(|chunk| chunk.to_vec())
		.collect();

	let chunk_count = chunks.len();
	let all_chunks: Vec<String> = chunks.iter().map(|chunk| compute_sha256(chunk)).collect();

	let chunk_metas: Vec<ChunkMeta> = chunks
		.into_par_iter()
		.enumerate()
		.map(|(index, chunk)| {
			let chunk_plain_sha256 = compute_sha256(&chunk);
			let data_b64 = encode_base64(&chunk);

			ChunkMeta {
				file_name: relative_path.to_string(),
				file_size,
				file_sha256: file_sha256.clone(),
				chunk_index: index,
				chunk_count,
				chunk_plain_sha256,
				all_chunks: all_chunks.clone(),
				nonce: String::new(), // Will be set during encryption
				data: data_b64,
			}
		})
		.collect();

	Ok(chunk_metas)
}

pub fn assemble_file_from_chunks(chunk_metas: &[ChunkMeta]) -> Result<Vec<u8>> {
	let mut sorted_chunks = chunk_metas.to_vec();
	sorted_chunks.sort_by_key(|chunk| chunk.chunk_index);

	let mut file_data = Vec::new();
	for chunk in sorted_chunks {
		let chunk_data = crate::utils::decode_base64(&chunk.data)?;
		file_data.extend(chunk_data);
	}

	Ok(file_data)
}

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
