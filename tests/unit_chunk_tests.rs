use n0n::chunk::*;
use n0n::model::ChunkMeta;
use n0n::utils::{compute_sha256, encode_base64, decode_base64};
use proptest::prelude::*;
use tempfile::{NamedTempFile, tempdir};
use std::fs;
use std::path::Path;

#[test]
fn test_split_file_into_chunks_small_file() {
    let temp_file = NamedTempFile::new().unwrap();
    let test_data = b"Hello, chunking world!";
    fs::write(temp_file.path(), test_data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 10, "test.txt").unwrap();
    
    assert_eq!(chunks.len(), 3); // 22 bytes / 10 = 3 chunks
    assert_eq!(chunks[0].chunk_count, 3);
    assert_eq!(chunks[0].file_name, "test.txt");
    assert_eq!(chunks[0].file_size, 22);
    
    // Check chunk indices
    for (i, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk.chunk_index, i);
    }
    
    // Verify file hash consistency
    let expected_file_hash = compute_sha256(test_data);
    for chunk in &chunks {
        assert_eq!(chunk.file_sha256, expected_file_hash);
    }
}

#[test]
fn test_split_file_into_chunks_exact_division() {
    let temp_file = NamedTempFile::new().unwrap();
    let test_data = vec![42u8; 100]; // Exactly divisible by chunk size
    fs::write(temp_file.path(), &test_data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 20, "exact.bin").unwrap();
    
    assert_eq!(chunks.len(), 5); // 100 / 20 = 5 chunks exactly
    
    // Each chunk should be exactly 20 bytes except maybe the last
    for chunk in &chunks {
        let chunk_data = decode_base64(&chunk.data).unwrap();
        assert_eq!(chunk_data.len(), 20);
    }
}

#[test]
fn test_split_file_into_chunks_larger_chunk_than_file() {
    let temp_file = NamedTempFile::new().unwrap();
    let test_data = b"Small file";
    fs::write(temp_file.path(), test_data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 1000, "small.txt").unwrap();
    
    assert_eq!(chunks.len(), 1); // File smaller than chunk size
    assert_eq!(chunks[0].chunk_count, 1);
    
    let chunk_data = decode_base64(&chunks[0].data).unwrap();
    assert_eq!(chunk_data, test_data);
}

#[test]
fn test_split_empty_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), b"").unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 10, "empty.txt").unwrap();
    
    assert_eq!(chunks.len(), 0); // Empty file produces no chunks
}

#[test]
fn test_assemble_file_from_chunks() {
    let temp_file = NamedTempFile::new().unwrap();
    let original_data = b"This is test data for chunk assembly testing!";
    fs::write(temp_file.path(), original_data).unwrap();
    
    // Split into chunks
    let chunks = split_file_into_chunks(temp_file.path(), 15, "test.txt").unwrap();
    
    // Assemble back
    let assembled = assemble_file_from_chunks(&chunks).unwrap();
    
    assert_eq!(assembled, original_data);
}

#[test]
fn test_assemble_file_from_unordered_chunks() {
    let temp_file = NamedTempFile::new().unwrap();
    let original_data = b"Unordered chunk assembly test data";
    fs::write(temp_file.path(), original_data).unwrap();
    
    // Split into chunks
    let mut chunks = split_file_into_chunks(temp_file.path(), 10, "unordered.txt").unwrap();
    
    // Shuffle chunks to test ordering
    chunks.reverse();
    
    // Assemble should still work correctly
    let assembled = assemble_file_from_chunks(&chunks).unwrap();
    
    assert_eq!(assembled, original_data);
}

#[test]
fn test_assemble_empty_chunks() {
    let chunks: Vec<ChunkMeta> = vec![];
    let assembled = assemble_file_from_chunks(&chunks).unwrap();
    assert!(assembled.is_empty());
}

#[test]
fn test_verify_chunk_integrity_valid() {
    let temp_file = NamedTempFile::new().unwrap();
    let test_data = b"Integrity test data";
    fs::write(temp_file.path(), test_data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 10, "integrity.txt").unwrap();
    
    // All chunks should pass integrity check
    for chunk in &chunks {
        verify_chunk_integrity(chunk).unwrap();
    }
}

#[test]
fn test_verify_chunk_integrity_corrupted() {
    let temp_file = NamedTempFile::new().unwrap();
    let test_data = b"Data that will be corrupted";
    fs::write(temp_file.path(), test_data).unwrap();
    
    let mut chunks = split_file_into_chunks(temp_file.path(), 10, "corrupted.txt").unwrap();
    
    // Corrupt the first chunk's data
    let corrupt_data = encode_base64(b"corrupted data here");
    chunks[0].data = corrupt_data;
    
    // Integrity check should fail
    let result = verify_chunk_integrity(&chunks[0]);
    assert!(result.is_err());
}

#[test]
fn test_verify_file_integrity_valid() {
    let temp_file = NamedTempFile::new().unwrap();
    let original_data = b"File integrity verification test data";
    fs::write(temp_file.path(), original_data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 12, "integrity.txt").unwrap();
    let assembled = assemble_file_from_chunks(&chunks).unwrap();
    
    verify_file_integrity(&chunks, &assembled).unwrap();
}

#[test]
fn test_verify_file_integrity_corrupted() {
    let temp_file = NamedTempFile::new().unwrap();
    let original_data = b"File that will be corrupted during assembly";
    fs::write(temp_file.path(), original_data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 15, "corrupted.txt").unwrap();
    let mut assembled = assemble_file_from_chunks(&chunks).unwrap();
    
    // Corrupt assembled data
    assembled[0] ^= 1;
    
    let result = verify_file_integrity(&chunks, &assembled);
    assert!(result.is_err());
}

#[test]
fn test_verify_file_integrity_empty_chunks() {
    let chunks: Vec<ChunkMeta> = vec![];
    let assembled: Vec<u8> = vec![];
    
    // Should not panic on empty chunks
    verify_file_integrity(&chunks, &assembled).unwrap();
}

#[test]
fn test_chunk_metadata_consistency() {
    let temp_file = NamedTempFile::new().unwrap();
    let test_data = vec![123u8; 250]; // Create test data
    fs::write(temp_file.path(), &test_data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 73, "metadata.bin").unwrap();
    
    // Check that all chunks have the same metadata
    let first_chunk = &chunks[0];
    for chunk in &chunks {
        assert_eq!(chunk.file_name, first_chunk.file_name);
        assert_eq!(chunk.file_size, first_chunk.file_size);
        assert_eq!(chunk.file_sha256, first_chunk.file_sha256);
        assert_eq!(chunk.chunk_count, first_chunk.chunk_count);
        assert_eq!(chunk.all_chunks, first_chunk.all_chunks);
    }
    
    // Check that all_chunks contains all individual chunk hashes
    let individual_hashes: Vec<String> = chunks.iter()
        .map(|c| c.chunk_plain_sha256.clone())
        .collect();
    
    assert_eq!(chunks[0].all_chunks, individual_hashes);
}

#[test]
fn test_chunk_plain_sha256_calculation() {
    let temp_file = NamedTempFile::new().unwrap();
    let test_data = b"SHA256 calculation test for individual chunks";
    fs::write(temp_file.path(), test_data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 15, "sha256.txt").unwrap();
    
    // Verify each chunk's SHA256 is computed correctly
    for chunk in &chunks {
        let chunk_data = decode_base64(&chunk.data).unwrap();
        let expected_hash = compute_sha256(&chunk_data);
        assert_eq!(chunk.chunk_plain_sha256, expected_hash);
    }
}

#[test]
fn test_relative_path_preservation() {
    let temp_file = NamedTempFile::new().unwrap();
    let test_data = b"Path preservation test";
    fs::write(temp_file.path(), test_data).unwrap();
    
    let relative_path = "some/nested/path/file.txt";
    let chunks = split_file_into_chunks(temp_file.path(), 10, relative_path).unwrap();
    
    for chunk in &chunks {
        assert_eq!(chunk.file_name, relative_path);
    }
}

#[test]
fn test_nonce_field_initialization() {
    let temp_file = NamedTempFile::new().unwrap();
    let test_data = b"Nonce initialization test";
    fs::write(temp_file.path(), test_data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 10, "nonce.txt").unwrap();
    
    // Nonce should be empty initially (set during encryption)
    for chunk in &chunks {
        assert_eq!(chunk.nonce, "");
    }
}

// Property-based tests using proptest
proptest! {
    #[test]
    fn test_split_assemble_roundtrip(
        data: Vec<u8>,
        chunk_size in 1usize..1000
    ) {
        prop_assume!(!data.is_empty());
        
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunks = split_file_into_chunks(temp_file.path(), chunk_size, "test.bin").unwrap();
        let assembled = assemble_file_from_chunks(&chunks).unwrap();
        
        prop_assert_eq!(data, assembled);
    }
    
    #[test]
    fn test_chunk_count_calculation(
        data_len in 1usize..10000,
        chunk_size in 1usize..1000
    ) {
        let data = vec![42u8; data_len];
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunks = split_file_into_chunks(temp_file.path(), chunk_size, "test.bin").unwrap();
        let expected_chunks = (data_len + chunk_size - 1) / chunk_size; // Ceiling division
        
        prop_assert_eq!(chunks.len(), expected_chunks);
        for chunk in &chunks {
            prop_assert_eq!(chunk.chunk_count, expected_chunks);
        }
    }
    
    #[test]
    fn test_chunk_indices_sequential(
        data_len in 1usize..1000,
        chunk_size in 1usize..100
    ) {
        let data = vec![123u8; data_len];
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunks = split_file_into_chunks(temp_file.path(), chunk_size, "test.bin").unwrap();
        
        for (i, chunk) in chunks.iter().enumerate() {
            prop_assert_eq!(chunk.chunk_index, i);
        }
    }
    
    #[test]
    fn test_file_metadata_consistency(
        data: Vec<u8>,
        chunk_size in 1usize..500,
        relative_path: String
    ) {
        prop_assume!(!data.is_empty());
        prop_assume!(!relative_path.is_empty());
        
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunks = split_file_into_chunks(temp_file.path(), chunk_size, &relative_path).unwrap();
        
        if !chunks.is_empty() {
            let expected_file_size = data.len() as u64;
            let expected_file_hash = compute_sha256(&data);
            
            for chunk in &chunks {
                prop_assert_eq!(chunk.file_size, expected_file_size);
                prop_assert_eq!(chunk.file_sha256, expected_file_hash);
                prop_assert_eq!(chunk.file_name, relative_path);
            }
        }
    }
    
    #[test]
    fn test_chunk_integrity_property(
        data: Vec<u8>,
        chunk_size in 1usize..500
    ) {
        prop_assume!(!data.is_empty());
        
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunks = split_file_into_chunks(temp_file.path(), chunk_size, "test.bin").unwrap();
        
        // All chunks should pass integrity verification
        for chunk in &chunks {
            verify_chunk_integrity(chunk).unwrap();
        }
        
        // Assembled file should match original
        let assembled = assemble_file_from_chunks(&chunks).unwrap();
        verify_file_integrity(&chunks, &assembled).unwrap();
    }
}

// Benchmark tests for performance analysis
#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::Instant;
    
    #[test]
    fn bench_split_small_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![42u8; 10240]; // 10KB
        fs::write(temp_file.path(), &data).unwrap();
        
        let start = Instant::now();
        for _ in 0..100 {
            let _ = split_file_into_chunks(temp_file.path(), 1024, "bench.bin").unwrap();
        }
        let duration = start.elapsed();
        println!("Split small file (10KB) 100x: {:?}", duration);
    }
    
    #[test]
    fn bench_split_large_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![42u8; 1024 * 1024]; // 1MB
        fs::write(temp_file.path(), &data).unwrap();
        
        let start = Instant::now();
        for _ in 0..10 {
            let _ = split_file_into_chunks(temp_file.path(), 1024, "bench.bin").unwrap();
        }
        let duration = start.elapsed();
        println!("Split large file (1MB) 10x: {:?}", duration);
    }
    
    #[test]
    fn bench_assemble_chunks() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![123u8; 50000]; // 50KB
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunks = split_file_into_chunks(temp_file.path(), 1024, "bench.bin").unwrap();
        
        let start = Instant::now();
        for _ in 0..100 {
            let _ = assemble_file_from_chunks(&chunks).unwrap();
        }
        let duration = start.elapsed();
        println!("Assemble chunks (50KB) 100x: {:?}", duration);
    }
    
    #[test]
    fn bench_verify_chunk_integrity() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![42u8; 10000]; // 10KB
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunks = split_file_into_chunks(temp_file.path(), 1000, "bench.bin").unwrap();
        
        let start = Instant::now();
        for _ in 0..1000 {
            for chunk in &chunks {
                verify_chunk_integrity(chunk).unwrap();
            }
        }
        let duration = start.elapsed();
        println!("Verify chunk integrity 1000x: {:?}", duration);
    }
    
    #[test]
    fn bench_different_chunk_sizes() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![42u8; 100000]; // 100KB
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunk_sizes = [512, 1024, 2048, 4096, 8192];
        
        for chunk_size in &chunk_sizes {
            let start = Instant::now();
            for _ in 0..10 {
                let _ = split_file_into_chunks(temp_file.path(), *chunk_size, "bench.bin").unwrap();
            }
            let duration = start.elapsed();
            println!("Split 100KB with {}B chunks 10x: {:?}", chunk_size, duration);
        }
    }
}

// Integration tests with file operations
#[cfg(test)]
mod integration_tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    
    #[test]
    fn test_multiple_file_chunking() {
        let temp_dir = tempdir().unwrap();
        
        // Create multiple test files
        let files = [
            ("file1.txt", b"First test file content"),
            ("file2.bin", &vec![1u8; 1000]), // Binary data
            ("file3.txt", b"Third file with different content"),
        ];
        
        let mut all_chunks = Vec::new();
        
        for (filename, content) in &files {
            let file_path = temp_dir.path().join(filename);
            fs::write(&file_path, content).unwrap();
            
            let chunks = split_file_into_chunks(&file_path, 100, filename).unwrap();
            
            // Verify each file's chunks
            let assembled = assemble_file_from_chunks(&chunks).unwrap();
            assert_eq!(assembled, *content);
            
            all_chunks.extend(chunks);
        }
        
        // Verify we have chunks from all files
        assert!(all_chunks.iter().any(|c| c.file_name == "file1.txt"));
        assert!(all_chunks.iter().any(|c| c.file_name == "file2.bin"));
        assert!(all_chunks.iter().any(|c| c.file_name == "file3.txt"));
    }
    
    #[test]
    fn test_nested_directory_chunking() {
        let temp_dir = tempdir().unwrap();
        let nested_dir = temp_dir.path().join("level1").join("level2");
        fs::create_dir_all(&nested_dir).unwrap();
        
        let file_path = nested_dir.join("nested_file.txt");
        let content = b"Content in nested directory";
        fs::write(&file_path, content).unwrap();
        
        let relative_path = "level1/level2/nested_file.txt";
        let chunks = split_file_into_chunks(&file_path, 10, relative_path).unwrap();
        
        // Verify relative path is preserved
        for chunk in &chunks {
            assert_eq!(chunk.file_name, relative_path);
        }
        
        let assembled = assemble_file_from_chunks(&chunks).unwrap();
        assert_eq!(assembled, content);
    }
    
    #[test]
    fn test_very_large_file_simulation() {
        let temp_file = NamedTempFile::new().unwrap();
        
        // Simulate a large file by writing in chunks
        let chunk_data = vec![42u8; 8192]; // 8KB chunks
        let num_chunks = 128; // Total: 1MB
        
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(temp_file.path())
                .unwrap();
            
            for _ in 0..num_chunks {
                std::io::Write::write_all(&mut file, &chunk_data).unwrap();
            }
        }
        
        // Split the large file
        let chunks = split_file_into_chunks(temp_file.path(), 16384, "large.bin").unwrap();
        
        // Should produce approximately num_chunks/2 chunks (since we're using larger chunk size)
        let expected_chunks = num_chunks / 2;
        assert_eq!(chunks.len(), expected_chunks);
        
        // Verify integrity
        let assembled = assemble_file_from_chunks(&chunks).unwrap();
        verify_file_integrity(&chunks, &assembled).unwrap();
    }
    
    #[test]
    fn test_chunk_parallel_processing() {
        use rayon::prelude::*;
        
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![123u8; 10000];
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunks = split_file_into_chunks(temp_file.path(), 500, "parallel.bin").unwrap();
        
        // Process chunks in parallel
        let results: Vec<bool> = chunks
            .par_iter()
            .map(|chunk| verify_chunk_integrity(chunk).is_ok())
            .collect();
        
        // All chunks should pass verification
        assert!(results.iter().all(|&result| result));
    }
    
    #[test]
    fn test_chunk_serialization_deserialization() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = b"Serialization test data for chunks";
        fs::write(temp_file.path(), data).unwrap();
        
        let original_chunks = split_file_into_chunks(temp_file.path(), 10, "serial.txt").unwrap();
        
        // Serialize to JSON
        for chunk in &original_chunks {
            let json = serde_json::to_string(chunk).unwrap();
            let deserialized: ChunkMeta = serde_json::from_str(&json).unwrap();
            
            // Verify all fields match
            assert_eq!(chunk.file_name, deserialized.file_name);
            assert_eq!(chunk.file_size, deserialized.file_size);
            assert_eq!(chunk.file_sha256, deserialized.file_sha256);
            assert_eq!(chunk.chunk_index, deserialized.chunk_index);
            assert_eq!(chunk.chunk_count, deserialized.chunk_count);
            assert_eq!(chunk.chunk_plain_sha256, deserialized.chunk_plain_sha256);
            assert_eq!(chunk.all_chunks, deserialized.all_chunks);
            assert_eq!(chunk.nonce, deserialized.nonce);
            assert_eq!(chunk.data, deserialized.data);
        }
        
        // Test round-trip through assembly
        let assembled = assemble_file_from_chunks(&original_chunks).unwrap();
        assert_eq!(assembled, data);
    }
}