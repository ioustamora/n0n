use n0n::utils::*;
use std::fs;
use tempfile::{tempdir, NamedTempFile};
use proptest::prelude::*;

#[test]
fn test_compute_sha256_known_values() {
    // Test known SHA256 values
    let test_cases = vec![
        ("hello", "2cf24dba4f21d4288094e9b259d0c48e533b6e44be07bb6b7f0b4e2d8c5e7d1e"),
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
    ];

    for (input, expected) in test_cases {
        let result = compute_sha256(input.as_bytes());
        assert_eq!(result, expected, "SHA256 hash mismatch for input: {}", input);
    }
}

#[test]
fn test_compute_sha256_consistency() {
    let data = b"test data for consistency check";
    let hash1 = compute_sha256(data);
    let hash2 = compute_sha256(data);
    assert_eq!(hash1, hash2, "SHA256 should be consistent");
}

#[test]
fn test_compute_sha256_different_inputs() {
    let hash1 = compute_sha256(b"input1");
    let hash2 = compute_sha256(b"input2");
    assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
}

#[test]
fn test_base64_encoding_known_values() {
    let test_cases = vec![
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    for (input, expected) in test_cases {
        let result = encode_base64(input.as_bytes());
        assert_eq!(result, expected, "Base64 encoding mismatch for input: {}", input);
    }
}

#[test]
fn test_base64_decoding_known_values() {
    let test_cases = vec![
        ("", ""),
        ("Zg==", "f"),
        ("Zm8=", "fo"),
        ("Zm9v", "foo"),
        ("Zm9vYg==", "foob"),
        ("Zm9vYmE=", "fooba"),
        ("Zm9vYmFy", "foobar"),
    ];

    for (encoded, expected) in test_cases {
        let result = decode_base64(encoded).unwrap();
        let result_str = String::from_utf8(result).unwrap();
        assert_eq!(result_str, expected, "Base64 decoding mismatch for input: {}", encoded);
    }
}

#[test]
fn test_base64_roundtrip() {
    let original_data = b"This is test data for base64 roundtrip testing!";
    let encoded = encode_base64(original_data);
    let decoded = decode_base64(&encoded).unwrap();
    assert_eq!(original_data, &decoded[..], "Base64 roundtrip failed");
}

#[test]
fn test_base64_decode_invalid() {
    let invalid_inputs = vec![
        "invalid base64!",
        "Zm9v!", // Invalid character
        "Zm9", // Invalid padding
    ];

    for invalid in invalid_inputs {
        assert!(decode_base64(invalid).is_err(), "Should fail to decode invalid base64: {}", invalid);
    }
}

#[test]
fn test_file_operations() {
    let temp_file = NamedTempFile::new().unwrap();
    let test_data = b"test file content for utils testing";
    
    // Write test data
    fs::write(temp_file.path(), test_data).unwrap();
    
    // Test get_file_size
    let size = get_file_size(temp_file.path()).unwrap();
    assert_eq!(size, test_data.len() as u64);
    
    // Test read_file_to_bytes
    let read_data = read_file_to_bytes(temp_file.path()).unwrap();
    assert_eq!(read_data, test_data);
}

#[test]
fn test_file_size_nonexistent() {
    let nonexistent_path = std::path::Path::new("/nonexistent/file/path");
    assert!(get_file_size(nonexistent_path).is_err());
}

#[test]
fn test_read_nonexistent_file() {
    let nonexistent_path = std::path::Path::new("/nonexistent/file/path");
    assert!(read_file_to_bytes(nonexistent_path).is_err());
}

#[test]
fn test_chunk_size_calculation() {
    let test_cases = vec![
        (1000, 100, 10),   // 1000 bytes, 100 byte chunks = 10 chunks
        (1500, 100, 15),   // 1500 bytes, 100 byte chunks = 15 chunks
        (99, 100, 1),      // 99 bytes, 100 byte chunks = 1 chunk
        (0, 100, 0),       // 0 bytes = 0 chunks
    ];

    for (file_size, chunk_size, expected_chunks) in test_cases {
        let chunks = calculate_chunks_needed(file_size, chunk_size);
        assert_eq!(chunks, expected_chunks, 
            "Chunk calculation failed for file_size={}, chunk_size={}", file_size, chunk_size);
    }
}

#[test]
fn test_create_directories() {
    let temp_dir = tempdir().unwrap();
    let nested_path = temp_dir.path().join("level1").join("level2").join("level3");
    
    // Test creating nested directories
    create_dir_if_not_exists(&nested_path).unwrap();
    assert!(nested_path.exists(), "Nested directory should be created");
    
    // Test creating directory that already exists (should not fail)
    create_dir_if_not_exists(&nested_path).unwrap();
    assert!(nested_path.exists(), "Should handle existing directory");
}

#[test]
fn test_write_bytes_to_file() {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("test_file.bin");
    let test_data = b"binary test data \x00\x01\x02\x03\xFF";
    
    // Write data
    write_bytes_to_file(&file_path, test_data).unwrap();
    
    // Verify data was written correctly
    let read_data = fs::read(&file_path).unwrap();
    assert_eq!(read_data, test_data);
}

// Property-based tests using proptest
proptest! {
    #[test]
    fn test_sha256_length_property(data: Vec<u8>) {
        let hash = compute_sha256(&data);
        // SHA256 always produces 64 hex characters
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_sha256_hex_chars_property(data: Vec<u8>) {
        let hash = compute_sha256(&data);
        // All characters should be valid hex
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_base64_roundtrip_property(data: Vec<u8>) {
        let encoded = encode_base64(&data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_chunk_calculation_property(file_size in 0u64..10_000_000, chunk_size in 1u64..1_000_000) {
        let chunks = calculate_chunks_needed(file_size, chunk_size);
        
        // Basic properties
        if file_size == 0 {
            assert_eq!(chunks, 0);
        } else {
            assert!(chunks > 0);
            // Should not need more chunks than bytes
            assert!(chunks <= file_size);
            // Should need at least ceil(file_size / chunk_size) chunks
            let expected_min = (file_size + chunk_size - 1) / chunk_size;
            assert_eq!(chunks, expected_min);
        }
    }
}

// Benchmark tests (these require cargo bench to run)
#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::Instant;

    #[test]
    fn bench_sha256_small() {
        let data = vec![0u8; 1024]; // 1KB
        let start = Instant::now();
        for _ in 0..1000 {
            compute_sha256(&data);
        }
        let duration = start.elapsed();
        println!("SHA256 1KB x1000: {:?}", duration);
    }

    #[test]
    fn bench_sha256_large() {
        let data = vec![0u8; 1024 * 1024]; // 1MB
        let start = Instant::now();
        for _ in 0..10 {
            compute_sha256(&data);
        }
        let duration = start.elapsed();
        println!("SHA256 1MB x10: {:?}", duration);
    }

    #[test]
    fn bench_base64_encoding() {
        let data = vec![0u8; 1024 * 1024]; // 1MB
        let start = Instant::now();
        for _ in 0..100 {
            encode_base64(&data);
        }
        let duration = start.elapsed();
        println!("Base64 encode 1MB x100: {:?}", duration);
    }
}

// Test utilities and helper functions
pub fn calculate_chunks_needed(file_size: u64, chunk_size: u64) -> u64 {
    if file_size == 0 || chunk_size == 0 {
        return 0;
    }
    file_size.div_ceil(chunk_size)
}

pub fn create_dir_if_not_exists(path: &std::path::Path) -> std::io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)
    } else {
        Ok(())
    }
}

pub fn write_bytes_to_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    fs::write(path, data)
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_full_file_processing_pipeline() {
        let temp_dir = tempdir().unwrap();
        let input_file = temp_dir.path().join("input.txt");
        let output_file = temp_dir.path().join("output.txt");
        
        let original_data = b"This is test data for the full pipeline test";
        
        // Write original file
        write_bytes_to_file(&input_file, original_data).unwrap();
        
        // Read and hash
        let read_data = read_file_to_bytes(&input_file).unwrap();
        let hash1 = compute_sha256(&read_data);
        
        // Encode to base64 and write
        let encoded = encode_base64(&read_data);
        write_bytes_to_file(&output_file, encoded.as_bytes()).unwrap();
        
        // Read base64 and decode
        let encoded_data = read_file_to_bytes(&output_file).unwrap();
        let encoded_str = String::from_utf8(encoded_data).unwrap();
        let decoded = decode_base64(&encoded_str).unwrap();
        
        // Verify integrity
        let hash2 = compute_sha256(&decoded);
        assert_eq!(hash1, hash2, "Data integrity check failed");
        assert_eq!(original_data, &decoded[..], "Original data should match decoded data");
    }
}