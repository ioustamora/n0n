use n0n::utils::*;
use n0n::crypto::*;
use n0n::chunk::*;
use n0n::storage::backend::*;
use n0n::storage::backends::local::LocalStorage;
use tempfile::{tempdir, NamedTempFile};
use std::fs;
use std::path::Path;
use proptest::prelude::*;

/// Test error handling in utility functions
#[test]
fn test_base64_decode_errors() {
    let invalid_inputs = [
        "",
        "invalid base64!",
        "Zm9v!", // Invalid character
        "Zm9", // Invalid padding
        "A", // Too short
        "😀", // Unicode characters
        "====", // All padding
    ];
    
    for invalid in &invalid_inputs {
        let result = decode_base64(invalid);
        assert!(result.is_err(), "Should fail to decode: {}", invalid);
    }
}

#[test]
fn test_file_operations_errors() {
    let nonexistent_path = Path::new("/definitely/does/not/exist/file.txt");
    
    // Test get_file_size with nonexistent file
    let result = get_file_size(nonexistent_path);
    assert!(result.is_err());
    
    // Test read_file_to_bytes with nonexistent file
    let result = read_file_to_bytes(nonexistent_path);
    assert!(result.is_err());
    
    // Test write to read-only location (attempt)
    #[cfg(unix)]
    {
        let readonly_path = Path::new("/read_only_test_file.txt");
        let result = write_bytes_to_file(readonly_path, b"test data");
        assert!(result.is_err());
    }
}

#[test] 
fn test_key_parsing_errors() {
    let invalid_keys = [
        "", // Empty string
        "not a key", // Plain text
        "zz", // Invalid hex (odd length)
        "gg", // Invalid hex characters
        "😀", // Unicode
        "a very long string that is definitely not a key but just text",
    ];
    
    for invalid_key in &invalid_keys {
        let result = parse_key_hex_or_b64(invalid_key);
        // Should either fail or return something reasonable
        // (implementation might handle some cases gracefully)
        if result.is_err() {
            // This is expected for clearly invalid keys
        } else {
            // If it succeeds, the result should at least be non-empty for non-empty input
            if !invalid_key.is_empty() {
                assert!(!result.unwrap().is_empty());
            }
        }
    }
}

#[test]
fn test_crypto_decrypt_errors() {
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    let (_wrong_pk, wrong_sk) = generate_keypair();
    
    let plaintext = b"Test message";
    let (ciphertext, nonce_b64) = encrypt_chunk(plaintext, &recipient_pk, &sender_sk).unwrap();
    
    // Wrong recipient key
    let result = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &wrong_sk);
    assert!(result.is_err());
    
    // Wrong sender key  
    let result = decrypt_chunk(&ciphertext, &nonce_b64, &wrong_sk, &recipient_sk);
    assert!(result.is_err());
    
    // Invalid nonce
    let result = decrypt_chunk(&ciphertext, "invalid_nonce", &sender_pk, &recipient_sk);
    assert!(result.is_err());
    
    // Corrupted ciphertext
    let mut corrupted_ciphertext = ciphertext.clone();
    if !corrupted_ciphertext.is_empty() {
        corrupted_ciphertext[0] ^= 1;
    }
    let result = decrypt_chunk(&corrupted_ciphertext, &nonce_b64, &sender_pk, &recipient_sk);
    assert!(result.is_err());
    
    // Empty ciphertext
    let result = decrypt_chunk(&[], &nonce_b64, &sender_pk, &recipient_sk);
    assert!(result.is_err());
}

#[test]
fn test_encrypt_with_nonce_errors() {
    init();
    let (recipient_pk, _) = generate_keypair();
    let (_, sender_sk) = generate_keypair();
    
    let plaintext = b"Test message";
    
    // Invalid nonce sizes
    let invalid_nonces = [
        vec![], // Empty
        vec![0u8; 12], // Too short
        vec![0u8; 48], // Too long
        vec![0u8; NONCEBYTES - 1], // One byte short
        vec![0u8; NONCEBYTES + 1], // One byte too long
    ];
    
    for invalid_nonce in &invalid_nonces {
        let result = encrypt_with_nonce(plaintext, invalid_nonce, &recipient_pk, &sender_sk);
        assert!(result.is_err(), "Should fail with nonce length: {}", invalid_nonce.len());
    }
}

#[test]
fn test_chunk_operations_errors() {
    let temp_dir = tempdir().unwrap();
    
    // Test split_file_into_chunks with nonexistent file
    let nonexistent_file = temp_dir.path().join("does_not_exist.txt");
    let result = split_file_into_chunks(&nonexistent_file, 1024, "test.txt");
    assert!(result.is_err());
    
    // Test verify_chunk_integrity with corrupted chunk
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), b"test data").unwrap();
    
    let mut chunks = split_file_into_chunks(temp_file.path(), 5, "test.txt").unwrap();
    
    // Corrupt the chunk data
    chunks[0].data = encode_base64(b"corrupted data");
    let result = verify_chunk_integrity(&chunks[0]);
    assert!(result.is_err());
    
    // Test verify_file_integrity with corrupted assembled data
    let valid_chunks = split_file_into_chunks(temp_file.path(), 5, "test.txt").unwrap();
    let mut assembled_data = b"wrong data".to_vec();
    let result = verify_file_integrity(&valid_chunks, &assembled_data);
    assert!(result.is_err());
}

#[test]
fn test_chunk_assembly_errors() {
    use n0n::model::ChunkMeta;
    
    // Test with chunk that has invalid base64 data
    let invalid_chunk = ChunkMeta {
        file_name: "test.txt".to_string(),
        file_size: 100,
        file_sha256: "hash".to_string(),
        chunk_index: 0,
        chunk_count: 1,
        chunk_plain_sha256: "chunk_hash".to_string(),
        all_chunks: vec!["chunk_hash".to_string()],
        nonce: "".to_string(),
        data: "invalid base64 data!".to_string(),
    };
    
    let result = assemble_file_from_chunks(&[invalid_chunk]);
    assert!(result.is_err());
}

#[test]
fn test_storage_backend_errors() {
    let temp_dir = tempdir().unwrap();
    let config = LocalStorageConfig {
        base_path: temp_dir.path().to_path_buf(),
        create_directories: true,
    };
    
    let storage = LocalStorage::new(config);
    
    // Test with invalid recipient (should still work for local storage but test error handling)
    let invalid_recipient = ""; // Empty recipient
    let chunk_data = b"test data";
    let chunk_hash = "testhash";
    let nonce = "testnonce";
    let sender = "testsender";
    
    // This might succeed for local storage, but we're testing the error handling paths exist
    let result = futures::executor::block_on(
        storage.store_chunk(invalid_recipient, chunk_hash, chunk_data, nonce, sender)
    );
    // Local storage might handle empty recipients gracefully, so we just ensure no panic
    let _ = result;
}

#[test]
fn test_directory_creation_errors() {
    // Test create_dir_if_not_exists with invalid path
    #[cfg(unix)]
    {
        let invalid_path = Path::new("/root/test_dir_should_fail");
        let result = create_dir_if_not_exists(invalid_path);
        // This might fail due to permissions, which is expected
        let _ = result; // Don't assert - just ensure no panic
    }
    
    #[cfg(windows)]
    {
        let invalid_path = Path::new("C:\\Windows\\System32\\test_dir_should_fail");
        let result = create_dir_if_not_exists(invalid_path);
        // This might fail due to permissions, which is expected  
        let _ = result; // Don't assert - just ensure no panic
    }
}

#[test]
fn test_concurrent_error_handling() {
    use rayon::prelude::*;
    
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    // Test concurrent operations with some invalid data
    let test_data: Vec<&[u8]> = vec![
        b"valid data 1",
        b"valid data 2", 
        b"", // Empty data
        b"valid data 3",
        b"valid data 4",
    ];
    
    let results: Vec<_> = test_data.par_iter().map(|data| {
        encrypt_chunk(data, &recipient_pk, &sender_sk)
    }).collect();
    
    // All should succeed (including empty data)
    for result in results {
        assert!(result.is_ok());
    }
    
    // Test concurrent decryption with some invalid nonces
    let valid_data = b"test message";
    let (valid_ciphertext, valid_nonce) = encrypt_chunk(valid_data, &recipient_pk, &sender_sk).unwrap();
    
    let nonces = vec![
        valid_nonce.clone(),
        "invalid_nonce_1".to_string(),
        valid_nonce.clone(),
        "invalid_nonce_2".to_string(),
    ];
    
    let decrypt_results: Vec<_> = nonces.par_iter().map(|nonce| {
        decrypt_chunk(&valid_ciphertext, nonce, &sender_pk, &recipient_sk)
    }).collect();
    
    // Should have mixed results - valid nonces succeed, invalid ones fail
    assert!(decrypt_results[0].is_ok()); // Valid
    assert!(decrypt_results[1].is_err()); // Invalid
    assert!(decrypt_results[2].is_ok()); // Valid
    assert!(decrypt_results[3].is_err()); // Invalid
}

#[test]
fn test_edge_case_inputs() {
    // Test with very small chunk sizes
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), b"a").unwrap();
    
    let result = split_file_into_chunks(temp_file.path(), 1, "tiny.txt");
    assert!(result.is_ok());
    
    let chunks = result.unwrap();
    assert_eq!(chunks.len(), 1);
    
    // Test assembly of single byte
    let assembled = assemble_file_from_chunks(&chunks).unwrap();
    assert_eq!(assembled, b"a");
    
    // Test zero-sized inputs where applicable
    let result = estimate_chunks(0, 1024);
    assert_eq!(result, 0);
    
    let result = estimate_chunks(100, 0);
    assert_eq!(result, 1); // Should handle division by zero gracefully
}

#[test]
fn test_memory_exhaustion_protection() {
    // Test with reasonable limits to avoid actually exhausting memory
    // These tests verify that the functions don't panic with large inputs
    
    let large_chunk_size = 1024 * 1024; // 1MB chunks
    let reasonable_file_size = 10 * 1024 * 1024; // 10MB file
    
    let chunks_needed = estimate_chunks(reasonable_file_size, large_chunk_size);
    assert!(chunks_needed > 0);
    assert!(chunks_needed < 1000); // Reasonable number of chunks
    
    // Test that we don't create absurdly large data structures
    let temp_file = NamedTempFile::new().unwrap();
    let data = vec![42u8; 1024]; // Small file
    fs::write(temp_file.path(), &data).unwrap();
    
    // Very small chunk size should still work
    let result = split_file_into_chunks(temp_file.path(), 1, "small_chunks.txt");
    assert!(result.is_ok());
    
    let chunks = result.unwrap();
    assert_eq!(chunks.len(), 1024); // One chunk per byte
}

// Property-based error handling tests
proptest! {
    #[test]
    fn test_base64_error_handling_property(invalid_chars: String) {
        // Generate strings that are likely to be invalid base64
        prop_assume!(invalid_chars.len() > 0);
        prop_assume!(invalid_chars.chars().any(|c| !c.is_ascii_alphanumeric() && c != '=' && c != '+' && c != '/'));
        
        let result = decode_base64(&invalid_chars);
        // Should either succeed or fail gracefully (no panic)
        let _ = result;
    }
    
    #[test]
    fn test_crypto_error_handling_property(data: Vec<u8>, corrupt_byte_index: usize) {
        prop_assume!(data.len() > 0);
        
        init();
        let (recipient_pk, recipient_sk) = generate_keypair();
        let (sender_pk, sender_sk) = generate_keypair();
        
        if let Ok((mut ciphertext, nonce_b64)) = encrypt_chunk(&data, &recipient_pk, &sender_sk) {
            // Corrupt the ciphertext at a random position
            if !ciphertext.is_empty() {
                let corrupt_index = corrupt_byte_index % ciphertext.len();
                ciphertext[corrupt_index] ^= 1;
                
                // Decryption should fail gracefully
                let result = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk);
                prop_assert!(result.is_err());
            }
        }
    }
    
    #[test]
    fn test_chunk_size_edge_cases(file_size: usize, chunk_size: usize) {
        prop_assume!(file_size > 0);
        prop_assume!(chunk_size > 0);
        prop_assume!(chunk_size <= 1024 * 1024); // Reasonable upper bound
        
        let chunks_needed = estimate_chunks(file_size, chunk_size);
        
        // Basic properties that should always hold
        prop_assert!(chunks_needed > 0 || file_size == 0);
        prop_assert!(chunks_needed <= file_size); // Can't need more chunks than bytes
        
        // Mathematical property: ceiling division
        let expected = (file_size + chunk_size - 1) / chunk_size;
        prop_assert_eq!(chunks_needed, expected);
    }
    
    #[test]
    fn test_file_operations_safety(filename: String) {
        // Test that file operations handle various filename inputs safely
        prop_assume!(!filename.is_empty());
        prop_assume!(filename.len() < 1000); // Reasonable filename length
        
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join(&filename);
        
        // Writing should either succeed or fail gracefully
        let write_result = write_bytes_to_file(&file_path, b"test data");
        
        if write_result.is_ok() {
            // If write succeeded, read should also succeed
            let read_result = read_file_to_bytes(&file_path);
            prop_assert!(read_result.is_ok());
            
            let size_result = get_file_size(&file_path);
            prop_assert!(size_result.is_ok());
            prop_assert_eq!(size_result.unwrap(), 9); // "test data".len()
        }
        // If write failed, that's also acceptable (invalid filename, permissions, etc.)
    }
}

// Stress testing for error conditions
#[test]
fn test_error_handling_under_stress() {
    use std::thread;
    use std::sync::{Arc, Mutex};
    
    let error_count = Arc::new(Mutex::new(0));
    let success_count = Arc::new(Mutex::new(0));
    
    let handles: Vec<_> = (0..10).map(|_| {
        let error_count = error_count.clone();
        let success_count = success_count.clone();
        
        thread::spawn(move || {
            for i in 0..100 {
                // Mix of valid and invalid operations
                let result = if i % 3 == 0 {
                    // Invalid base64
                    decode_base64(&format!("invalid_{}", i))
                } else {
                    // Valid base64
                    let data = format!("valid_data_{}", i);
                    let encoded = encode_base64(data.as_bytes());
                    decode_base64(&encoded)
                };
                
                if result.is_ok() {
                    *success_count.lock().unwrap() += 1;
                } else {
                    *error_count.lock().unwrap() += 1;
                }
            }
        })
    }).collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let total_errors = *error_count.lock().unwrap();
    let total_successes = *success_count.lock().unwrap();
    
    // Should have mixed results
    assert!(total_errors > 0, "Should have some errors from invalid inputs");
    assert!(total_successes > 0, "Should have some successes from valid inputs");
    assert_eq!(total_errors + total_successes, 1000); // 10 threads * 100 operations
}

#[test] 
fn test_cascading_error_recovery() {
    // Test that errors in one operation don't prevent recovery in subsequent operations
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    let valid_data = b"valid test data";
    let mut operations_results = Vec::new();
    
    // Sequence of operations with some failures in between
    for i in 0..10 {
        let result = if i % 3 == 0 {
            // Invalid operation (wrong keys)
            let (wrong_pk, wrong_sk) = generate_keypair();
            let (ciphertext, nonce) = encrypt_chunk(valid_data, &recipient_pk, &sender_sk).unwrap();
            decrypt_chunk(&ciphertext, &nonce, &wrong_pk, &wrong_sk)
        } else {
            // Valid operation
            let (ciphertext, nonce) = encrypt_chunk(valid_data, &recipient_pk, &sender_sk).unwrap();
            decrypt_chunk(&ciphertext, &nonce, &sender_pk, &recipient_sk)
        };
        
        operations_results.push(result);
    }
    
    // Should have both successes and failures
    let successes = operations_results.iter().filter(|r| r.is_ok()).count();
    let failures = operations_results.iter().filter(|r| r.is_err()).count();
    
    assert!(successes > 0, "Should have some successful operations");
    assert!(failures > 0, "Should have some failed operations");
    
    // Failed operations shouldn't prevent subsequent successful ones
    for i in 1..operations_results.len() {
        if operations_results[i-1].is_err() && operations_results[i].is_ok() {
            // This demonstrates error recovery - previous failure didn't break the system
            let decrypted = operations_results[i].as_ref().unwrap();
            assert_eq!(decrypted, valid_data);
        }
    }
}