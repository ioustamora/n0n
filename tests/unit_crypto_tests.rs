use n0n::crypto::*;
use n0n::utils::{encode_base64, decode_base64};
use proptest::prelude::*;
use tempfile::{tempdir, TempDir};
use std::sync::Arc;

#[test]
fn test_crypto_init() {
    // Test that sodium oxide initializes correctly
    init();
    // If this doesn't panic, initialization succeeded
}

#[test]
fn test_generate_keypair() {
    init();
    let (pk1, sk1) = generate_keypair();
    let (pk2, sk2) = generate_keypair();
    
    // Keys should be different
    assert_ne!(pk1.0, pk2.0);
    assert_ne!(sk1.0, sk2.0);
    
    // Keys should have correct lengths
    assert_eq!(pk1.0.len(), 32);
    assert_eq!(sk1.0.len(), 32);
}

#[test]
fn test_encrypt_decrypt_chunk() {
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    let plaintext = b"Hello, secure world!";
    
    // Encrypt
    let (ciphertext, nonce_b64) = encrypt_chunk(plaintext, &recipient_pk, &sender_sk).unwrap();
    
    // Decrypt
    let decrypted = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk).unwrap();
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_encrypt_decrypt_empty_data() {
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    let plaintext = b"";
    
    let (ciphertext, nonce_b64) = encrypt_chunk(plaintext, &recipient_pk, &sender_sk).unwrap();
    let decrypted = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk).unwrap();
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_encrypt_decrypt_large_data() {
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    let plaintext = vec![42u8; 10240]; // 10KB of data
    
    let (ciphertext, nonce_b64) = encrypt_chunk(&plaintext, &recipient_pk, &sender_sk).unwrap();
    let decrypted = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk).unwrap();
    
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_decrypt_with_wrong_keys() {
    init();
    let (recipient_pk, _recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    let (_wrong_pk, wrong_sk) = generate_keypair();
    
    let plaintext = b"Secret message";
    let (ciphertext, nonce_b64) = encrypt_chunk(plaintext, &recipient_pk, &sender_sk).unwrap();
    
    // Try to decrypt with wrong recipient key
    let result = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &wrong_sk);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_with_invalid_nonce() {
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    let plaintext = b"Secret message";
    let (ciphertext, _nonce_b64) = encrypt_chunk(plaintext, &recipient_pk, &sender_sk).unwrap();
    
    // Try to decrypt with invalid nonce
    let invalid_nonce = encode_base64(&[0u8; 12]); // Wrong size
    let result = decrypt_chunk(&ciphertext, &invalid_nonce, &sender_pk, &recipient_sk);
    assert!(result.is_err());
    
    // Try with completely invalid base64
    let result = decrypt_chunk(&ciphertext, "invalid base64!", &sender_pk, &recipient_sk);
    assert!(result.is_err());
}

#[test]
fn test_precompute_shared_key() {
    init();
    let (recipient_pk, _recipient_sk) = generate_keypair();
    let (_sender_pk, sender_sk) = generate_keypair();
    
    let shared_key = precompute_shared(&sender_sk, &recipient_pk);
    
    // Test that precomputed key has correct length
    assert_eq!(shared_key.0.len(), 32);
}

#[test]
fn test_encrypt_with_nonce() {
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    let plaintext = b"Test message with custom nonce";
    let nonce_bytes = vec![1u8; NONCEBYTES];
    
    let ciphertext = encrypt_with_nonce(plaintext, &nonce_bytes, &recipient_pk, &sender_sk).unwrap();
    
    // Decrypt using the same nonce
    let nonce_b64 = encode_base64(&nonce_bytes);
    let decrypted = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk).unwrap();
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_encrypt_with_invalid_nonce_size() {
    init();
    let (recipient_pk, _recipient_sk) = generate_keypair();
    let (_sender_pk, sender_sk) = generate_keypair();
    
    let plaintext = b"Test message";
    let invalid_nonce = vec![1u8; 12]; // Wrong size
    
    let result = encrypt_with_nonce(plaintext, &invalid_nonce, &recipient_pk, &sender_sk);
    assert!(result.is_err());
}

#[test]
fn test_nonce_uniqueness() {
    init();
    let (recipient_pk, _recipient_sk) = generate_keypair();
    let (_sender_pk, sender_sk) = generate_keypair();
    
    let plaintext = b"Same message";
    
    // Encrypt the same message multiple times
    let (_, nonce1) = encrypt_chunk(plaintext, &recipient_pk, &sender_sk).unwrap();
    let (_, nonce2) = encrypt_chunk(plaintext, &recipient_pk, &sender_sk).unwrap();
    let (_, nonce3) = encrypt_chunk(plaintext, &recipient_pk, &sender_sk).unwrap();
    
    // Nonces should be different
    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce2, nonce3);
    assert_ne!(nonce1, nonce3);
}

#[test]
fn test_ciphertext_integrity() {
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    let plaintext = b"Important data that must not be tampered with";
    let (mut ciphertext, nonce_b64) = encrypt_chunk(plaintext, &recipient_pk, &sender_sk).unwrap();
    
    // Tamper with ciphertext
    ciphertext[0] ^= 1;
    
    // Decryption should fail
    let result = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk);
    assert!(result.is_err());
}

// Key Management System Tests
#[tokio::test]
async fn test_key_management_system_creation() {
    let temp_dir = tempdir().unwrap();
    
    let config = KeyStoreConfig {
        storage_path: temp_dir.path().join("keys"),
        master_key_algorithm: KeyAlgorithm::Aes256,
        hsm_config: None,
        audit_enabled: false,
        compliance_frameworks: vec![],
        cache_ttl: std::time::Duration::from_secs(60),
        max_cache_size: 100,
    };
    
    let kms = KeyManagementSystem::new(config).await.unwrap();
    assert!(!kms.is_empty().await);
}

#[tokio::test]
async fn test_key_generation_and_retrieval() {
    let temp_dir = tempdir().unwrap();
    
    let config = KeyStoreConfig {
        storage_path: temp_dir.path().join("keys"),
        master_key_algorithm: KeyAlgorithm::Aes256,
        hsm_config: None,
        audit_enabled: false,
        compliance_frameworks: vec![],
        cache_ttl: std::time::Duration::from_secs(60),
        max_cache_size: 100,
    };
    
    let kms = KeyManagementSystem::new(config).await.unwrap();
    
    // Generate a data encryption key
    let key_id = kms.generate_data_key(KeyAlgorithm::Aes256).await.unwrap();
    
    // Retrieve the key
    let key = kms.get_key(&key_id).await.unwrap();
    assert!(key.is_some());
}

#[tokio::test]
async fn test_key_rotation() {
    let temp_dir = tempdir().unwrap();
    
    let config = KeyStoreConfig {
        storage_path: temp_dir.path().join("keys"),
        master_key_algorithm: KeyAlgorithm::Aes256,
        hsm_config: None,
        audit_enabled: false,
        compliance_frameworks: vec![],
        cache_ttl: std::time::Duration::from_secs(60),
        max_cache_size: 100,
    };
    
    let kms = KeyManagementSystem::new(config).await.unwrap();
    
    // Generate initial key
    let key_id = kms.generate_data_key(KeyAlgorithm::Aes256).await.unwrap();
    
    // Rotate the key
    let new_key_id = kms.rotate_key(&key_id).await.unwrap();
    
    // New key should be different
    assert_ne!(key_id, new_key_id);
    
    // Both keys should exist
    assert!(kms.get_key(&key_id).await.unwrap().is_some());
    assert!(kms.get_key(&new_key_id).await.unwrap().is_some());
}

#[tokio::test]
async fn test_key_lifecycle_manager() {
    let temp_dir = tempdir().unwrap();
    
    let kms_config = KeyStoreConfig {
        storage_path: temp_dir.path().join("keys"),
        master_key_algorithm: KeyAlgorithm::Aes256,
        hsm_config: None,
        audit_enabled: false,
        compliance_frameworks: vec![],
        cache_ttl: std::time::Duration::from_secs(60),
        max_cache_size: 100,
    };
    
    let lifecycle_config = LifecycleConfig {
        default_key_lifetime: std::time::Duration::from_secs(3600),
        rotation_check_interval: std::time::Duration::from_secs(60),
        compliance_check_interval: std::time::Duration::from_secs(300),
        notification_settings: NotificationSettings {
            email_notifications: false,
            webhook_url: None,
            slack_webhook: None,
            escalation_rules: Vec::new(),
        },
        audit_retention_days: 30,
    };
    
    let kms = Arc::new(KeyManagementSystem::new(kms_config).await.unwrap());
    let lifecycle_manager = KeyLifecycleManager::new(kms.clone(), lifecycle_config).await.unwrap();
    
    // Test that lifecycle manager is initialized
    let policies = lifecycle_manager.get_active_policies().await;
    assert!(policies.is_empty()); // Should start with no policies
}

#[tokio::test]
async fn test_certificate_manager() {
    let temp_dir = tempdir().unwrap();
    
    let config = CertificateManagerConfig {
        storage_path: temp_dir.path().join("certificates"),
        default_validity_period: std::time::Duration::from_secs(86400),
        crl_update_interval: std::time::Duration::from_secs(3600),
        ocsp_responder_timeout: std::time::Duration::from_secs(10),
        certificate_cache_ttl: std::time::Duration::from_secs(300),
        max_certificate_cache_size: 100,
        audit_enabled: false,
    };
    
    let cert_manager = CertificateManager::new(config).await.unwrap();
    
    // Test listing empty certificates
    let certificates = cert_manager.list_certificates().await.unwrap();
    assert!(certificates.is_empty());
}

// Property-based tests using proptest
proptest! {
    #[test]
    fn test_encrypt_decrypt_roundtrip(data: Vec<u8>) {
        init();
        let (recipient_pk, recipient_sk) = generate_keypair();
        let (sender_pk, sender_sk) = generate_keypair();
        
        if let Ok((ciphertext, nonce_b64)) = encrypt_chunk(&data, &recipient_pk, &sender_sk) {
            if let Ok(decrypted) = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk) {
                prop_assert_eq!(data, decrypted);
            }
        }
    }
    
    #[test]
    fn test_nonce_base64_roundtrip(nonce_data in prop::array::uniform24(prop::num::u8::ANY)) {
        let nonce_b64 = encode_base64(&nonce_data);
        let decoded = decode_base64(&nonce_b64).unwrap();
        prop_assert_eq!(nonce_data.to_vec(), decoded);
    }
    
    #[test]
    fn test_encrypt_with_nonce_deterministic(
        data: Vec<u8>,
        nonce_data in prop::array::uniform24(prop::num::u8::ANY)
    ) {
        init();
        let (recipient_pk, _recipient_sk) = generate_keypair();
        let (_sender_pk, sender_sk) = generate_keypair();
        
        // Same data and nonce should produce same ciphertext
        if let Ok(ciphertext1) = encrypt_with_nonce(&data, &nonce_data, &recipient_pk, &sender_sk) {
            if let Ok(ciphertext2) = encrypt_with_nonce(&data, &nonce_data, &recipient_pk, &sender_sk) {
                prop_assert_eq!(ciphertext1, ciphertext2);
            }
        }
    }
    
    #[test]
    fn test_different_nonces_produce_different_ciphertext(
        data: Vec<u8>,
        nonce1 in prop::array::uniform24(prop::num::u8::ANY),
        nonce2 in prop::array::uniform24(prop::num::u8::ANY)
    ) {
        prop_assume!(nonce1 != nonce2);
        prop_assume!(!data.is_empty());
        
        init();
        let (recipient_pk, _recipient_sk) = generate_keypair();
        let (_sender_pk, sender_sk) = generate_keypair();
        
        if let Ok(ciphertext1) = encrypt_with_nonce(&data, &nonce1, &recipient_pk, &sender_sk) {
            if let Ok(ciphertext2) = encrypt_with_nonce(&data, &nonce2, &recipient_pk, &sender_sk) {
                prop_assert_ne!(ciphertext1, ciphertext2);
            }
        }
    }
    
    #[test]
    fn test_ciphertext_length_property(data: Vec<u8>) {
        init();
        let (recipient_pk, _recipient_sk) = generate_keypair();
        let (_sender_pk, sender_sk) = generate_keypair();
        
        if let Ok((ciphertext, _nonce_b64)) = encrypt_chunk(&data, &recipient_pk, &sender_sk) {
            // Ciphertext should be longer than plaintext due to authentication tag
            prop_assert!(ciphertext.len() > data.len() || (data.is_empty() && ciphertext.len() > 0));
        }
    }
}

// Benchmark tests for performance analysis
#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::Instant;
    
    #[test]
    fn bench_keypair_generation() {
        init();
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = generate_keypair();
        }
        let duration = start.elapsed();
        println!("Keypair generation 1000x: {:?}", duration);
        
        // Should be reasonably fast (less than 1 second for 1000 keypairs)
        assert!(duration.as_secs() < 1);
    }
    
    #[test]
    fn bench_small_encryption() {
        init();
        let (recipient_pk, _recipient_sk) = generate_keypair();
        let (_sender_pk, sender_sk) = generate_keypair();
        let data = vec![0u8; 1024]; // 1KB
        
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = encrypt_chunk(&data, &recipient_pk, &sender_sk);
        }
        let duration = start.elapsed();
        println!("Small encryption (1KB) 1000x: {:?}", duration);
    }
    
    #[test]
    fn bench_large_encryption() {
        init();
        let (recipient_pk, _recipient_sk) = generate_keypair();
        let (_sender_pk, sender_sk) = generate_keypair();
        let data = vec![0u8; 1024 * 1024]; // 1MB
        
        let start = Instant::now();
        for _ in 0..10 {
            let _ = encrypt_chunk(&data, &recipient_pk, &sender_sk);
        }
        let duration = start.elapsed();
        println!("Large encryption (1MB) 10x: {:?}", duration);
    }
    
    #[test]
    fn bench_decryption() {
        init();
        let (recipient_pk, recipient_sk) = generate_keypair();
        let (sender_pk, sender_sk) = generate_keypair();
        let data = vec![42u8; 1024]; // 1KB
        
        let (ciphertext, nonce_b64) = encrypt_chunk(&data, &recipient_pk, &sender_sk).unwrap();
        
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk);
        }
        let duration = start.elapsed();
        println!("Decryption (1KB) 1000x: {:?}", duration);
    }
    
    #[test]
    fn bench_precompute_shared() {
        init();
        let (recipient_pk, _recipient_sk) = generate_keypair();
        let (_sender_pk, sender_sk) = generate_keypair();
        
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = precompute_shared(&sender_sk, &recipient_pk);
        }
        let duration = start.elapsed();
        println!("Precompute shared key 1000x: {:?}", duration);
    }
}

// Integration tests combining multiple crypto operations
#[cfg(test)]
mod integration_tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_multi_party_encryption() {
        init();
        
        // Create three parties
        let (alice_pk, alice_sk) = generate_keypair();
        let (bob_pk, bob_sk) = generate_keypair();
        let (charlie_pk, charlie_sk) = generate_keypair();
        
        let message = b"Secret shared between all parties";
        
        // Alice encrypts for Bob
        let (ciphertext_for_bob, nonce_for_bob) = encrypt_chunk(message, &bob_pk, &alice_sk).unwrap();
        
        // Alice encrypts for Charlie
        let (ciphertext_for_charlie, nonce_for_charlie) = encrypt_chunk(message, &charlie_pk, &alice_sk).unwrap();
        
        // Bob decrypts his message
        let bob_plaintext = decrypt_chunk(&ciphertext_for_bob, &nonce_for_bob, &alice_pk, &bob_sk).unwrap();
        
        // Charlie decrypts his message
        let charlie_plaintext = decrypt_chunk(&ciphertext_for_charlie, &nonce_for_charlie, &alice_pk, &charlie_sk).unwrap();
        
        // Both should get the original message
        assert_eq!(message, &bob_plaintext[..]);
        assert_eq!(message, &charlie_plaintext[..]);
        assert_eq!(bob_plaintext, charlie_plaintext);
    }
    
    #[tokio::test]
    async fn test_full_enterprise_crypto_pipeline() {
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path().to_path_buf();
        
        // Create complete crypto service
        let kms_config = KeyStoreConfig {
            storage_path: base_path.join("keys"),
            master_key_algorithm: KeyAlgorithm::Aes256,
            hsm_config: None,
            audit_enabled: false,
            compliance_frameworks: vec![],
            cache_ttl: std::time::Duration::from_secs(60),
            max_cache_size: 100,
        };
        
        let lifecycle_config = LifecycleConfig {
            default_key_lifetime: std::time::Duration::from_secs(3600),
            rotation_check_interval: std::time::Duration::from_secs(60),
            compliance_check_interval: std::time::Duration::from_secs(300),
            notification_settings: NotificationSettings {
                email_notifications: false,
                webhook_url: None,
                slack_webhook: None,
                escalation_rules: Vec::new(),
            },
            audit_retention_days: 30,
        };
        
        let cert_config = CertificateManagerConfig {
            storage_path: base_path.join("certificates"),
            default_validity_period: std::time::Duration::from_secs(86400),
            crl_update_interval: std::time::Duration::from_secs(3600),
            ocsp_responder_timeout: std::time::Duration::from_secs(10),
            certificate_cache_ttl: std::time::Duration::from_secs(300),
            max_certificate_cache_size: 100,
            audit_enabled: false,
        };
        
        let advanced_config = AdvancedCryptoConfig {
            enable_zk_proofs: false,
            enable_homomorphic_encryption: false,
            enable_mpc: false,
            operation_cache_ttl: std::time::Duration::from_secs(300),
            max_operation_cache_size: 100,
            secure_random_entropy_sources: vec!["system".to_string()],
            performance_monitoring: false,
            audit_all_operations: false,
        };
        
        let crypto_service = CryptoService::new(
            kms_config,
            lifecycle_config,
            cert_config,
            advanced_config,
        ).await.unwrap();
        
        // Test the complete pipeline
        crypto_service.start_services().await.unwrap();
        
        // Generate some keys through KMS
        let key_id = crypto_service.key_management().generate_data_key(KeyAlgorithm::Aes256).await.unwrap();
        let key = crypto_service.key_management().get_key(&key_id).await.unwrap();
        assert!(key.is_some());
        
        // Test lifecycle management
        let policies = crypto_service.lifecycle_manager().get_active_policies().await;
        assert!(policies.is_empty()); // Should start empty
        
        // Test certificate management
        let certificates = crypto_service.certificate_manager().list_certificates().await.unwrap();
        assert!(certificates.is_empty()); // Should start empty
        
        // Shutdown gracefully
        crypto_service.shutdown().await.unwrap();
    }
}

// Mock HSM tests for offline development
#[cfg(test)]
mod mock_hsm_tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_mock_hsm_provider() {
        let temp_dir = tempdir().unwrap();
        
        let mut config = KeyStoreConfig {
            storage_path: temp_dir.path().join("keys"),
            master_key_algorithm: KeyAlgorithm::Aes256,
            hsm_config: Some(HsmProvider::Mock),
            audit_enabled: false,
            compliance_frameworks: vec![],
            cache_ttl: std::time::Duration::from_secs(60),
            max_cache_size: 100,
        };
        
        let kms = KeyManagementSystem::new(config).await.unwrap();
        
        // Test key generation with mock HSM
        let key_id = kms.generate_data_key(KeyAlgorithm::Aes256).await.unwrap();
        let key = kms.get_key(&key_id).await.unwrap();
        assert!(key.is_some());
    }
}