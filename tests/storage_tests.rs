use std::collections::HashMap;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use chrono::Utc;

use n0n::storage::backend::{StorageBackend, StorageConfig, StorageType, ChunkMetadata, LocalConfig, StorageError};
use n0n::storage::factory::StorageFactory;
use n0n::storage::backends::LocalBackend;

/// Test utilities for storage backend testing
pub struct StorageTestUtils;

impl StorageTestUtils {
    /// Create test chunk data
    pub fn create_test_chunk(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }
    
    /// Create test metadata
    pub fn create_test_metadata(size: u64) -> ChunkMetadata {
        ChunkMetadata {
            nonce: "test_nonce_12345".to_string(),
            sender_public_key: "test_public_key_abcdef".to_string(),
            size,
            created_at: Utc::now(),
        }
    }
    
    /// Run basic storage backend tests
    pub async fn test_storage_backend_basic_operations(backend: &dyn StorageBackend) -> Result<(), Box<dyn std::error::Error>> {
        let recipient = "test_recipient";
        let chunk_hash = "test_chunk_hash_123";
        let test_data = Self::create_test_chunk(1024);
        let test_metadata = Self::create_test_metadata(test_data.len() as u64);
        
        // Test save operations
        println!("Testing save_chunk...");
        let stored_key = backend.save_chunk(recipient, chunk_hash, &test_data).await?;
        assert_eq!(stored_key, chunk_hash);
        
        println!("Testing save_metadata...");
        backend.save_metadata(recipient, chunk_hash, &test_metadata).await?;
        
        // Test load operations
        println!("Testing load_chunk...");
        let loaded_data = backend.load_chunk(recipient, chunk_hash).await?;
        assert_eq!(loaded_data, test_data);
        
        println!("Testing load_metadata...");
        let loaded_metadata = backend.load_metadata(recipient, chunk_hash).await?;
        assert_eq!(loaded_metadata.nonce, test_metadata.nonce);
        assert_eq!(loaded_metadata.sender_public_key, test_metadata.sender_public_key);
        assert_eq!(loaded_metadata.size, test_metadata.size);
        
        // Test list operations
        println!("Testing list_chunks...");
        let chunks = backend.list_chunks(recipient).await?;
        assert!(chunks.contains(&chunk_hash.to_string()));
        
        // Test connection
        println!("Testing test_connection...");
        backend.test_connection().await?;
        
        // Test backend info
        println!("Testing get_info...");
        let info = backend.get_info();
        assert!(info.contains_key("backend_type"));
        
        // Test health check
        println!("Testing health_check...");
        let health = backend.health_check().await?;
        assert!(health.contains_key("status"));
        
        // Test delete operations
        println!("Testing delete_chunk...");
        backend.delete_chunk(recipient, chunk_hash).await?;
        
        // Verify deletion
        let result = backend.load_chunk(recipient, chunk_hash).await;
        assert!(result.is_err());
        
        println!("✅ All basic operations passed!");
        Ok(())
    }
    
    /// Test batch operations
    pub async fn test_storage_backend_batch_operations(backend: &dyn StorageBackend) -> Result<(), Box<dyn std::error::Error>> {
        let recipient = "test_batch_recipient";
        let chunks = vec![
            ("batch_chunk_1".to_string(), Self::create_test_chunk(512), Self::create_test_metadata(512)),
            ("batch_chunk_2".to_string(), Self::create_test_chunk(1024), Self::create_test_metadata(1024)),
            ("batch_chunk_3".to_string(), Self::create_test_chunk(2048), Self::create_test_metadata(2048)),
        ];
        
        println!("Testing save_chunks_batch...");
        let results = backend.save_chunks_batch(recipient, chunks.clone()).await?;
        assert_eq!(results.len(), 3);
        
        // Verify all chunks were saved
        for (hash, original_data, original_metadata) in chunks {
            let loaded_data = backend.load_chunk(recipient, &hash).await?;
            assert_eq!(loaded_data, original_data);
            
            let loaded_metadata = backend.load_metadata(recipient, &hash).await?;
            assert_eq!(loaded_metadata.size, original_metadata.size);
        }
        
        // Cleanup
        for result in results {
            backend.delete_chunk(recipient, &result).await?;
        }
        
        println!("✅ Batch operations passed!");
        Ok(())
    }
    
    /// Test error conditions
    pub async fn test_storage_backend_error_conditions(backend: &dyn StorageBackend) -> Result<(), Box<dyn std::error::Error>> {
        let recipient = "test_error_recipient";
        let nonexistent_hash = "nonexistent_chunk_hash";
        
        println!("Testing error conditions...");
        
        // Test loading nonexistent chunk
        let result = backend.load_chunk(recipient, nonexistent_hash).await;
        assert!(result.is_err());
        
        // Test loading nonexistent metadata
        let result = backend.load_metadata(recipient, nonexistent_hash).await;
        assert!(result.is_err());
        
        // Test deleting nonexistent chunk (should not error)
        backend.delete_chunk(recipient, nonexistent_hash).await?;
        
        println!("✅ Error conditions handled correctly!");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_local_backend() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let local_config = LocalConfig {
            base_path: temp_dir.path().to_string_lossy().to_string(),
            create_dirs: Some(true),
        };
        
        let backend = LocalBackend::new(local_config).await
            .expect("Failed to create LocalBackend");
        
        // Run all tests
        StorageTestUtils::test_storage_backend_basic_operations(&backend).await
            .expect("Basic operations test failed");
        
        StorageTestUtils::test_storage_backend_batch_operations(&backend).await
            .expect("Batch operations test failed");
            
        StorageTestUtils::test_storage_backend_error_conditions(&backend).await
            .expect("Error conditions test failed");
        
        println!("🎉 LocalBackend tests completed successfully!");
    }
    
    #[tokio::test]
    async fn test_storage_factory() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        
        let config = StorageConfig {
            backend_type: StorageType::Local,
            local: Some(LocalConfig {
                base_path: temp_dir.path().to_string_lossy().to_string(),
                create_dirs: Some(true),
            }),
            ..Default::default()
        };
        
        // Test factory creation
        let backend = StorageFactory::create_backend(config.clone()).await
            .expect("Failed to create backend through factory");
        
        assert_eq!(backend.backend_type(), StorageType::Local);
        
        // Test configuration validation
        let validation_result = StorageFactory::validate_config(&config).await;
        assert!(validation_result.is_ok());
        
        // Test available backends
        let available = StorageFactory::available_backends();
        assert!(available.contains(&StorageType::Local));
        assert!(available.contains(&StorageType::S3Compatible));
        assert!(available.contains(&StorageType::Redis));
        
        println!("🎉 StorageFactory tests completed successfully!");
    }
    
    #[tokio::test]
    async fn test_storage_manager() {
        use n0n::storage::factory::StorageManager;
        
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let mut manager = StorageManager::new();
        
        let config = StorageConfig {
            backend_type: StorageType::Local,
            local: Some(LocalConfig {
                base_path: temp_dir.path().to_string_lossy().to_string(),
                create_dirs: Some(true),
            }),
            ..Default::default()
        };
        
        // Register a backend
        manager.register_backend("test_local".to_string(), config).await
            .expect("Failed to register backend");
        
        // Test getting backend
        let backend = manager.get_backend("test_local")
            .expect("Failed to get registered backend");
        
        assert_eq!(backend.backend_type(), StorageType::Local);
        
        // Test primary backend
        let primary = manager.get_primary_backend()
            .expect("Failed to get primary backend");
        
        assert_eq!(primary.backend_type(), StorageType::Local);
        
        // Test listing backends
        let backends = manager.list_backends();
        assert_eq!(backends.len(), 1);
        assert!(backends.contains(&"test_local".to_string()));
        
        println!("🎉 StorageManager tests completed successfully!");
    }
    
    #[tokio::test]
    async fn test_chunk_metadata_serialization() {
        let metadata = StorageTestUtils::create_test_metadata(1024);
        
        // Test JSON serialization
        let json = serde_json::to_string(&metadata)
            .expect("Failed to serialize metadata to JSON");
        
        let deserialized: ChunkMetadata = serde_json::from_str(&json)
            .expect("Failed to deserialize metadata from JSON");
        
        assert_eq!(metadata.nonce, deserialized.nonce);
        assert_eq!(metadata.sender_public_key, deserialized.sender_public_key);
        assert_eq!(metadata.size, deserialized.size);
        
        println!("🎉 Metadata serialization tests completed successfully!");
    }
}

/// Integration tests that require external services
#[cfg(feature = "integration-tests")]
mod integration_tests {
    use super::*;
    
    /// These tests require actual cloud credentials and should be run separately
    /// Enable with: cargo test --features integration-tests
    
    #[tokio::test]
    #[ignore] // Requires Redis server
    async fn test_redis_backend_integration() {
        use n0n::storage::backend::RedisConfig;
        use n0n::storage::backends::RedisBackend;
        
        let config = RedisConfig {
            url: std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            cluster_mode: Some(false),
            key_prefix: Some("n0n_test".to_string()),
            ttl: Some(3600), // 1 hour TTL for tests
        };
        
        let backend = RedisBackend::new(config).await
            .expect("Failed to create RedisBackend");
        
        StorageTestUtils::test_storage_backend_basic_operations(&backend).await
            .expect("Redis basic operations test failed");
            
        StorageTestUtils::test_storage_backend_batch_operations(&backend).await
            .expect("Redis batch operations test failed");
        
        println!("🎉 Redis integration tests completed successfully!");
    }
    
    #[tokio::test]
    #[ignore] // Requires PostgreSQL server
    async fn test_postgresql_backend_integration() {
        use n0n::storage::backend::PostgreSQLConfig;
        use n0n::storage::backends::PostgreSQLBackend;
        
        let config = PostgreSQLConfig {
            connection_string: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/n0n_test".to_string()),
            table_prefix: Some("test".to_string()),
            pool_size: Some(5),
        };
        
        let backend = PostgreSQLBackend::new(config).await
            .expect("Failed to create PostgreSQLBackend");
        
        StorageTestUtils::test_storage_backend_basic_operations(&backend).await
            .expect("PostgreSQL basic operations test failed");
            
        StorageTestUtils::test_storage_backend_batch_operations(&backend).await
            .expect("PostgreSQL batch operations test failed");
        
        println!("🎉 PostgreSQL integration tests completed successfully!");
    }
}

/// Benchmark tests for performance measurement
#[cfg(feature = "bench-tests")]
mod benchmark_tests {
    use super::*;
    use std::time::Instant;
    
    #[tokio::test]
    async fn benchmark_local_backend_throughput() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let local_config = LocalConfig {
            base_path: temp_dir.path().to_string_lossy().to_string(),
            create_dirs: Some(true),
        };
        
        let backend = LocalBackend::new(local_config).await
            .expect("Failed to create LocalBackend");
        
        let recipient = "benchmark_recipient";
        let chunk_data = StorageTestUtils::create_test_chunk(1024); // 1KB chunks
        let chunk_metadata = StorageTestUtils::create_test_metadata(1024);
        let num_operations = 1000;
        
        println!("Benchmarking LocalBackend with {} operations...", num_operations);
        
        // Benchmark writes
        let start = Instant::now();
        for i in 0..num_operations {
            let chunk_hash = format!("benchmark_chunk_{}", i);
            backend.save_chunk(recipient, &chunk_hash, &chunk_data).await.unwrap();
            backend.save_metadata(recipient, &chunk_hash, &chunk_metadata).await.unwrap();
        }
        let write_duration = start.elapsed();
        
        // Benchmark reads
        let start = Instant::now();
        for i in 0..num_operations {
            let chunk_hash = format!("benchmark_chunk_{}", i);
            let _ = backend.load_chunk(recipient, &chunk_hash).await.unwrap();
            let _ = backend.load_metadata(recipient, &chunk_hash).await.unwrap();
        }
        let read_duration = start.elapsed();
        
        // Cleanup
        for i in 0..num_operations {
            let chunk_hash = format!("benchmark_chunk_{}", i);
            backend.delete_chunk(recipient, &chunk_hash).await.unwrap();
        }
        
        let write_ops_per_sec = num_operations as f64 / write_duration.as_secs_f64();
        let read_ops_per_sec = num_operations as f64 / read_duration.as_secs_f64();
        
        println!("📊 LocalBackend Benchmark Results:");
        println!("  Write Operations: {:.2} ops/sec", write_ops_per_sec);
        println!("  Read Operations: {:.2} ops/sec", read_ops_per_sec);
        println!("  Write Throughput: {:.2} KB/sec", (write_ops_per_sec * 1024.0) / 1024.0);
        println!("  Read Throughput: {:.2} KB/sec", (read_ops_per_sec * 1024.0) / 1024.0);
    }
}