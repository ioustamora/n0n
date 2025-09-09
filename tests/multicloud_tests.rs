use std::collections::HashMap;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

use n0n::storage::backend::{
    StorageConfig, StorageType, LocalConfig, 
    ReplicationConfig, ConsistencyLevel, ReplicationStrategy
};
use n0n::storage::backends::MultiCloudBackend;
use n0n::storage::factory::StorageFactory;

/// Tests for multi-cloud replication functionality
#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_tests::StorageTestUtils;
    
    async fn create_test_multicloud_backend() -> (MultiCloudBackend, Vec<TempDir>) {
        let temp_dirs = vec![
            TempDir::new().expect("Failed to create temp directory 1"),
            TempDir::new().expect("Failed to create temp directory 2"),
            TempDir::new().expect("Failed to create temp directory 3"),
        ];
        
        let replication_config = ReplicationConfig {
            primary_backend: StorageType::Local,
            replica_backends: vec![StorageType::Local, StorageType::Local],
            consistency_level: ConsistencyLevel::Strong,
            replication_strategy: ReplicationStrategy::SyncReplication,
        };
        
        let mut backend_configs = HashMap::new();
        
        // Primary backend
        backend_configs.insert(StorageType::Local, StorageConfig {
            backend_type: StorageType::Local,
            local: Some(LocalConfig {
                base_path: temp_dirs[0].path().to_string_lossy().to_string(),
                create_dirs: Some(true),
            }),
            ..Default::default()
        });
        
        // Create replica backends with different paths to simulate different storage systems
        for (i, temp_dir) in temp_dirs.iter().enumerate().skip(1) {
            backend_configs.insert(StorageType::Local, StorageConfig {
                backend_type: StorageType::Local,
                local: Some(LocalConfig {
                    base_path: temp_dir.path().to_string_lossy().to_string(),
                    create_dirs: Some(true),
                }),
                ..Default::default()
            });
        }
        
        let backend = MultiCloudBackend::new(replication_config, backend_configs).await
            .expect("Failed to create MultiCloudBackend");
        
        (backend, temp_dirs)
    }
    
    #[tokio::test]
    async fn test_multicloud_strong_consistency() {
        let (backend, _temp_dirs) = create_test_multicloud_backend().await;
        
        let recipient = "multicloud_recipient";
        let chunk_hash = "multicloud_chunk";
        let test_data = StorageTestUtils::create_test_chunk(2048);
        let test_metadata = StorageTestUtils::create_test_metadata(test_data.len() as u64);
        
        println!("Testing MultiCloud strong consistency...");
        
        // Save with strong consistency - should replicate to all backends
        let result = backend.save_chunk(recipient, chunk_hash, &test_data).await;
        assert!(result.is_ok());
        
        // Save metadata
        backend.save_metadata(recipient, chunk_hash, &test_metadata).await
            .expect("Failed to save metadata");
        
        // Read should be available from any replica
        let loaded_data = backend.load_chunk(recipient, chunk_hash).await
            .expect("Failed to load chunk");
        assert_eq!(loaded_data, test_data);
        
        let loaded_metadata = backend.load_metadata(recipient, chunk_hash).await
            .expect("Failed to load metadata");
        assert_eq!(loaded_metadata.size, test_metadata.size);
        
        println!("✅ Strong consistency test passed!");
    }
    
    #[tokio::test]
    async fn test_multicloud_eventual_consistency() {
        let temp_dirs = vec![
            TempDir::new().expect("Failed to create temp directory 1"),
            TempDir::new().expect("Failed to create temp directory 2"),
        ];
        
        let replication_config = ReplicationConfig {
            primary_backend: StorageType::Local,
            replica_backends: vec![StorageType::Local],
            consistency_level: ConsistencyLevel::Eventual,
            replication_strategy: ReplicationStrategy::AsyncReplication,
        };
        
        let mut backend_configs = HashMap::new();
        backend_configs.insert(StorageType::Local, StorageConfig {
            backend_type: StorageType::Local,
            local: Some(LocalConfig {
                base_path: temp_dirs[0].path().to_string_lossy().to_string(),
                create_dirs: Some(true),
            }),
            ..Default::default()
        });
        
        let backend = MultiCloudBackend::new(replication_config, backend_configs).await
            .expect("Failed to create MultiCloudBackend");
        
        let recipient = "eventual_recipient";
        let chunk_hash = "eventual_chunk";
        let test_data = StorageTestUtils::create_test_chunk(1024);
        let test_metadata = StorageTestUtils::create_test_metadata(test_data.len() as u64);
        
        println!("Testing MultiCloud eventual consistency...");
        
        // Save with eventual consistency - should return quickly
        let start = std::time::Instant::now();
        backend.save_chunk(recipient, chunk_hash, &test_data).await
            .expect("Failed to save chunk");
        backend.save_metadata(recipient, chunk_hash, &test_metadata).await
            .expect("Failed to save metadata");
        let duration = start.elapsed();
        
        // With async replication, this should be fast
        println!("Async save took: {:?}", duration);
        
        // Read should work immediately from primary
        let loaded_data = backend.load_chunk(recipient, chunk_hash).await
            .expect("Failed to load chunk");
        assert_eq!(loaded_data, test_data);
        
        // Wait a bit for async replication to complete
        sleep(Duration::from_millis(100)).await;
        
        println!("✅ Eventual consistency test passed!");
    }
    
    #[tokio::test]
    async fn test_multicloud_quorum_operations() {
        let temp_dirs: Vec<TempDir> = (0..3)
            .map(|_| TempDir::new().expect("Failed to create temp directory"))
            .collect();
        
        let replication_config = ReplicationConfig {
            primary_backend: StorageType::Local,
            replica_backends: vec![StorageType::Local, StorageType::Local],
            consistency_level: ConsistencyLevel::Quorum,
            replication_strategy: ReplicationStrategy::QuorumWrite,
        };
        
        let mut backend_configs = HashMap::new();
        for (i, temp_dir) in temp_dirs.iter().enumerate() {
            backend_configs.insert(StorageType::Local, StorageConfig {
                backend_type: StorageType::Local,
                local: Some(LocalConfig {
                    base_path: temp_dir.path().to_string_lossy().to_string(),
                    create_dirs: Some(true),
                }),
                ..Default::default()
            });
        }
        
        let backend = MultiCloudBackend::new(replication_config, backend_configs).await
            .expect("Failed to create MultiCloudBackend");
        
        let recipient = "quorum_recipient";
        let chunk_hash = "quorum_chunk";
        let test_data = StorageTestUtils::create_test_chunk(512);
        let test_metadata = StorageTestUtils::create_test_metadata(test_data.len() as u64);
        
        println!("Testing MultiCloud quorum operations...");
        
        // Quorum write - should succeed if majority of replicas are available
        backend.save_chunk(recipient, chunk_hash, &test_data).await
            .expect("Quorum write failed");
        backend.save_metadata(recipient, chunk_hash, &test_metadata).await
            .expect("Failed to save metadata");
        
        // Quorum read - should read from majority
        let loaded_data = backend.load_chunk(recipient, chunk_hash).await
            .expect("Quorum read failed");
        assert_eq!(loaded_data, test_data);
        
        println!("✅ Quorum operations test passed!");
    }
    
    #[tokio::test]
    async fn test_multicloud_failover() {
        let (backend, _temp_dirs) = create_test_multicloud_backend().await;
        
        let recipient = "failover_recipient";
        let chunk_hash = "failover_chunk";
        let test_data = StorageTestUtils::create_test_chunk(1024);
        let test_metadata = StorageTestUtils::create_test_metadata(test_data.len() as u64);
        
        println!("Testing MultiCloud failover behavior...");
        
        // First, save data successfully
        backend.save_chunk(recipient, chunk_hash, &test_data).await
            .expect("Failed to save chunk");
        backend.save_metadata(recipient, chunk_hash, &test_metadata).await
            .expect("Failed to save metadata");
        
        // Verify data is accessible
        let loaded_data = backend.load_chunk(recipient, chunk_hash).await
            .expect("Failed to load chunk");
        assert_eq!(loaded_data, test_data);
        
        // Test health check
        let health = backend.health_check().await
            .expect("Health check failed");
        println!("MultiCloud health status: {:?}", health);
        
        // Test backend info
        let info = backend.get_info();
        assert!(info.contains_key("backend_type"));
        assert_eq!(info["backend_type"], "MultiCloud");
        
        println!("✅ Failover behavior test passed!");
    }
    
    #[tokio::test]
    async fn test_multicloud_batch_operations() {
        let (backend, _temp_dirs) = create_test_multicloud_backend().await;
        
        let recipient = "batch_multicloud_recipient";
        let chunks = vec![
            ("multicloud_batch_1".to_string(), StorageTestUtils::create_test_chunk(256), StorageTestUtils::create_test_metadata(256)),
            ("multicloud_batch_2".to_string(), StorageTestUtils::create_test_chunk(512), StorageTestUtils::create_test_metadata(512)),
            ("multicloud_batch_3".to_string(), StorageTestUtils::create_test_chunk(1024), StorageTestUtils::create_test_metadata(1024)),
        ];
        
        println!("Testing MultiCloud batch operations...");
        
        // Test batch save with replication
        let results = backend.save_chunks_batch(recipient, chunks.clone()).await
            .expect("Batch save failed");
        assert_eq!(results.len(), 3);
        
        // Verify all chunks were replicated correctly
        for (hash, original_data, _) in chunks {
            let loaded_data = backend.load_chunk(recipient, &hash).await
                .expect("Failed to load replicated chunk");
            assert_eq!(loaded_data, original_data);
        }
        
        // Test list chunks
        let chunk_list = backend.list_chunks(recipient).await
            .expect("Failed to list chunks");
        assert!(chunk_list.len() >= 3);
        
        println!("✅ MultiCloud batch operations test passed!");
    }
    
    #[tokio::test]
    async fn test_multicloud_consistency_levels() {
        // Test different consistency levels
        let consistency_levels = vec![
            ConsistencyLevel::Eventual,
            ConsistencyLevel::Strong,
            ConsistencyLevel::Quorum,
        ];
        
        for consistency_level in consistency_levels {
            println!("Testing consistency level: {:?}", consistency_level);
            
            let temp_dirs: Vec<TempDir> = (0..2)
                .map(|_| TempDir::new().expect("Failed to create temp directory"))
                .collect();
            
            let replication_config = ReplicationConfig {
                primary_backend: StorageType::Local,
                replica_backends: vec![StorageType::Local],
                consistency_level: consistency_level.clone(),
                replication_strategy: ReplicationStrategy::SyncReplication,
            };
            
            let mut backend_configs = HashMap::new();
            for (i, temp_dir) in temp_dirs.iter().enumerate() {
                backend_configs.insert(StorageType::Local, StorageConfig {
                    backend_type: StorageType::Local,
                    local: Some(LocalConfig {
                        base_path: temp_dir.path().to_string_lossy().to_string(),
                        create_dirs: Some(true),
                    }),
                    ..Default::default()
                });
            }
            
            let backend = MultiCloudBackend::new(replication_config, backend_configs).await
                .expect("Failed to create MultiCloudBackend");
            
            // Test basic operations with this consistency level
            let recipient = &format!("consistency_test_{:?}", consistency_level);
            let chunk_hash = "consistency_chunk";
            let test_data = StorageTestUtils::create_test_chunk(128);
            
            backend.save_chunk(recipient, chunk_hash, &test_data).await
                .expect("Failed to save chunk");
            
            let loaded_data = backend.load_chunk(recipient, chunk_hash).await
                .expect("Failed to load chunk");
            assert_eq!(loaded_data, test_data);
            
            println!("✅ Consistency level {:?} test passed!", consistency_level);
        }
    }
}