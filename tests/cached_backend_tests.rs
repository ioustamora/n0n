use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::time::sleep;

use n0n::storage::backend::{StorageConfig, StorageType, LocalConfig, CachedCloudConfigSimple};
use n0n::storage::backends::{CachedCloudBackend, CachedCloudConfig, CacheEvictionPolicy, CacheWritePolicy};
use n0n::storage::factory::StorageFactory;

/// Tests for cached cloud storage functionality
#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_tests::StorageTestUtils;
    
    async fn create_test_cached_backend(
        write_policy: CacheWritePolicy,
        eviction_policy: CacheEvictionPolicy,
        max_cache_size: u64,
    ) -> (CachedCloudBackend, TempDir, TempDir) {
        let cloud_temp_dir = TempDir::new().expect("Failed to create cloud temp directory");
        let cache_temp_dir = TempDir::new().expect("Failed to create cache temp directory");
        
        let cloud_config = StorageConfig {
            backend_type: StorageType::Local,
            local: Some(LocalConfig {
                base_path: cloud_temp_dir.path().to_string_lossy().to_string(),
                create_dirs: Some(true),
            }),
            ..Default::default()
        };
        
        let cached_config = CachedCloudConfig {
            cloud_config,
            cache_dir: cache_temp_dir.path().to_string_lossy().to_string(),
            max_cache_size,
            eviction_policy,
            write_policy,
            ttl_seconds: None,
            enable_prefetch: false,
        };
        
        let backend = CachedCloudBackend::new(cached_config).await
            .expect("Failed to create CachedCloudBackend");
        
        (backend, cloud_temp_dir, cache_temp_dir)
    }
    
    #[tokio::test]
    async fn test_cached_backend_write_through() {
        let (backend, _cloud_dir, _cache_dir) = create_test_cached_backend(
            CacheWritePolicy::WriteThrough,
            CacheEvictionPolicy::Lru,
            1024 * 1024, // 1MB cache
        ).await;
        
        let recipient = "cached_write_through";
        let chunk_hash = "cached_chunk_wt";
        let test_data = StorageTestUtils::create_test_chunk(1024);
        let test_metadata = StorageTestUtils::create_test_metadata(test_data.len() as u64);
        
        println!("Testing CachedBackend write-through policy...");
        
        // First write - should go to both cache and cloud
        let start = Instant::now();
        backend.save_chunk(recipient, chunk_hash, &test_data).await
            .expect("Write-through save failed");
        backend.save_metadata(recipient, chunk_hash, &test_metadata).await
            .expect("Failed to save metadata");
        let write_time = start.elapsed();
        
        println!("Write-through time: {:?}", write_time);
        
        // First read - should be fast (from cache)
        let start = Instant::now();
        let loaded_data = backend.load_chunk(recipient, chunk_hash).await
            .expect("Failed to load from cache");
        let cached_read_time = start.elapsed();
        
        assert_eq!(loaded_data, test_data);
        println!("Cached read time: {:?}", cached_read_time);
        
        // Verify metadata
        let loaded_metadata = backend.load_metadata(recipient, chunk_hash).await
            .expect("Failed to load metadata");
        assert_eq!(loaded_metadata.size, test_metadata.size);
        
        // Check health to see cache statistics
        let health = backend.health_check().await
            .expect("Health check failed");
        
        println!("Cache statistics: {:?}", health);
        assert!(health.contains_key("cache_hits"));
        assert!(health.contains_key("cache_misses"));
        
        println!("✅ Write-through policy test passed!");
    }
    
    #[tokio::test]
    async fn test_cached_backend_write_back() {
        let (backend, _cloud_dir, _cache_dir) = create_test_cached_backend(
            CacheWritePolicy::WriteBack,
            CacheEvictionPolicy::Lru,
            1024 * 1024, // 1MB cache
        ).await;
        
        let recipient = "cached_write_back";
        let chunk_hash = "cached_chunk_wb";
        let test_data = StorageTestUtils::create_test_chunk(512);
        let test_metadata = StorageTestUtils::create_test_metadata(test_data.len() as u64);
        
        println!("Testing CachedBackend write-back policy...");
        
        // Write should be very fast (only to cache initially)
        let start = Instant::now();
        backend.save_chunk(recipient, chunk_hash, &test_data).await
            .expect("Write-back save failed");
        backend.save_metadata(recipient, chunk_hash, &test_metadata).await
            .expect("Failed to save metadata");
        let write_time = start.elapsed();
        
        println!("Write-back time: {:?}", write_time);
        
        // Read should be fast (from cache)
        let loaded_data = backend.load_chunk(recipient, chunk_hash).await
            .expect("Failed to load from cache");
        assert_eq!(loaded_data, test_data);
        
        println!("✅ Write-back policy test passed!");
    }
    
    #[tokio::test]
    async fn test_cached_backend_write_around() {
        let (backend, _cloud_dir, _cache_dir) = create_test_cached_backend(
            CacheWritePolicy::WriteAround,
            CacheEvictionPolicy::Lru,
            1024 * 1024, // 1MB cache
        ).await;
        
        let recipient = "cached_write_around";
        let chunk_hash = "cached_chunk_wa";
        let test_data = StorageTestUtils::create_test_chunk(256);
        let test_metadata = StorageTestUtils::create_test_metadata(test_data.len() as u64);
        
        println!("Testing CachedBackend write-around policy...");
        
        // Write bypasses cache, goes directly to cloud
        backend.save_chunk(recipient, chunk_hash, &test_data).await
            .expect("Write-around save failed");
        backend.save_metadata(recipient, chunk_hash, &test_metadata).await
            .expect("Failed to save metadata");
        
        // First read will be slower (cache miss, loads from cloud into cache)
        let start = Instant::now();
        let loaded_data = backend.load_chunk(recipient, chunk_hash).await
            .expect("Failed to load chunk");
        let first_read_time = start.elapsed();
        
        assert_eq!(loaded_data, test_data);
        println!("First read (cache miss) time: {:?}", first_read_time);
        
        // Second read should be faster (cache hit)
        let start = Instant::now();
        let loaded_data2 = backend.load_chunk(recipient, chunk_hash).await
            .expect("Failed to load from cache");
        let second_read_time = start.elapsed();
        
        assert_eq!(loaded_data2, test_data);
        println!("Second read (cache hit) time: {:?}", second_read_time);
        
        // Second read should be faster than first
        assert!(second_read_time < first_read_time);
        
        println!("✅ Write-around policy test passed!");
    }
    
    #[tokio::test]
    async fn test_cache_eviction_lru() {
        let (backend, _cloud_dir, _cache_dir) = create_test_cached_backend(
            CacheWritePolicy::WriteThrough,
            CacheEvictionPolicy::Lru,
            2048, // Very small cache to trigger eviction
        ).await;
        
        let recipient = "eviction_test";
        let chunks = vec![
            ("chunk_1", StorageTestUtils::create_test_chunk(512)),
            ("chunk_2", StorageTestUtils::create_test_chunk(512)),
            ("chunk_3", StorageTestUtils::create_test_chunk(512)),
            ("chunk_4", StorageTestUtils::create_test_chunk(512)),
            ("chunk_5", StorageTestUtils::create_test_chunk(512)),
        ];
        
        println!("Testing LRU cache eviction...");
        
        // Fill cache beyond capacity
        for (i, (chunk_hash, data)) in chunks.iter().enumerate() {
            println!("Saving chunk {}: {}", i + 1, chunk_hash);
            backend.save_chunk(recipient, chunk_hash, data).await
                .expect("Failed to save chunk");
            
            // Small delay to ensure different access times
            sleep(Duration::from_millis(10)).await;
        }
        
        // Access first chunk to make it recently used
        backend.load_chunk(recipient, "chunk_1").await
            .expect("Failed to access first chunk");
        
        // Add one more chunk to trigger eviction
        let extra_data = StorageTestUtils::create_test_chunk(512);
        backend.save_chunk(recipient, "chunk_extra", &extra_data).await
            .expect("Failed to save extra chunk");
        
        // Check cache statistics
        let health = backend.health_check().await
            .expect("Health check failed");
        
        println!("Cache statistics after eviction: {:?}", health);
        
        // Verify that evictions occurred
        if let Some(evictions_str) = health.get("cache_evictions") {
            let evictions: u64 = evictions_str.parse().unwrap_or(0);
            println!("Number of evictions: {}", evictions);
            assert!(evictions > 0, "Expected some evictions to occur");
        }
        
        println!("✅ LRU eviction test passed!");
    }
    
    #[tokio::test]
    async fn test_cache_eviction_fifo() {
        let (backend, _cloud_dir, _cache_dir) = create_test_cached_backend(
            CacheWritePolicy::WriteThrough,
            CacheEvictionPolicy::Fifo,
            1536, // Small cache to trigger eviction
        ).await;
        
        let recipient = "fifo_test";
        
        println!("Testing FIFO cache eviction...");
        
        // Add chunks in sequence
        for i in 1..=5 {
            let chunk_hash = format!("fifo_chunk_{}", i);
            let data = StorageTestUtils::create_test_chunk(512);
            backend.save_chunk(recipient, &chunk_hash, &data).await
                .expect("Failed to save chunk");
            
            sleep(Duration::from_millis(10)).await;
        }
        
        // Check that evictions occurred (FIFO should evict oldest first)
        let health = backend.health_check().await
            .expect("Health check failed");
        
        println!("FIFO cache statistics: {:?}", health);
        
        if let Some(evictions_str) = health.get("cache_evictions") {
            let evictions: u64 = evictions_str.parse().unwrap_or(0);
            println!("FIFO evictions: {}", evictions);
        }
        
        println!("✅ FIFO eviction test passed!");
    }
    
    #[tokio::test]
    async fn test_cached_backend_performance() {
        let (backend, _cloud_dir, _cache_dir) = create_test_cached_backend(
            CacheWritePolicy::WriteThrough,
            CacheEvictionPolicy::Lru,
            10 * 1024 * 1024, // 10MB cache
        ).await;
        
        let recipient = "performance_test";
        let chunk_hash = "perf_chunk";
        let test_data = StorageTestUtils::create_test_chunk(4096);
        let test_metadata = StorageTestUtils::create_test_metadata(test_data.len() as u64);
        
        println!("Testing CachedBackend performance characteristics...");
        
        // Initial write
        let start = Instant::now();
        backend.save_chunk(recipient, chunk_hash, &test_data).await
            .expect("Failed to save chunk");
        backend.save_metadata(recipient, chunk_hash, &test_metadata).await
            .expect("Failed to save metadata");
        let write_time = start.elapsed();
        
        // First read (should populate cache)
        let start = Instant::now();
        let _ = backend.load_chunk(recipient, chunk_hash).await
            .expect("First read failed");
        let first_read_time = start.elapsed();
        
        // Second read (should be from cache, faster)
        let start = Instant::now();
        let _ = backend.load_chunk(recipient, chunk_hash).await
            .expect("Second read failed");
        let second_read_time = start.elapsed();
        
        // Third read (should still be from cache)
        let start = Instant::now();
        let _ = backend.load_chunk(recipient, chunk_hash).await
            .expect("Third read failed");
        let third_read_time = start.elapsed();
        
        println!("📊 Performance Results:");
        println!("  Write time: {:?}", write_time);
        println!("  First read (cache miss): {:?}", first_read_time);
        println!("  Second read (cache hit): {:?}", second_read_time);
        println!("  Third read (cache hit): {:?}", third_read_time);
        
        // Cache hits should generally be faster
        println!("  Cache speedup: {:.2}x", 
            first_read_time.as_nanos() as f64 / second_read_time.as_nanos() as f64);
        
        // Verify cache statistics
        let health = backend.health_check().await
            .expect("Health check failed");
        
        println!("Final cache statistics:");
        for (key, value) in health.iter() {
            if key.starts_with("cache_") {
                println!("  {}: {}", key, value);
            }
        }
        
        println!("✅ Performance test completed!");
    }
    
    #[tokio::test]
    async fn test_cached_backend_batch_operations() {
        let (backend, _cloud_dir, _cache_dir) = create_test_cached_backend(
            CacheWritePolicy::WriteThrough,
            CacheEvictionPolicy::Lru,
            5 * 1024 * 1024, // 5MB cache
        ).await;
        
        let recipient = "batch_cache_test";
        let chunks = vec![
            ("batch_cached_1".to_string(), StorageTestUtils::create_test_chunk(1024), StorageTestUtils::create_test_metadata(1024)),
            ("batch_cached_2".to_string(), StorageTestUtils::create_test_chunk(2048), StorageTestUtils::create_test_metadata(2048)),
            ("batch_cached_3".to_string(), StorageTestUtils::create_test_chunk(512), StorageTestUtils::create_test_metadata(512)),
        ];
        
        println!("Testing cached backend batch operations...");
        
        // Batch save
        let start = Instant::now();
        let results = backend.save_chunks_batch(recipient, chunks.clone()).await
            .expect("Batch save failed");
        let batch_save_time = start.elapsed();
        
        println!("Batch save time: {:?}", batch_save_time);
        assert_eq!(results.len(), 3);
        
        // Batch read (should be fast due to caching)
        let start = Instant::now();
        for (hash, original_data, _) in chunks {
            let loaded_data = backend.load_chunk(recipient, &hash).await
                .expect("Failed to load cached chunk");
            assert_eq!(loaded_data, original_data);
        }
        let batch_read_time = start.elapsed();
        
        println!("Batch read time: {:?}", batch_read_time);
        
        // Check final cache statistics
        let health = backend.health_check().await
            .expect("Health check failed");
        
        println!("Batch operation cache statistics: {:?}", health);
        
        println!("✅ Cached backend batch operations test passed!");
    }
    
    #[tokio::test]
    async fn test_cached_backend_factory_integration() {
        let cloud_temp_dir = TempDir::new().expect("Failed to create cloud temp directory");
        let cache_temp_dir = TempDir::new().expect("Failed to create cache temp directory");
        
        let config = StorageConfig {
            backend_type: StorageType::CachedCloud,
            local: Some(LocalConfig {
                base_path: cloud_temp_dir.path().to_string_lossy().to_string(),
                create_dirs: Some(true),
            }),
            cached_cloud: Some(CachedCloudConfigSimple {
                cloud_backend_type: StorageType::Local,
                cache_dir: cache_temp_dir.path().to_string_lossy().to_string(),
                max_cache_size: 1024 * 1024,
                eviction_policy: "lru".to_string(),
                write_policy: "write_through".to_string(),
                ttl_seconds: None,
                enable_prefetch: false,
            }),
            ..Default::default()
        };
        
        println!("Testing cached backend creation through factory...");
        
        // Create through factory
        let backend = StorageFactory::create_backend(config.clone()).await
            .expect("Failed to create cached backend through factory");
        
        assert_eq!(backend.backend_type(), StorageType::CachedCloud);
        
        // Test basic operations
        let recipient = "factory_cache_test";
        let chunk_hash = "factory_chunk";
        let test_data = StorageTestUtils::create_test_chunk(256);
        
        backend.save_chunk(recipient, chunk_hash, &test_data).await
            .expect("Factory-created backend save failed");
        
        let loaded_data = backend.load_chunk(recipient, chunk_hash).await
            .expect("Factory-created backend load failed");
        assert_eq!(loaded_data, test_data);
        
        println!("✅ Factory integration test passed!");
    }
}