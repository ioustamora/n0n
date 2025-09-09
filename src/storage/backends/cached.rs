use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, StorageError};
use crate::storage::factory::StorageFactory;
use crate::storage::backend::StorageConfig;

/// Configuration for cached cloud storage
#[derive(Debug, Clone)]
pub struct CachedCloudConfig {
    /// The underlying cloud storage backend configuration
    pub cloud_config: StorageConfig,
    /// Local cache directory
    pub cache_dir: String,
    /// Maximum cache size in bytes (0 = unlimited)
    pub max_cache_size: u64,
    /// Cache eviction policy
    pub eviction_policy: CacheEvictionPolicy,
    /// Write-through vs write-back caching
    pub write_policy: CacheWritePolicy,
    /// How long to keep items in cache without access (in seconds)
    pub ttl_seconds: Option<u64>,
    /// Whether to preload frequently accessed items
    pub enable_prefetch: bool,
}

#[derive(Debug, Clone)]
pub enum CacheEvictionPolicy {
    /// Least Recently Used
    Lru,
    /// Least Frequently Used
    Lfu,
    /// First In, First Out
    Fifo,
    /// Time-based eviction only
    TtlOnly,
}

#[derive(Debug, Clone)]
pub enum CacheWritePolicy {
    /// Write to cache and cloud storage simultaneously
    WriteThrough,
    /// Write to cache first, sync to cloud later
    WriteBack,
    /// Write to cloud first, then cache
    WriteAround,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    data: Vec<u8>,
    metadata: ChunkMetadata,
    last_accessed: DateTime<Utc>,
    access_count: u64,
    created_at: DateTime<Utc>,
    dirty: bool, // For write-back policy
}

/// Cached Cloud Storage backend
/// Provides local caching with cloud storage backing for improved performance
pub struct CachedCloudBackend {
    cloud_backend: Arc<dyn StorageBackend>,
    config: CachedCloudConfig,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    cache_size: Arc<RwLock<u64>>,
    cache_stats: Arc<RwLock<CacheStats>>,
}

#[derive(Debug, Default)]
struct CacheStats {
    hits: u64,
    misses: u64,
    evictions: u64,
    writes: u64,
    syncs: u64,
    errors: u64,
}

impl CachedCloudBackend {
    pub async fn new(config: CachedCloudConfig) -> Result<Self> {
        // Create the underlying cloud storage backend
        let cloud_backend = StorageFactory::create_backend(config.cloud_config.clone()).await?;
        
        // Validate cache directory
        if config.cache_dir.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "Cache directory path cannot be empty".to_string(),
            }.into());
        }
        
        // Create cache directory if it doesn't exist
        tokio::fs::create_dir_all(&config.cache_dir).await
            .map_err(|e| StorageError::ConfigurationError {
                message: format!("Failed to create cache directory: {}", e),
            })?;
        
        Ok(Self {
            cloud_backend,
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_size: Arc::new(RwLock::new(0)),
            cache_stats: Arc::new(RwLock::new(CacheStats::default())),
        })
    }
    
    /// Generate cache key for a chunk
    fn get_cache_key(&self, recipient: &str, chunk_hash: &str) -> String {
        format!("{}:{}", recipient, chunk_hash)
    }
    
    /// Check if cache needs eviction and perform it
    async fn maybe_evict_cache(&self) -> Result<()> {
        if self.config.max_cache_size == 0 {
            return Ok(()); // Unlimited cache
        }
        
        let current_size = *self.cache_size.read().await;
        if current_size <= self.config.max_cache_size {
            return Ok(());
        }
        
        let mut cache = self.cache.write().await;
        let mut cache_size = self.cache_size.write().await;
        let mut stats = self.cache_stats.write().await;
        
        // Calculate how much to evict (evict 25% when over limit)
        let target_size = (self.config.max_cache_size as f64 * 0.75) as u64;
        let mut to_evict = Vec::new();
        
        match self.config.eviction_policy {
            CacheEvictionPolicy::Lru => {
                let mut entries: Vec<_> = cache.iter().collect();
                entries.sort_by_key(|(_, entry)| entry.last_accessed);
                
                let mut evicted_size = 0u64;
                for (key, entry) in entries {
                    if current_size - evicted_size <= target_size {
                        break;
                    }
                    to_evict.push(key.clone());
                    evicted_size += entry.data.len() as u64;
                }
            }
            CacheEvictionPolicy::Lfu => {
                let mut entries: Vec<_> = cache.iter().collect();
                entries.sort_by_key(|(_, entry)| entry.access_count);
                
                let mut evicted_size = 0u64;
                for (key, entry) in entries {
                    if current_size - evicted_size <= target_size {
                        break;
                    }
                    to_evict.push(key.clone());
                    evicted_size += entry.data.len() as u64;
                }
            }
            CacheEvictionPolicy::Fifo => {
                let mut entries: Vec<_> = cache.iter().collect();
                entries.sort_by_key(|(_, entry)| entry.created_at);
                
                let mut evicted_size = 0u64;
                for (key, entry) in entries {
                    if current_size - evicted_size <= target_size {
                        break;
                    }
                    to_evict.push(key.clone());
                    evicted_size += entry.data.len() as u64;
                }
            }
            CacheEvictionPolicy::TtlOnly => {
                // Only evict expired entries
                let now = Utc::now();
                if let Some(ttl) = self.config.ttl_seconds {
                    for (key, entry) in cache.iter() {
                        let age = now.signed_duration_since(entry.last_accessed).num_seconds() as u64;
                        if age > ttl {
                            to_evict.push(key.clone());
                        }
                    }
                }
            }
        }
        
        // Perform eviction
        for key in &to_evict {
            if let Some(entry) = cache.remove(key) {
                *cache_size -= entry.data.len() as u64;
                stats.evictions += 1;
                
                // If entry is dirty (write-back), sync to cloud first
                if entry.dirty {
                    let (recipient, chunk_hash) = self.parse_cache_key(key)?;
                    if let Err(e) = self.sync_to_cloud(&recipient, &chunk_hash, &entry).await {
                        eprintln!("Failed to sync dirty cache entry to cloud: {}", e);
                        stats.errors += 1;
                    } else {
                        stats.syncs += 1;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Parse cache key back to recipient and chunk_hash
    fn parse_cache_key(&self, key: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = key.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid cache key format: {}", key));
        }
        Ok((parts[0].to_string(), parts[1].to_string()))
    }
    
    /// Sync a dirty cache entry to the cloud
    async fn sync_to_cloud(&self, recipient: &str, chunk_hash: &str, entry: &CacheEntry) -> Result<()> {
        // Save chunk data
        self.cloud_backend.save_chunk(recipient, chunk_hash, &entry.data).await?;
        
        // Save metadata
        self.cloud_backend.save_metadata(recipient, chunk_hash, &entry.metadata).await?;
        
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for CachedCloudBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        let cache_key = self.get_cache_key(recipient, chunk_hash);
        let now = Utc::now();
        
        match self.config.write_policy {
            CacheWritePolicy::WriteThrough => {
                // Write to cloud first
                let result = self.cloud_backend.save_chunk(recipient, chunk_hash, data).await?;
                
                // Then add to cache
                let mut cache = self.cache.write().await;
                let mut cache_size = self.cache_size.write().await;
                let mut stats = self.cache_stats.write().await;
                
                let entry = CacheEntry {
                    data: data.to_vec(),
                    metadata: ChunkMetadata {
                        nonce: "".to_string(), // Will be set when metadata is saved
                        sender_public_key: "".to_string(),
                        size: data.len() as u64,
                        created_at: now,
                    },
                    last_accessed: now,
                    access_count: 1,
                    created_at: now,
                    dirty: false,
                };
                
                *cache_size += data.len() as u64;
                cache.insert(cache_key, entry);
                stats.writes += 1;
                
                // Check if we need to evict
                drop(cache);
                drop(cache_size);
                drop(stats);
                self.maybe_evict_cache().await?;
                
                Ok(result)
            }
            CacheWritePolicy::WriteBack => {
                // Write to cache first
                let mut cache = self.cache.write().await;
                let mut cache_size = self.cache_size.write().await;
                let mut stats = self.cache_stats.write().await;
                
                let entry = CacheEntry {
                    data: data.to_vec(),
                    metadata: ChunkMetadata {
                        nonce: "".to_string(),
                        sender_public_key: "".to_string(),
                        size: data.len() as u64,
                        created_at: now,
                    },
                    last_accessed: now,
                    access_count: 1,
                    created_at: now,
                    dirty: true, // Mark as dirty for later sync
                };
                
                *cache_size += data.len() as u64;
                cache.insert(cache_key, entry);
                stats.writes += 1;
                
                // Check if we need to evict
                drop(cache);
                drop(cache_size);
                drop(stats);
                self.maybe_evict_cache().await?;
                
                Ok(chunk_hash.to_string())
            }
            CacheWritePolicy::WriteAround => {
                // Write directly to cloud, bypass cache
                self.cloud_backend.save_chunk(recipient, chunk_hash, data).await
            }
        }
    }
    
    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        let cache_key = self.get_cache_key(recipient, chunk_hash);
        
        // Update metadata in cache if present
        {
            let mut cache = self.cache.write().await;
            if let Some(entry) = cache.get_mut(&cache_key) {
                entry.metadata = metadata.clone();
                if matches!(self.config.write_policy, CacheWritePolicy::WriteBack) {
                    entry.dirty = true;
                }
            }
        }
        
        // Save to cloud (except for write-back policy)
        match self.config.write_policy {
            CacheWritePolicy::WriteBack => Ok(()),
            _ => self.cloud_backend.save_metadata(recipient, chunk_hash, metadata).await,
        }
    }
    
    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        let cache_key = self.get_cache_key(recipient, chunk_hash);
        let now = Utc::now();
        
        // Check cache first
        {
            let mut cache = self.cache.write().await;
            let mut stats = self.cache_stats.write().await;
            
            if let Some(entry) = cache.get_mut(&cache_key) {
                // Cache hit
                entry.last_accessed = now;
                entry.access_count += 1;
                stats.hits += 1;
                
                return Ok(entry.data.clone());
            } else {
                stats.misses += 1;
            }
        }
        
        // Cache miss - load from cloud
        let data = self.cloud_backend.load_chunk(recipient, chunk_hash).await?;
        let metadata = self.cloud_backend.load_metadata(recipient, chunk_hash).await
            .unwrap_or_else(|_| ChunkMetadata {
                nonce: "".to_string(),
                sender_public_key: "".to_string(),
                size: data.len() as u64,
                created_at: now,
            });
        
        // Add to cache
        {
            let mut cache = self.cache.write().await;
            let mut cache_size = self.cache_size.write().await;
            
            let entry = CacheEntry {
                data: data.clone(),
                metadata,
                last_accessed: now,
                access_count: 1,
                created_at: now,
                dirty: false,
            };
            
            *cache_size += data.len() as u64;
            cache.insert(cache_key, entry);
        }
        
        // Check if we need to evict
        self.maybe_evict_cache().await?;
        
        Ok(data)
    }
    
    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        let cache_key = self.get_cache_key(recipient, chunk_hash);
        let now = Utc::now();
        
        // Check cache first
        {
            let mut cache = self.cache.write().await;
            let mut stats = self.cache_stats.write().await;
            
            if let Some(entry) = cache.get_mut(&cache_key) {
                // Cache hit
                entry.last_accessed = now;
                entry.access_count += 1;
                stats.hits += 1;
                
                return Ok(entry.metadata.clone());
            } else {
                stats.misses += 1;
            }
        }
        
        // Cache miss - load from cloud
        self.cloud_backend.load_metadata(recipient, chunk_hash).await
    }
    
    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        // Always get from cloud for consistency
        self.cloud_backend.list_chunks(recipient).await
    }
    
    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let cache_key = self.get_cache_key(recipient, chunk_hash);
        
        // Remove from cache
        {
            let mut cache = self.cache.write().await;
            let mut cache_size = self.cache_size.write().await;
            
            if let Some(entry) = cache.remove(&cache_key) {
                *cache_size -= entry.data.len() as u64;
            }
        }
        
        // Delete from cloud
        self.cloud_backend.delete_chunk(recipient, chunk_hash).await
    }
    
    async fn test_connection(&self) -> Result<()> {
        self.cloud_backend.test_connection().await
    }
    
    fn backend_type(&self) -> StorageType {
        StorageType::CachedCloud
    }
    
    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "CachedCloud".to_string());
        info.insert("cache_dir".to_string(), self.config.cache_dir.clone());
        info.insert("max_cache_size".to_string(), self.config.max_cache_size.to_string());
        info.insert("eviction_policy".to_string(), format!("{:?}", self.config.eviction_policy));
        info.insert("write_policy".to_string(), format!("{:?}", self.config.write_policy));
        
        if let Some(ttl) = self.config.ttl_seconds {
            info.insert("ttl_seconds".to_string(), ttl.to_string());
        }
        
        info.insert("enable_prefetch".to_string(), self.config.enable_prefetch.to_string());
        
        // Add cloud backend info
        let cloud_info = self.cloud_backend.get_info();
        for (key, value) in cloud_info {
            info.insert(format!("cloud_{}", key), value);
        }
        
        info
    }
    
    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();
        
        // Check cloud backend health
        let cloud_health = self.cloud_backend.health_check().await?;
        for (key, value) in cloud_health {
            health.insert(format!("cloud_{}", key), value);
        }
        
        // Add cache statistics
        let stats = self.cache_stats.read().await;
        let cache_size = *self.cache_size.read().await;
        let cache_count = self.cache.read().await.len();
        
        health.insert("cache_size_bytes".to_string(), cache_size.to_string());
        health.insert("cache_entries".to_string(), cache_count.to_string());
        health.insert("cache_hits".to_string(), stats.hits.to_string());
        health.insert("cache_misses".to_string(), stats.misses.to_string());
        health.insert("cache_evictions".to_string(), stats.evictions.to_string());
        health.insert("cache_writes".to_string(), stats.writes.to_string());
        health.insert("cache_syncs".to_string(), stats.syncs.to_string());
        health.insert("cache_errors".to_string(), stats.errors.to_string());
        
        let hit_rate = if stats.hits + stats.misses > 0 {
            (stats.hits as f64 / (stats.hits + stats.misses) as f64 * 100.0).round()
        } else {
            0.0
        };
        health.insert("cache_hit_rate_percent".to_string(), hit_rate.to_string());
        
        health.insert("cache_status".to_string(), "healthy".to_string());
        
        Ok(health)
    }
    
    async fn save_chunks_batch(&self, recipient: &str, chunks: Vec<(String, Vec<u8>, ChunkMetadata)>) -> Result<Vec<String>> {
        // For batch operations, we optimize based on write policy
        match self.config.write_policy {
            CacheWritePolicy::WriteThrough => {
                // Use cloud backend's batch operation
                let result = self.cloud_backend.save_chunks_batch(recipient, chunks.clone()).await?;
                
                // Add all to cache
                let now = Utc::now();
                {
                    let mut cache = self.cache.write().await;
                    let mut cache_size = self.cache_size.write().await;
                    let mut stats = self.cache_stats.write().await;
                    
                    for (hash, data, metadata) in chunks {
                        let cache_key = self.get_cache_key(recipient, &hash);
                        let entry = CacheEntry {
                            data: data.clone(),
                            metadata,
                            last_accessed: now,
                            access_count: 1,
                            created_at: now,
                            dirty: false,
                        };
                        
                        *cache_size += data.len() as u64;
                        cache.insert(cache_key, entry);
                        stats.writes += 1;
                    }
                }
                
                self.maybe_evict_cache().await?;
                Ok(result)
            }
            _ => {
                // Fall back to individual operations for other policies
                let mut results = Vec::new();
                for (hash, data, metadata) in chunks {
                    self.save_chunk(recipient, &hash, &data).await?;
                    self.save_metadata(recipient, &hash, &metadata).await?;
                    results.push(hash);
                }
                Ok(results)
            }
        }
    }
}

impl Clone for CachedCloudBackend {
    fn clone(&self) -> Self {
        Self {
            cloud_backend: self.cloud_backend.clone(),
            config: self.config.clone(),
            cache: self.cache.clone(),
            cache_size: self.cache_size.clone(),
            cache_stats: self.cache_stats.clone(),
        }
    }
}