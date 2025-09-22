use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use futures::future::join_all;

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, ReplicationConfig, ConsistencyLevel, ReplicationStrategy, StorageError};
use crate::storage::factory::StorageFactory;

/// Multi-cloud replication backend
/// Replicates data across multiple storage backends for redundancy and disaster recovery
pub struct MultiCloudBackend {
    primary_backend: Arc<dyn StorageBackend>,
    replica_backends: Vec<Arc<dyn StorageBackend>>,
    config: ReplicationConfig,
}

impl MultiCloudBackend {
    pub async fn new(config: ReplicationConfig, all_configs: HashMap<StorageType, crate::storage::backend::StorageConfig>) -> Result<Self> {
        // Get primary backend config
        let primary_config = all_configs.get(&config.primary_backend)
            .ok_or_else(|| StorageError::ConfigurationError {
                message: format!("Primary backend config not found: {:?}", config.primary_backend),
            })?;
        
        // Create primary backend
        let primary_backend = StorageFactory::create_backend(primary_config.clone()).await?;
        
        // Create replica backends
        let mut replica_backends = Vec::new();
        for replica_type in &config.replica_backends {
            if let Some(replica_config) = all_configs.get(replica_type) {
                match StorageFactory::create_backend(replica_config.clone()).await {
                    Ok(backend) => replica_backends.push(backend),
                    Err(e) => {
                        log::warn!("Failed to create replica backend {:?}: {}", replica_type, e);
                        // Continue with other replicas - partial replication is better than none
                    }
                }
            } else {
                log::warn!("Replica backend config not found: {:?}", replica_type);
            }
        }
        
        if replica_backends.is_empty() {
            return Err(StorageError::ConfigurationError {
                message: "No replica backends could be created".to_string(),
            }.into());
        }
        
        Ok(Self {
            primary_backend,
            replica_backends,
            config,
        })
    }
    
    /// Execute operation on primary backend
    async fn execute_on_primary<T, F, Fut>(&self, operation: F) -> Result<T>
    where
        F: FnOnce(Arc<dyn StorageBackend>) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        operation(self.primary_backend.clone()).await
    }
    
    /// Execute operation on replica backends (fire-and-forget for async replication)
    async fn replicate_to_backups<F, Fut>(&self, operation: F) -> Vec<Result<()>>
    where
        F: Clone,
        F: FnOnce(Arc<dyn StorageBackend>) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let tasks = self.replica_backends.iter().map(|backend| {
            let op = operation.clone();
            let backend = backend.clone();
            async move { op(backend).await }
        });
        
        join_all(tasks).await
    }
    
    /// Execute operation on replica backends and wait for results
    async fn execute_on_replicas<T, F, Fut>(&self, operation: F) -> Vec<Result<T>>
    where
        F: Clone,
        F: FnOnce(Arc<dyn StorageBackend>) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let tasks = self.replica_backends.iter().map(|backend| {
            let op = operation.clone();
            let backend = backend.clone();
            async move { op(backend).await }
        });
        
        join_all(tasks).await
    }
    
    /// Check if we have enough successful operations for quorum
    fn check_quorum(&self, successful_count: usize) -> bool {
        let total_backends = self.replica_backends.len() + 1; // +1 for primary
        successful_count > total_backends / 2
    }
    
    /// Get the first successful result from multiple backends
    fn get_first_success<T>(results: Vec<Result<T>>) -> Result<T> {
        for result in results {
            if result.is_ok() {
                return result;
            }
        }
        Err(anyhow!("All operations failed"))
    }
}

#[async_trait]
impl StorageBackend for MultiCloudBackend {
    async fn save_chunk(&self, recipient: &str, chunk_hash: &str, data: &[u8]) -> Result<String> {
        match self.config.replication_strategy {
            ReplicationStrategy::AsyncReplication => {
                // Save to primary first
                let result = self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    let data = data.to_vec();
                    async move {
                        backend.save_chunk(&recipient, &chunk_hash, &data).await
                    }
                }).await?;
                
                // Replicate to backups asynchronously (fire-and-forget)
                let recipient = recipient.to_string();
                let chunk_hash = chunk_hash.to_string();
                let data = data.to_vec();
                let backup_backends = self.replica_backends.clone();

                tokio::spawn(async move {
                    // Replicate to backup backends
                    let futures = backup_backends.into_iter().map(|backend| {
                        let recipient = recipient.clone();
                        let chunk_hash = chunk_hash.clone();
                        let data = data.clone();
                        async move {
                            backend.save_chunk(&recipient, &chunk_hash, &data).await.map(|_| ())
                        }
                    });
                    let _results = join_all(futures).await;
                    // Log failures but don't fail the operation
                });
                
                Ok(result)
            }
            
            ReplicationStrategy::SyncReplication => {
                // Save to primary
                let primary_result = self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    let data = data.to_vec();
                    async move {
                        backend.save_chunk(&recipient, &chunk_hash, &data).await
                    }
                }).await;
                
                // Save to all replicas
                let replica_results = self.execute_on_replicas(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    let data = data.to_vec();
                    async move {
                        backend.save_chunk(&recipient, &chunk_hash, &data).await.map(|_| ())
                    }
                }).await;
                
                // Check if primary succeeded
                let result = primary_result?;
                
                // Log replica failures but don't fail the operation
                for (i, replica_result) in replica_results.iter().enumerate() {
                    if let Err(e) = replica_result {
                        log::warn!("Replica {} failed to save chunk: {}", i, e);
                    }
                }
                
                Ok(result)
            }
            
            ReplicationStrategy::QuorumWrite => {
                // Execute on primary and all replicas
                let mut all_results = vec![self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    let data = data.to_vec();
                    async move {
                        backend.save_chunk(&recipient, &chunk_hash, &data).await
                    }
                }).await];
                
                let replica_results = self.execute_on_replicas(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    let data = data.to_vec();
                    async move {
                        backend.save_chunk(&recipient, &chunk_hash, &data).await
                    }
                }).await;
                
                all_results.extend(replica_results);
                
                // Count successful operations
                let successful_count = all_results.iter().filter(|r| r.is_ok()).count();
                
                if self.check_quorum(successful_count) {
                    // Return the first successful result
                    Self::get_first_success(all_results)
                } else {
                    Err(anyhow!("Quorum not reached for save operation"))
                }
            }
        }
    }
    
    async fn save_metadata(&self, recipient: &str, chunk_hash: &str, metadata: &ChunkMetadata) -> Result<()> {
        match self.config.replication_strategy {
            ReplicationStrategy::AsyncReplication => {
                // Save to primary first
                self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    let metadata = metadata.clone();
                    async move {
                        backend.save_metadata(&recipient, &chunk_hash, &metadata).await
                    }
                }).await?;
                
                // Replicate to backups asynchronously
                let recipient = recipient.to_string();
                let chunk_hash = chunk_hash.to_string();
                let metadata = metadata.clone();
                let backup_backends = self.replica_backends.clone();

                tokio::spawn(async move {
                    // Replicate to backup backends
                    let futures = backup_backends.into_iter().map(|backend| {
                        let recipient = recipient.clone();
                        let chunk_hash = chunk_hash.clone();
                        let metadata = metadata.clone();
                        async move {
                            backend.save_metadata(&recipient, &chunk_hash, &metadata).await
                        }
                    });
                    let _results = join_all(futures).await;
                });
                
                Ok(())
            }
            
            ReplicationStrategy::SyncReplication => {
                // Save to primary
                self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    let metadata = metadata.clone();
                    async move {
                        backend.save_metadata(&recipient, &chunk_hash, &metadata).await
                    }
                }).await?;
                
                // Save to all replicas
                let _replica_results = self.execute_on_replicas(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    let metadata = metadata.clone();
                    async move {
                        backend.save_metadata(&recipient, &chunk_hash, &metadata).await
                    }
                }).await;
                
                Ok(())
            }
            
            ReplicationStrategy::QuorumWrite => {
                // Similar to save_chunk but for metadata
                let mut all_results = vec![self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    let metadata = metadata.clone();
                    async move {
                        backend.save_metadata(&recipient, &chunk_hash, &metadata).await
                    }
                }).await];
                
                let replica_results = self.execute_on_replicas(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    let metadata = metadata.clone();
                    async move {
                        backend.save_metadata(&recipient, &chunk_hash, &metadata).await
                    }
                }).await;
                
                all_results.extend(replica_results);
                
                let successful_count = all_results.iter().filter(|r| r.is_ok()).count();
                
                if self.check_quorum(successful_count) {
                    Ok(())
                } else {
                    Err(anyhow!("Quorum not reached for metadata save operation"))
                }
            }
        }
    }
    
    async fn load_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<Vec<u8>> {
        match self.config.consistency_level {
            ConsistencyLevel::Eventual => {
                // Try primary first, then replicas
                match self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    async move {
                        backend.load_chunk(&recipient, &chunk_hash).await
                    }
                }).await {
                    Ok(data) => Ok(data),
                    Err(_) => {
                        // If primary fails, try replicas
                        let replica_results = self.execute_on_replicas(|backend| {
                            let recipient = recipient.to_string();
                            let chunk_hash = chunk_hash.to_string();
                            async move {
                                backend.load_chunk(&recipient, &chunk_hash).await
                            }
                        }).await;
                        
                        Self::get_first_success(replica_results)
                    }
                }
            }
            
            ConsistencyLevel::Strong => {
                // Always read from primary
                self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    async move {
                        backend.load_chunk(&recipient, &chunk_hash).await
                    }
                }).await
            }
            
            ConsistencyLevel::Quorum => {
                // Read from multiple backends and ensure consistency
                let mut all_results = vec![self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    async move {
                        backend.load_chunk(&recipient, &chunk_hash).await
                    }
                }).await];
                
                let replica_results = self.execute_on_replicas(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    async move {
                        backend.load_chunk(&recipient, &chunk_hash).await
                    }
                }).await;
                
                all_results.extend(replica_results);
                
                // Find the most common successful result (basic consensus)
                let successful_results: Vec<_> = all_results.into_iter()
                    .filter_map(|r| r.ok())
                    .collect();
                
                if self.check_quorum(successful_results.len()) {
                    // Return the first result (in a real system, you'd want more sophisticated consensus)
                    successful_results.into_iter().next()
                        .ok_or_else(|| anyhow!("No successful reads for quorum"))
                } else {
                    Err(anyhow!("Quorum not reached for load operation"))
                }
            }
        }
    }
    
    async fn load_metadata(&self, recipient: &str, chunk_hash: &str) -> Result<ChunkMetadata> {
        // Similar logic to load_chunk but for metadata
        match self.config.consistency_level {
            ConsistencyLevel::Eventual => {
                match self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    async move {
                        backend.load_metadata(&recipient, &chunk_hash).await
                    }
                }).await {
                    Ok(metadata) => Ok(metadata),
                    Err(_) => {
                        let replica_results = self.execute_on_replicas(|backend| {
                            let recipient = recipient.to_string();
                            let chunk_hash = chunk_hash.to_string();
                            async move {
                                backend.load_metadata(&recipient, &chunk_hash).await
                            }
                        }).await;
                        
                        Self::get_first_success(replica_results)
                    }
                }
            }
            
            ConsistencyLevel::Strong => {
                self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    async move {
                        backend.load_metadata(&recipient, &chunk_hash).await
                    }
                }).await
            }
            
            ConsistencyLevel::Quorum => {
                // Simplified quorum read - in practice you'd want better conflict resolution
                self.execute_on_primary(|backend| {
                    let recipient = recipient.to_string();
                    let chunk_hash = chunk_hash.to_string();
                    async move {
                        backend.load_metadata(&recipient, &chunk_hash).await
                    }
                }).await
            }
        }
    }
    
    async fn list_chunks(&self, recipient: &str) -> Result<Vec<String>> {
        // List from primary backend
        self.execute_on_primary(|backend| {
            let recipient = recipient.to_string();
            async move {
                backend.list_chunks(&recipient).await
            }
        }).await
    }
    
    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        // Delete from all backends
        let primary_result = self.execute_on_primary(|backend| {
            let recipient = recipient.to_string();
            let chunk_hash = chunk_hash.to_string();
            async move {
                backend.delete_chunk(&recipient, &chunk_hash).await
            }
        }).await;
        
        let _replica_results = self.execute_on_replicas(|backend| {
            let recipient = recipient.to_string();
            let chunk_hash = chunk_hash.to_string();
            async move {
                backend.delete_chunk(&recipient, &chunk_hash).await
            }
        }).await;
        
        // Return primary result
        primary_result
    }
    
    async fn test_connection(&self) -> Result<()> {
        // Test primary backend
        let primary_result = self.primary_backend.test_connection().await;
        
        // Test replica backends
        let mut replica_failures = 0;
        for (i, backend) in self.replica_backends.iter().enumerate() {
            if let Err(e) = backend.test_connection().await {
                log::warn!("Replica backend {} connection test failed: {}", i, e);
                replica_failures += 1;
            }
        }
        
        // Succeed if primary is healthy
        primary_result?;
        
        if replica_failures == self.replica_backends.len() {
            log::warn!("All replica backends are unhealthy");
        }
        
        Ok(())
    }
    
    fn backend_type(&self) -> StorageType {
        StorageType::MultiCloud
    }
    
    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("backend_type".to_string(), "MultiCloud".to_string());
        info.insert("primary_backend".to_string(), format!("{:?}", self.config.primary_backend));
        info.insert("replica_count".to_string(), self.replica_backends.len().to_string());
        info.insert("consistency_level".to_string(), format!("{:?}", self.config.consistency_level));
        info.insert("replication_strategy".to_string(), format!("{:?}", self.config.replication_strategy));
        
        // Add replica backend types
        let replica_types: Vec<String> = self.config.replica_backends.iter()
            .map(|t| format!("{:?}", t))
            .collect();
        info.insert("replica_backends".to_string(), replica_types.join(", "));
        
        info
    }
    
    async fn health_check(&self) -> Result<HashMap<String, String>> {
        let mut health = HashMap::new();
        
        // Check primary backend
        match self.primary_backend.health_check().await {
            Ok(primary_health) => {
                health.insert("primary_status".to_string(), "healthy".to_string());
                // Add primary backend info with prefix
                for (key, value) in primary_health {
                    health.insert(format!("primary_{}", key), value);
                }
            }
            Err(e) => {
                health.insert("primary_status".to_string(), "unhealthy".to_string());
                health.insert("primary_error".to_string(), e.to_string());
            }
        }
        
        // Check replica backends
        let mut healthy_replicas = 0;
        for (i, backend) in self.replica_backends.iter().enumerate() {
            match backend.health_check().await {
                Ok(replica_health) => {
                    healthy_replicas += 1;
                    health.insert(format!("replica_{}_status", i), "healthy".to_string());
                    // Add key replica info
                    if let Some(backend_type) = replica_health.get("backend_type") {
                        health.insert(format!("replica_{}_type", i), backend_type.clone());
                    }
                }
                Err(e) => {
                    health.insert(format!("replica_{}_status", i), "unhealthy".to_string());
                    health.insert(format!("replica_{}_error", i), e.to_string());
                }
            }
        }
        
        health.insert("healthy_replicas".to_string(), healthy_replicas.to_string());
        health.insert("total_replicas".to_string(), self.replica_backends.len().to_string());
        
        // Overall status
        let primary_healthy = health.get("primary_status") == Some(&"healthy".to_string());
        let has_healthy_replicas = healthy_replicas > 0;
        
        if primary_healthy && has_healthy_replicas {
            health.insert("status".to_string(), "healthy".to_string());
        } else if primary_healthy {
            health.insert("status".to_string(), "degraded".to_string());
            health.insert("warning".to_string(), "No healthy replicas".to_string());
        } else {
            health.insert("status".to_string(), "unhealthy".to_string());
            health.insert("error".to_string(), "Primary backend is unhealthy".to_string());
        }
        
        Ok(health)
    }
}