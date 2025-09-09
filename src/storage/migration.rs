use async_trait::async_trait;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use tokio::time::{sleep, Duration};
use chrono::{DateTime, Utc};

use crate::storage::backend::{StorageBackend, StorageType, ChunkMetadata, StorageError};
use crate::storage::factory::StorageFactory;

/// Migration strategy configuration
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Source backend configuration
    pub source: crate::storage::backend::StorageConfig,
    /// Destination backend configuration  
    pub destination: crate::storage::backend::StorageConfig,
    /// Migration strategy
    pub strategy: MigrationStrategy,
    /// Batch size for processing chunks
    pub batch_size: usize,
    /// Number of concurrent operations
    pub concurrency: usize,
    /// Whether to verify data integrity during migration
    pub verify_integrity: bool,
    /// Whether to delete source data after successful migration
    pub delete_source: bool,
    /// Resume from a specific recipient (for interrupted migrations)
    pub resume_from_recipient: Option<String>,
    /// Maximum retry attempts for failed operations
    pub max_retries: u32,
    /// Delay between retry attempts
    pub retry_delay_ms: u64,
}

/// Migration strategies
#[derive(Debug, Clone)]
pub enum MigrationStrategy {
    /// Copy all data, then optionally delete source
    CopyThenDelete,
    /// Copy data and immediately delete source (streaming migration)
    StreamingMigration,
    /// Synchronize data (bidirectional sync)
    Synchronize,
    /// Verify only (check data integrity without copying)
    VerifyOnly,
}

/// Migration progress information
#[derive(Debug, Clone)]
pub struct MigrationProgress {
    pub total_recipients: usize,
    pub processed_recipients: usize,
    pub total_chunks: usize,
    pub processed_chunks: usize,
    pub failed_chunks: usize,
    pub bytes_transferred: u64,
    pub current_recipient: Option<String>,
    pub start_time: DateTime<Utc>,
    pub last_update: DateTime<Utc>,
    pub estimated_completion: Option<DateTime<Utc>>,
    pub errors: Vec<String>,
}

/// Migration statistics
#[derive(Debug, Default)]
pub struct MigrationStats {
    pub chunks_migrated: AtomicUsize,
    pub chunks_failed: AtomicUsize,
    pub bytes_transferred: AtomicUsize,
    pub operations_per_second: f64,
}

/// Storage backend migration manager
pub struct StorageMigrationManager {
    source: Arc<dyn StorageBackend>,
    destination: Arc<dyn StorageBackend>,
    config: MigrationConfig,
    progress: Arc<std::sync::Mutex<MigrationProgress>>,
    stats: Arc<MigrationStats>,
    cancelled: Arc<AtomicBool>,
}

impl StorageMigrationManager {
    /// Create a new migration manager
    pub async fn new(config: MigrationConfig) -> Result<Self> {
        // Create source and destination backends
        let source = StorageFactory::create_backend(config.source.clone()).await?;
        let destination = StorageFactory::create_backend(config.destination.clone()).await?;

        // Test connections
        source.test_connection().await
            .map_err(|e| anyhow!("Source backend connection failed: {}", e))?;
        destination.test_connection().await
            .map_err(|e| anyhow!("Destination backend connection failed: {}", e))?;

        let progress = Arc::new(std::sync::Mutex::new(MigrationProgress {
            total_recipients: 0,
            processed_recipients: 0,
            total_chunks: 0,
            processed_chunks: 0,
            failed_chunks: 0,
            bytes_transferred: 0,
            current_recipient: None,
            start_time: Utc::now(),
            last_update: Utc::now(),
            estimated_completion: None,
            errors: Vec::new(),
        }));

        Ok(Self {
            source,
            destination,
            config,
            progress,
            stats: Arc::new(MigrationStats::default()),
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Start the migration process
    pub async fn migrate(&self) -> Result<MigrationProgress> {
        match self.config.strategy {
            MigrationStrategy::CopyThenDelete => self.copy_then_delete().await,
            MigrationStrategy::StreamingMigration => self.streaming_migration().await,
            MigrationStrategy::Synchronize => self.synchronize().await,
            MigrationStrategy::VerifyOnly => self.verify_only().await,
        }
    }

    /// Cancel the migration
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Get current migration progress
    pub fn get_progress(&self) -> MigrationProgress {
        self.progress.lock().unwrap().clone()
    }

    /// Get migration statistics
    pub fn get_stats(&self) -> MigrationStats {
        MigrationStats {
            chunks_migrated: AtomicUsize::new(self.stats.chunks_migrated.load(Ordering::Relaxed)),
            chunks_failed: AtomicUsize::new(self.stats.chunks_failed.load(Ordering::Relaxed)),
            bytes_transferred: AtomicUsize::new(self.stats.bytes_transferred.load(Ordering::Relaxed)),
            operations_per_second: self.stats.operations_per_second,
        }
    }

    /// Copy all data then optionally delete source
    async fn copy_then_delete(&self) -> Result<MigrationProgress> {
        println!("Starting copy-then-delete migration...");

        // Phase 1: Discover all recipients and chunks
        let recipients = self.discover_recipients().await?;
        let mut total_chunks = 0;

        // Count total chunks
        for recipient in &recipients {
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(anyhow!("Migration cancelled by user"));
            }
            
            match self.source.list_chunks(recipient).await {
                Ok(chunks) => total_chunks += chunks.len(),
                Err(e) => {
                    self.add_error(format!("Failed to list chunks for {}: {}", recipient, e));
                }
            }
        }

        // Update progress
        {
            let mut progress = self.progress.lock().unwrap();
            progress.total_recipients = recipients.len();
            progress.total_chunks = total_chunks;
        }

        // Phase 2: Copy all data
        for recipient in &recipients {
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(anyhow!("Migration cancelled by user"));
            }

            // Skip if resuming and haven't reached resume point
            if let Some(ref resume_recipient) = self.config.resume_from_recipient {
                if recipient < resume_recipient {
                    continue;
                }
            }

            self.migrate_recipient(recipient).await?;

            // Update progress
            {
                let mut progress = self.progress.lock().unwrap();
                progress.processed_recipients += 1;
                progress.current_recipient = Some(recipient.clone());
                progress.last_update = Utc::now();
                
                // Estimate completion time
                if progress.processed_recipients > 0 {
                    let elapsed = progress.last_update.signed_duration_since(progress.start_time);
                    let rate = progress.processed_recipients as f64 / elapsed.num_seconds() as f64;
                    let remaining = progress.total_recipients - progress.processed_recipients;
                    let eta_seconds = (remaining as f64 / rate) as i64;
                    progress.estimated_completion = Some(progress.last_update + chrono::Duration::seconds(eta_seconds));
                }
            }
        }

        // Phase 3: Delete source data if requested
        if self.config.delete_source {
            println!("Deleting source data...");
            self.delete_source_data(&recipients).await?;
        }

        Ok(self.get_progress())
    }

    /// Streaming migration (copy and delete immediately)
    async fn streaming_migration(&self) -> Result<MigrationProgress> {
        println!("Starting streaming migration...");

        let recipients = self.discover_recipients().await?;
        
        for recipient in &recipients {
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(anyhow!("Migration cancelled by user"));
            }

            // Get chunks for this recipient
            let chunks = self.source.list_chunks(recipient).await?;
            
            // Process in batches
            for batch in chunks.chunks(self.config.batch_size) {
                self.migrate_chunk_batch_streaming(recipient, batch).await?;
            }

            // Update progress
            {
                let mut progress = self.progress.lock().unwrap();
                progress.processed_recipients += 1;
                progress.current_recipient = Some(recipient.clone());
                progress.last_update = Utc::now();
            }
        }

        Ok(self.get_progress())
    }

    /// Synchronize data between backends
    async fn synchronize(&self) -> Result<MigrationProgress> {
        println!("Starting synchronization...");
        
        // This would implement bidirectional sync logic
        // For now, we'll implement a simple one-way sync
        self.copy_then_delete().await
    }

    /// Verify data integrity without copying
    async fn verify_only(&self) -> Result<MigrationProgress> {
        println!("Starting verification...");

        let recipients = self.discover_recipients().await?;
        
        for recipient in &recipients {
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(anyhow!("Verification cancelled by user"));
            }

            let chunks = self.source.list_chunks(recipient).await?;
            
            for chunk_hash in chunks {
                if let Err(e) = self.verify_chunk(recipient, &chunk_hash).await {
                    self.add_error(format!("Verification failed for {}:{}: {}", recipient, chunk_hash, e));
                    self.stats.chunks_failed.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.chunks_migrated.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        Ok(self.get_progress())
    }

    /// Discover all recipients in the source backend
    async fn discover_recipients(&self) -> Result<Vec<String>> {
        // This is backend-specific and would need enhancement
        // For now, return a placeholder implementation
        Ok(vec!["default_recipient".to_string()])
    }

    /// Migrate all chunks for a specific recipient
    async fn migrate_recipient(&self, recipient: &str) -> Result<()> {
        let chunks = self.source.list_chunks(recipient).await?;
        
        // Process chunks in batches
        for batch in chunks.chunks(self.config.batch_size) {
            self.migrate_chunk_batch(recipient, batch).await?;
            
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(anyhow!("Migration cancelled"));
            }
        }

        Ok(())
    }

    /// Migrate a batch of chunks
    async fn migrate_chunk_batch(&self, recipient: &str, chunk_hashes: &[String]) -> Result<()> {
        let mut handles = Vec::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));

        for chunk_hash in chunk_hashes {
            let chunk_hash = chunk_hash.clone();
            let recipient = recipient.to_string();
            let source = self.source.clone();
            let destination = self.destination.clone();
            let stats = self.stats.clone();
            let config = self.config.clone();
            let semaphore = semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                match Self::migrate_single_chunk(&source, &destination, &recipient, &chunk_hash, &config).await {
                    Ok(bytes_transferred) => {
                        stats.chunks_migrated.fetch_add(1, Ordering::Relaxed);
                        stats.bytes_transferred.fetch_add(bytes_transferred, Ordering::Relaxed);
                        Ok(())
                    }
                    Err(e) => {
                        stats.chunks_failed.fetch_add(1, Ordering::Relaxed);
                        Err(e)
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all chunks in the batch to complete
        let mut errors = Vec::new();
        for handle in handles {
            if let Err(e) = handle.await.unwrap() {
                errors.push(e.to_string());
            }
        }

        if !errors.is_empty() {
            return Err(anyhow!("Batch migration failed: {:?}", errors));
        }

        Ok(())
    }

    /// Migrate a batch of chunks with streaming deletion
    async fn migrate_chunk_batch_streaming(&self, recipient: &str, chunk_hashes: &[String]) -> Result<()> {
        for chunk_hash in chunk_hashes {
            // Migrate the chunk
            match Self::migrate_single_chunk(&self.source, &self.destination, recipient, chunk_hash, &self.config).await {
                Ok(bytes_transferred) => {
                    self.stats.chunks_migrated.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_transferred.fetch_add(bytes_transferred, Ordering::Relaxed);
                    
                    // Immediately delete from source
                    if let Err(e) = self.source.delete_chunk(recipient, chunk_hash).await {
                        self.add_error(format!("Failed to delete source chunk {}:{}: {}", recipient, chunk_hash, e));
                    }
                }
                Err(e) => {
                    self.stats.chunks_failed.fetch_add(1, Ordering::Relaxed);
                    self.add_error(format!("Failed to migrate chunk {}:{}: {}", recipient, chunk_hash, e));
                }
            }

            if self.cancelled.load(Ordering::Relaxed) {
                return Err(anyhow!("Migration cancelled"));
            }
        }

        Ok(())
    }

    /// Migrate a single chunk with retry logic
    async fn migrate_single_chunk(
        source: &Arc<dyn StorageBackend>,
        destination: &Arc<dyn StorageBackend>,
        recipient: &str,
        chunk_hash: &str,
        config: &MigrationConfig,
    ) -> Result<usize> {
        let mut retries = 0;

        loop {
            match Self::migrate_chunk_once(source, destination, recipient, chunk_hash, config).await {
                Ok(bytes_transferred) => return Ok(bytes_transferred),
                Err(e) => {
                    retries += 1;
                    if retries > config.max_retries {
                        return Err(anyhow!("Failed to migrate chunk after {} retries: {}", config.max_retries, e));
                    }
                    
                    // Wait before retry
                    sleep(Duration::from_millis(config.retry_delay_ms)).await;
                }
            }
        }
    }

    /// Migrate a single chunk (single attempt)
    async fn migrate_chunk_once(
        source: &Arc<dyn StorageBackend>,
        destination: &Arc<dyn StorageBackend>,
        recipient: &str,
        chunk_hash: &str,
        config: &MigrationConfig,
    ) -> Result<usize> {
        // Load chunk data and metadata from source
        let chunk_data = source.load_chunk(recipient, chunk_hash).await?;
        let metadata = source.load_metadata(recipient, chunk_hash).await?;

        // Save to destination
        destination.save_chunk(recipient, chunk_hash, &chunk_data).await?;
        destination.save_metadata(recipient, chunk_hash, &metadata).await?;

        // Verify integrity if requested
        if config.verify_integrity {
            let dest_data = destination.load_chunk(recipient, chunk_hash).await?;
            if dest_data != chunk_data {
                return Err(anyhow!("Data integrity check failed"));
            }
        }

        Ok(chunk_data.len())
    }

    /// Verify a chunk exists and matches between source and destination
    async fn verify_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        let source_data = self.source.load_chunk(recipient, chunk_hash).await?;
        let dest_data = self.destination.load_chunk(recipient, chunk_hash).await?;

        if source_data != dest_data {
            return Err(anyhow!("Data mismatch"));
        }

        Ok(())
    }

    /// Delete source data after successful migration
    async fn delete_source_data(&self, recipients: &[String]) -> Result<()> {
        for recipient in recipients {
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(anyhow!("Deletion cancelled"));
            }

            let chunks = self.source.list_chunks(recipient).await?;
            
            for chunk_hash in chunks {
                if let Err(e) = self.source.delete_chunk(recipient, &chunk_hash).await {
                    self.add_error(format!("Failed to delete source chunk {}:{}: {}", recipient, chunk_hash, e));
                }
            }
        }

        Ok(())
    }

    /// Add an error to the progress
    fn add_error(&self, error: String) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.errors.push(error);
        }
    }
}

/// Migration utilities
pub struct MigrationUtils;

impl MigrationUtils {
    /// Estimate migration time and cost
    pub async fn estimate_migration(
        source_config: &crate::storage::backend::StorageConfig,
        dest_config: &crate::storage::backend::StorageConfig,
    ) -> Result<MigrationEstimate> {
        let source = StorageFactory::create_backend(source_config.clone()).await?;
        
        // Get basic statistics (simplified)
        let mut total_chunks = 0;
        let mut total_bytes = 0u64;

        // This would need to be enhanced to actually scan the backend
        // For now, return a placeholder estimate
        
        Ok(MigrationEstimate {
            total_chunks,
            total_bytes,
            estimated_duration_hours: 1.0,
            estimated_cost_usd: 0.0,
        })
    }

    /// Get compatible migration strategies for backend types
    pub fn get_compatible_strategies(
        source_type: StorageType,
        dest_type: StorageType,
    ) -> Vec<MigrationStrategy> {
        vec![
            MigrationStrategy::CopyThenDelete,
            MigrationStrategy::VerifyOnly,
        ]
    }

    /// Create a default migration config
    pub fn default_migration_config(
        source: crate::storage::backend::StorageConfig,
        destination: crate::storage::backend::StorageConfig,
    ) -> MigrationConfig {
        MigrationConfig {
            source,
            destination,
            strategy: MigrationStrategy::CopyThenDelete,
            batch_size: 50,
            concurrency: 10,
            verify_integrity: true,
            delete_source: false,
            resume_from_recipient: None,
            max_retries: 3,
            retry_delay_ms: 1000,
        }
    }
}

/// Migration estimate information
#[derive(Debug)]
pub struct MigrationEstimate {
    pub total_chunks: usize,
    pub total_bytes: u64,
    pub estimated_duration_hours: f64,
    pub estimated_cost_usd: f64,
}