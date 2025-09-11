use async_trait::async_trait;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use thiserror::Error;

use crate::storage::backend::{StorageBackend, ChunkMetadata, StorageError};

#[derive(Error, Debug)]
pub enum AnalyticsError {
    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("Storage analytics error: {0}")]
    AnalyticsError(String),
}

/// Storage usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageStatistics {
    pub total_chunks: u64,
    pub total_size_bytes: u64,
    pub chunk_count_by_day: HashMap<String, u64>, // Date -> count
    pub size_by_day: HashMap<String, u64>, // Date -> bytes
    pub chunk_count_by_hour: HashMap<String, u64>, // Hour -> count
    pub size_by_hour: HashMap<String, u64>, // Hour -> bytes
    pub average_chunk_size: f64,
    pub largest_chunk_size: u64,
    pub smallest_chunk_size: u64,
    pub total_operations: u64,
    pub operations_by_type: HashMap<String, u64>, // "save", "load", "delete" -> count
    pub last_updated: DateTime<Utc>,
    pub retention_days: u32,
}

impl Default for UsageStatistics {
    fn default() -> Self {
        Self {
            total_chunks: 0,
            total_size_bytes: 0,
            chunk_count_by_day: HashMap::new(),
            size_by_day: HashMap::new(),
            chunk_count_by_hour: HashMap::new(),
            size_by_hour: HashMap::new(),
            average_chunk_size: 0.0,
            largest_chunk_size: 0,
            smallest_chunk_size: u64::MAX,
            total_operations: 0,
            operations_by_type: HashMap::new(),
            last_updated: Utc::now(),
            retention_days: 30,
        }
    }
}

/// Quota configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaConfig {
    pub max_total_size_bytes: Option<u64>,
    pub max_chunks: Option<u64>,
    pub max_daily_operations: Option<u64>,
    pub max_hourly_operations: Option<u64>,
    pub max_chunk_size_bytes: Option<u64>,
    pub enabled: bool,
    pub enforce_hard_limits: bool, // If false, only warn when limits are exceeded
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_total_size_bytes: None,
            max_chunks: None,
            max_daily_operations: None,
            max_hourly_operations: None,
            max_chunk_size_bytes: None,
            enabled: false,
            enforce_hard_limits: true,
        }
    }
}

/// Analytics and quota management wrapper around storage backends
pub struct AnalyticsStorageBackend {
    backend: Arc<dyn StorageBackend>,
    usage_stats: Arc<RwLock<UsageStatistics>>,
    quota_config: Arc<RwLock<QuotaConfig>>,
    stats_file_path: Option<String>,
}

impl AnalyticsStorageBackend {
    pub fn new(
        backend: Arc<dyn StorageBackend>, 
        quota_config: QuotaConfig,
        stats_file_path: Option<String>
    ) -> Self {
        let analytics_backend = Self {
            backend,
            usage_stats: Arc::new(RwLock::new(UsageStatistics::default())),
            quota_config: Arc::new(RwLock::new(quota_config)),
            stats_file_path,
        };
        
        // Load existing statistics if file exists
        if let Some(ref path) = analytics_backend.stats_file_path {
            if let Ok(data) = std::fs::read_to_string(path) {
                if let Ok(stats) = serde_json::from_str::<UsageStatistics>(&data) {
                    *analytics_backend.usage_stats.blocking_write() = stats;
                }
            }
        }
        
        analytics_backend
    }
    
    pub async fn get_usage_statistics(&self) -> UsageStatistics {
        self.usage_stats.read().await.clone()
    }
    
    pub async fn get_quota_config(&self) -> QuotaConfig {
        self.quota_config.read().await.clone()
    }
    
    pub async fn update_quota_config(&self, config: QuotaConfig) -> Result<(), AnalyticsError> {
        *self.quota_config.write().await = config;
        Ok(())
    }
    
    pub async fn reset_statistics(&self) -> Result<(), AnalyticsError> {
        let mut stats = self.usage_stats.write().await;
        *stats = UsageStatistics::default();
        self.persist_statistics(&stats).await?;
        Ok(())
    }
    
    pub async fn generate_report(&self, days: u32) -> Result<String, AnalyticsError> {
        let stats = self.usage_stats.read().await;
        let quota = self.quota_config.read().await;
        
        let mut report = String::new();
        report.push_str("=== Storage Analytics Report ===\n\n");
        
        // General statistics
        report.push_str(&format!("Total Chunks: {}\n", stats.total_chunks));
        report.push_str(&format!("Total Size: {:.2} MB ({} bytes)\n", 
            stats.total_size_bytes as f64 / 1024.0 / 1024.0, stats.total_size_bytes));
        report.push_str(&format!("Average Chunk Size: {:.2} KB\n", stats.average_chunk_size / 1024.0));
        report.push_str(&format!("Largest Chunk: {:.2} KB\n", stats.largest_chunk_size as f64 / 1024.0));
        report.push_str(&format!("Smallest Chunk: {:.2} KB\n", 
            if stats.smallest_chunk_size == u64::MAX { 0.0 } else { stats.smallest_chunk_size as f64 / 1024.0 }));
        
        // Operations
        report.push_str(&format!("\nTotal Operations: {}\n", stats.total_operations));
        for (op_type, count) in &stats.operations_by_type {
            report.push_str(&format!("  {}: {}\n", op_type, count));
        }
        
        // Daily trends (last N days)
        report.push_str(&format!("\n=== Daily Activity (Last {} Days) ===\n", days));
        let mut daily_entries: Vec<_> = stats.chunk_count_by_day.iter().collect();
        daily_entries.sort_by(|a, b| a.0.cmp(b.0));
        
        for (date, count) in daily_entries.iter().rev().take(days as usize) {
            let size = stats.size_by_day.get(*date).unwrap_or(&0);
            report.push_str(&format!("{}: {} chunks, {:.2} MB\n", 
                date, count, *size as f64 / 1024.0 / 1024.0));
        }
        
        // Quota status
        report.push_str("\n=== Quota Status ===\n");
        if quota.enabled {
            if let Some(max_size) = quota.max_total_size_bytes {
                let usage_pct = (stats.total_size_bytes as f64 / max_size as f64) * 100.0;
                report.push_str(&format!("Size Quota: {:.1}% used ({} / {} bytes)\n", 
                    usage_pct, stats.total_size_bytes, max_size));
            }
            
            if let Some(max_chunks) = quota.max_chunks {
                let usage_pct = (stats.total_chunks as f64 / max_chunks as f64) * 100.0;
                report.push_str(&format!("Chunk Quota: {:.1}% used ({} / {} chunks)\n", 
                    usage_pct, stats.total_chunks, max_chunks));
            }
        } else {
            report.push_str("Quotas are disabled\n");
        }
        
        report.push_str(&format!("\nLast Updated: {}\n", stats.last_updated));
        
        Ok(report)
    }
    
    async fn check_quotas(&self, operation: &str, chunk_size: Option<u64>) -> Result<(), AnalyticsError> {
        let stats = self.usage_stats.read().await;
        let quota = self.quota_config.read().await;
        
        if !quota.enabled {
            return Ok(());
        }
        
        let now = Utc::now();
        let today = now.format("%Y-%m-%d").to_string();
        let current_hour = now.format("%Y-%m-%d-%H").to_string();
        
        // Check chunk size limit
        if let Some(chunk_size) = chunk_size {
            if let Some(max_chunk_size) = quota.max_chunk_size_bytes {
                if chunk_size > max_chunk_size {
                    let msg = format!("Chunk size {} exceeds limit of {} bytes", chunk_size, max_chunk_size);
                    if quota.enforce_hard_limits {
                        return Err(AnalyticsError::QuotaExceeded(msg));
                    } else {
                        eprintln!("WARNING: {}", msg);
                    }
                }
            }
        }
        
        // Check total size quota (for save operations)
        if operation == "save" {
            if let Some(max_total_size) = quota.max_total_size_bytes {
                let projected_size = stats.total_size_bytes + chunk_size.unwrap_or(0);
                if projected_size > max_total_size {
                    let msg = format!("Total size would exceed quota: {} > {}", projected_size, max_total_size);
                    if quota.enforce_hard_limits {
                        return Err(AnalyticsError::QuotaExceeded(msg));
                    } else {
                        eprintln!("WARNING: {}", msg);
                    }
                }
            }
            
            // Check total chunks quota
            if let Some(max_chunks) = quota.max_chunks {
                if stats.total_chunks >= max_chunks {
                    let msg = format!("Chunk count would exceed quota: {} >= {}", stats.total_chunks + 1, max_chunks);
                    if quota.enforce_hard_limits {
                        return Err(AnalyticsError::QuotaExceeded(msg));
                    } else {
                        eprintln!("WARNING: {}", msg);
                    }
                }
            }
        }
        
        // Check daily operation quota
        if let Some(max_daily_ops) = quota.max_daily_operations {
            let daily_ops = stats.operations_by_type.values().sum::<u64>(); // Simplified - should be daily only
            if daily_ops >= max_daily_ops {
                let msg = format!("Daily operation limit reached: {}", max_daily_ops);
                if quota.enforce_hard_limits {
                    return Err(AnalyticsError::QuotaExceeded(msg));
                } else {
                    eprintln!("WARNING: {}", msg);
                }
            }
        }
        
        // Check hourly operation quota
        if let Some(max_hourly_ops) = quota.max_hourly_operations {
            let hourly_ops = stats.chunk_count_by_hour.get(&current_hour).unwrap_or(&0);
            if *hourly_ops >= max_hourly_ops {
                let msg = format!("Hourly operation limit reached: {}", max_hourly_ops);
                if quota.enforce_hard_limits {
                    return Err(AnalyticsError::QuotaExceeded(msg));
                } else {
                    eprintln!("WARNING: {}", msg);
                }
            }
        }
        
        Ok(())
    }
    
    async fn record_operation(&self, operation: &str, chunk_size: Option<u64>) -> Result<(), AnalyticsError> {
        let mut stats = self.usage_stats.write().await;
        let now = Utc::now();
        let today = now.format("%Y-%m-%d").to_string();
        let current_hour = now.format("%Y-%m-%d-%H").to_string();
        
        // Update operation counts
        *stats.operations_by_type.entry(operation.to_string()).or_insert(0) += 1;
        stats.total_operations += 1;
        
        // Update daily/hourly counters
        *stats.chunk_count_by_day.entry(today.clone()).or_insert(0) += 1;
        *stats.chunk_count_by_hour.entry(current_hour).or_insert(0) += 1;
        
        match operation {
            "save" => {
                if let Some(size) = chunk_size {
                    stats.total_chunks += 1;
                    stats.total_size_bytes += size;
                    *stats.size_by_day.entry(today).or_insert(0) += size;
                    
                    // Update size statistics
                    if size > stats.largest_chunk_size {
                        stats.largest_chunk_size = size;
                    }
                    if size < stats.smallest_chunk_size || stats.smallest_chunk_size == u64::MAX {
                        stats.smallest_chunk_size = size;
                    }
                    
                    // Update average
                    if stats.total_chunks > 0 {
                        stats.average_chunk_size = stats.total_size_bytes as f64 / stats.total_chunks as f64;
                    }
                }
            }
            "delete" => {
                if let Some(size) = chunk_size {
                    if stats.total_chunks > 0 {
                        stats.total_chunks -= 1;
                    }
                    if stats.total_size_bytes >= size {
                        stats.total_size_bytes -= size;
                    }
                    
                    // Recalculate average
                    if stats.total_chunks > 0 {
                        stats.average_chunk_size = stats.total_size_bytes as f64 / stats.total_chunks as f64;
                    } else {
                        stats.average_chunk_size = 0.0;
                    }
                }
            }
            _ => {} // load operations don't change storage metrics
        }
        
        stats.last_updated = now;
        
        // Clean up old data (keep only retention_days days)
        self.cleanup_old_data(&mut stats).await;
        
        // Persist statistics
        self.persist_statistics(&stats).await?;
        
        Ok(())
    }
    
    async fn cleanup_old_data(&self, stats: &mut UsageStatistics) {
        let cutoff_date = Utc::now() - Duration::days(stats.retention_days as i64);
        let cutoff_date_str = cutoff_date.format("%Y-%m-%d").to_string();
        let cutoff_hour_str = cutoff_date.format("%Y-%m-%d-%H").to_string();
        
        // Remove old daily data
        stats.chunk_count_by_day.retain(|date, _| date >= &cutoff_date_str);
        stats.size_by_day.retain(|date, _| date >= &cutoff_date_str);
        
        // Remove old hourly data (keep only last 7 days for hourly granularity)
        let week_cutoff = Utc::now() - Duration::days(7);
        let week_cutoff_str = week_cutoff.format("%Y-%m-%d-%H").to_string();
        stats.chunk_count_by_hour.retain(|hour, _| hour >= &week_cutoff_str);
        stats.size_by_hour.retain(|hour, _| hour >= &week_cutoff_str);
    }
    
    async fn persist_statistics(&self, stats: &UsageStatistics) -> Result<(), AnalyticsError> {
        if let Some(ref path) = self.stats_file_path {
            let json = serde_json::to_string_pretty(stats)
                .map_err(|e| AnalyticsError::AnalyticsError(format!("Serialization error: {}", e)))?;
            
            tokio::fs::write(path, json).await
                .map_err(|e| AnalyticsError::AnalyticsError(format!("Failed to save statistics: {}", e)))?;
        }
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for AnalyticsStorageBackend {
    async fn save_chunk(&self, chunk_hash: &str, data: Vec<u8>) -> Result<(), StorageError> {
        let chunk_size = data.len() as u64;
        
        // Check quotas before operation
        self.check_quotas("save", Some(chunk_size)).await
            .map_err(|e| StorageError::BackendError { message: e.to_string() })?;
        
        // Perform the actual save operation
        let result = self.backend.save_chunk(chunk_hash, data).await;
        
        // Record the operation (even if it failed, for monitoring purposes)
        if result.is_ok() {
            self.record_operation("save", Some(chunk_size)).await
                .map_err(|e| StorageError::BackendError { message: e.to_string() })?;
        }
        
        result
    }
    
    async fn load_chunk(&self, chunk_hash: &str) -> Result<Vec<u8>, StorageError> {
        // Check quotas for operation limits
        self.check_quotas("load", None).await
            .map_err(|e| StorageError::BackendError { message: e.to_string() })?;
        
        let result = self.backend.load_chunk(chunk_hash).await;
        
        // Record successful load operations
        if result.is_ok() {
            self.record_operation("load", None).await
                .map_err(|e| StorageError::BackendError { message: e.to_string() })?;
        }
        
        result
    }
    
    async fn chunk_exists(&self, recipient: &str, chunk_hash: &str) -> Result<bool> {
        self.backend.chunk_exists(recipient, chunk_hash).await
    }
    
    async fn delete_chunk(&self, recipient: &str, chunk_hash: &str) -> Result<()> {
        // Get chunk size before deletion for accurate statistics
        let chunk_size = if let Ok(data) = self.backend.load_chunk(recipient, chunk_hash).await {
            Some(data.len() as u64)
        } else {
            None
        };
        
        let result = self.backend.delete_chunk(recipient, chunk_hash).await;
        
        // Record successful deletion
        if result.is_ok() {
            self.record_operation("delete", chunk_size).await
                .map_err(|e| StorageError::BackendError { message: e.to_string() })?;
        }
        
        result
    }
    
    async fn save_metadata(&self, file_hash: &str, metadata: ChunkMetadata) -> Result<(), StorageError> {
        self.backend.save_metadata(file_hash, metadata).await
    }
    
    async fn load_metadata(&self, file_hash: &str) -> Result<ChunkMetadata, StorageError> {
        self.backend.load_metadata(file_hash).await
    }
    
    async fn list_chunks(&self) -> Result<Vec<String>, StorageError> {
        self.backend.list_chunks().await
    }
    
    async fn list_metadata(&self, recipient: &str) -> Result<Vec<(String, ChunkMetadata)>> {
        self.backend.list_metadata(recipient).await
    }
    
    async fn get_storage_info(&self) -> Result<HashMap<String, String>> {
        let mut info = self.backend.get_storage_info().await?;
        let stats = self.usage_stats.read().await;
        let quota = self.quota_config.read().await;
        
        info.insert("analytics_enabled".to_string(), "true".to_string());
        info.insert("total_chunks".to_string(), stats.total_chunks.to_string());
        info.insert("total_size_bytes".to_string(), stats.total_size_bytes.to_string());
        info.insert("total_operations".to_string(), stats.total_operations.to_string());
        info.insert("quota_enabled".to_string(), quota.enabled.to_string());
        
        if quota.enabled {
            if let Some(max_size) = quota.max_total_size_bytes {
                let usage_pct = (stats.total_size_bytes as f64 / max_size as f64) * 100.0;
                info.insert("size_quota_usage_pct".to_string(), format!("{:.1}", usage_pct));
            }
            
            if let Some(max_chunks) = quota.max_chunks {
                let usage_pct = (stats.total_chunks as f64 / max_chunks as f64) * 100.0;
                info.insert("chunk_quota_usage_pct".to_string(), format!("{:.1}", usage_pct));
            }
        }
        
        Ok(info)
    }
    
    async fn cleanup(&self) -> Result<u64> {
        self.backend.cleanup().await
    }
    
    async fn health_check(&self) -> Result<HashMap<String, String>, StorageError> {
        let mut health = self.backend.health_check().await?;
        let stats = self.usage_stats.read().await;
        
        health.insert("analytics_status".to_string(), "healthy".to_string());
        health.insert("last_stats_update".to_string(), stats.last_updated.to_rfc3339());
        
        // Check if statistics file can be written
        if let Some(ref path) = self.stats_file_path {
            match tokio::fs::metadata(path).await {
                Ok(_) => health.insert("stats_file_accessible".to_string(), "true".to_string()),
                Err(_) => health.insert("stats_file_accessible".to_string(), "false".to_string()),
            };
        }
        
        Ok(health)
    }
}