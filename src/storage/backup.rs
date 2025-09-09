use async_trait::async_trait;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, BTreeMap};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use thiserror::Error;
use uuid::Uuid;

use crate::storage::backend::{StorageBackend, ChunkMetadata, StorageError};

#[derive(Error, Debug)]
pub enum BackupError {
    #[error("Backup not found: {id}")]
    BackupNotFound { id: String },
    
    #[error("Backup failed: {0}")]
    BackupFailed(String),
    
    #[error("Restore failed: {0}")]
    RestoreFailed(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Schedule error: {0}")]
    ScheduleError(String),
    
    #[error("Storage error: {0}")]
    StorageError(#[from] StorageError),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Backup strategy types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackupStrategy {
    /// Full backup of all data
    Full,
    /// Incremental backup since last backup
    Incremental,
    /// Differential backup since last full backup
    Differential,
    /// Continuous data protection (real-time)
    Continuous,
}

/// Backup schedule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSchedule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub strategy: BackupStrategy,
    pub frequency: BackupFrequency,
    pub retention_policy: RetentionPolicy,
    pub source_backend: String,
    pub destination_backend: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub compression_enabled: bool,
    pub encryption_enabled: bool,
    pub verify_after_backup: bool,
    pub metadata: HashMap<String, String>,
}

/// Backup frequency options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupFrequency {
    /// Run once at specified time
    Once { at: DateTime<Utc> },
    /// Run every N minutes
    Minutes { interval: u32 },
    /// Run every N hours
    Hours { interval: u32 },
    /// Run daily at specified hour
    Daily { hour: u8 },
    /// Run weekly on specified day and hour
    Weekly { day: u8, hour: u8 }, // 0 = Sunday
    /// Run monthly on specified day and hour
    Monthly { day: u8, hour: u8 },
    /// Custom cron expression
    Cron { expression: String },
}

/// Retention policy for backups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Keep backups for this many days
    pub keep_days: Option<u32>,
    /// Keep this many recent backups
    pub keep_count: Option<u32>,
    /// Keep daily backups for this many days
    pub keep_daily: Option<u32>,
    /// Keep weekly backups for this many weeks
    pub keep_weekly: Option<u32>,
    /// Keep monthly backups for this many months
    pub keep_monthly: Option<u32>,
    /// Custom retention rules
    pub custom_rules: Vec<RetentionRule>,
}

/// Custom retention rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionRule {
    pub name: String,
    pub condition: String, // e.g., "age > 30 days AND size > 1GB"
    pub action: RetentionAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetentionAction {
    Delete,
    Archive,
    Compress,
    MoveToStorage { backend: String },
}

/// Backup record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    pub id: String,
    pub schedule_id: Option<String>,
    pub strategy: BackupStrategy,
    pub status: BackupStatus,
    pub source_backend: String,
    pub destination_backend: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<u64>,
    pub total_chunks: u64,
    pub backed_up_chunks: u64,
    pub total_size_bytes: u64,
    pub compressed_size_bytes: Option<u64>,
    pub chunks_manifest: Vec<ChunkBackupInfo>,
    pub metadata_manifest: Vec<String>,
    pub verification_status: Option<VerificationStatus>,
    pub error_message: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Backup status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackupStatus {
    Scheduled,
    Running,
    Completed,
    Failed,
    Cancelled,
    Verifying,
    VerificationFailed,
}

/// Chunk backup information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkBackupInfo {
    pub chunk_hash: String,
    pub original_size: u64,
    pub backed_up_size: u64,
    pub checksum: String,
    pub backup_location: String,
}

/// Verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStatus {
    pub verified_at: DateTime<Utc>,
    pub total_chunks: u64,
    pub verified_chunks: u64,
    pub failed_chunks: Vec<String>,
    pub integrity_ok: bool,
}

/// Point-in-time recovery information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPoint {
    pub timestamp: DateTime<Utc>,
    pub backup_id: String,
    pub description: String,
    pub total_size: u64,
    pub chunk_count: u64,
    pub can_restore: bool,
}

/// Disaster recovery plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasterRecoveryPlan {
    pub id: String,
    pub name: String,
    pub description: String,
    pub priority: u8, // 1 = highest, 5 = lowest
    pub recovery_time_objective: Duration, // RTO
    pub recovery_point_objective: Duration, // RPO
    pub backup_schedules: Vec<String>,
    pub recovery_procedures: Vec<RecoveryProcedure>,
    pub test_schedule: Option<BackupFrequency>,
    pub last_test: Option<DateTime<Utc>>,
    pub contacts: Vec<EmergencyContact>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Recovery procedure step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProcedure {
    pub step: u32,
    pub title: String,
    pub description: String,
    pub estimated_duration: Duration,
    pub required_resources: Vec<String>,
    pub automation_script: Option<String>,
}

/// Emergency contact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyContact {
    pub name: String,
    pub role: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub priority: u8,
}

/// Backup manager for handling all backup operations
pub struct BackupManager {
    schedules: Arc<RwLock<HashMap<String, BackupSchedule>>>,
    backup_records: Arc<RwLock<BTreeMap<DateTime<Utc>, BackupRecord>>>,
    recovery_plans: Arc<RwLock<HashMap<String, DisasterRecoveryPlan>>>,
    storage_backends: Arc<RwLock<HashMap<String, Arc<dyn StorageBackend>>>>,
    scheduler: Arc<Mutex<BackupScheduler>>,
    backup_dir: std::path::PathBuf,
}

impl BackupManager {
    /// Create new backup manager
    pub fn new<P: AsRef<std::path::Path>>(backup_dir: P) -> Result<Self, BackupError> {
        let backup_dir = backup_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&backup_dir)?;
        
        let manager = Self {
            schedules: Arc::new(RwLock::new(HashMap::new())),
            backup_records: Arc::new(RwLock::new(BTreeMap::new())),
            recovery_plans: Arc::new(RwLock::new(HashMap::new())),
            storage_backends: Arc::new(RwLock::new(HashMap::new())),
            scheduler: Arc::new(Mutex::new(BackupScheduler::new())),
            backup_dir,
            storage_backends: Arc::new(RwLock::new(HashMap::new())),
            scheduler: Arc::new(Mutex::new(BackupScheduler::new())),
            backup_dir,
        };
        
        // Load existing data
        manager.load_data()?;
        
        Ok(manager)
    }
    
    /// Register a storage backend
    pub async fn register_backend(&self, id: String, backend: Arc<dyn StorageBackend>) {
        self.storage_backends.write().await.insert(id, backend);
    }
    
    /// Create a new backup schedule
    pub async fn create_schedule(
        &self,
        name: String,
        strategy: BackupStrategy,
        frequency: BackupFrequency,
        retention: RetentionPolicy,
        source: String,
        destination: String,
    ) -> Result<String, BackupError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let schedule = BackupSchedule {
            id: id.clone(),
            name,
            enabled: true,
            strategy,
            frequency,
            retention_policy: retention,
            source_backend: source,
            destination_backend: destination,
            created_at: now,
            updated_at: now,
            last_run: None,
            next_run: self.calculate_next_run(&frequency, now),
            compression_enabled: true,
            encryption_enabled: false,
            verify_after_backup: true,
            metadata: HashMap::new(),
        };
        
        // Validate backends exist
        let backends = self.storage_backends.read().await;
        if !backends.contains_key(&schedule.source_backend) {
            return Err(BackupError::BackupFailed(
                format!("Source backend '{}' not found", schedule.source_backend)
            ));
        }
        if !backends.contains_key(&schedule.destination_backend) {
            return Err(BackupError::BackupFailed(
                format!("Destination backend '{}' not found", schedule.destination_backend)
            ));
        }
        
        self.schedules.write().await.insert(id.clone(), schedule);
        self.save_schedules().await?;
        
        // Update scheduler
        self.update_scheduler().await?;
        
        Ok(id)
    }
    
    /// Execute a backup manually
    pub async fn execute_backup(&self, schedule_id: &str) -> Result<String, BackupError> {
        let schedule = {
            let schedules = self.schedules.read().await;
            schedules.get(schedule_id).cloned()
                .ok_or_else(|| BackupError::BackupNotFound { id: schedule_id.to_string() })?
        };
        
        let backup_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let mut backup_record = BackupRecord {
            id: backup_id.clone(),
            schedule_id: Some(schedule_id.to_string()),
            strategy: schedule.strategy.clone(),
            status: BackupStatus::Running,
            source_backend: schedule.source_backend.clone(),
            destination_backend: schedule.destination_backend.clone(),
            started_at: now,
            completed_at: None,
            duration_seconds: None,
            total_chunks: 0,
            backed_up_chunks: 0,
            total_size_bytes: 0,
            compressed_size_bytes: None,
            chunks_manifest: Vec::new(),
            metadata_manifest: Vec::new(),
            verification_status: None,
            error_message: None,
            metadata: HashMap::new(),
        };
        
        // Save initial record
        self.backup_records.write().await.insert(now, backup_record.clone());
        
        // Execute backup
        match self.perform_backup(&schedule, &mut backup_record).await {
            Ok(()) => {
                backup_record.status = BackupStatus::Completed;
                backup_record.completed_at = Some(Utc::now());
                backup_record.duration_seconds = Some(
                    (backup_record.completed_at.unwrap() - backup_record.started_at)
                        .num_seconds() as u64
                );
                
                // Verification if enabled
                if schedule.verify_after_backup {
                    backup_record.status = BackupStatus::Verifying;
                    match self.verify_backup(&backup_record).await {
                        Ok(verification) => {
                            backup_record.verification_status = Some(verification);
                            backup_record.status = BackupStatus::Completed;
                        }
                        Err(e) => {
                            backup_record.status = BackupStatus::VerificationFailed;
                            backup_record.error_message = Some(e.to_string());
                        }
                    }
                }
            }
            Err(e) => {
                backup_record.status = BackupStatus::Failed;
                backup_record.error_message = Some(e.to_string());
                backup_record.completed_at = Some(Utc::now());
            }
        }
        
        // Update record
        self.backup_records.write().await.insert(backup_record.started_at, backup_record);
        self.save_backup_records().await?;
        
        // Update schedule last run
        {
            let mut schedules = self.schedules.write().await;
            if let Some(schedule) = schedules.get_mut(schedule_id) {
                schedule.last_run = Some(now);
                schedule.next_run = self.calculate_next_run(&schedule.frequency, now);
                schedule.updated_at = Utc::now();
            }
        }
        self.save_schedules().await?;
        
        Ok(backup_id)
    }
    
    /// Perform the actual backup operation
    async fn perform_backup(
        &self,
        schedule: &BackupSchedule,
        record: &mut BackupRecord,
    ) -> Result<(), BackupError> {
        let backends = self.storage_backends.read().await;
        let source = backends.get(&schedule.source_backend)
            .ok_or_else(|| BackupError::BackupFailed("Source backend not found".to_string()))?;
        let destination = backends.get(&schedule.destination_backend)
            .ok_or_else(|| BackupError::BackupFailed("Destination backend not found".to_string()))?;
        
        // Get list of chunks to backup
        let all_chunks = source.list_chunks().await?;
        let all_metadata = source.list_metadata().await?;
        
        record.total_chunks = all_chunks.len() as u64;
        record.metadata_manifest = all_metadata;
        
        // Filter chunks based on strategy
        let chunks_to_backup = match &schedule.strategy {
            BackupStrategy::Full => all_chunks,
            BackupStrategy::Incremental => {
                // Only backup chunks not in last backup
                self.filter_incremental_chunks(all_chunks, schedule).await?
            }
            BackupStrategy::Differential => {
                // Only backup chunks not in last full backup
                self.filter_differential_chunks(all_chunks, schedule).await?
            }
            BackupStrategy::Continuous => {
                // Backup changed chunks (simplified implementation)
                all_chunks
            }
        };
        
        // Backup each chunk
        for chunk_hash in chunks_to_backup {
            let chunk_data = source.load_chunk(&chunk_hash).await?;
            let original_size = chunk_data.len() as u64;
            
            // Optional compression
            let (final_data, compressed_size) = if schedule.compression_enabled {
                let compressed = self.compress_data(&chunk_data)?;
                let compressed_size = compressed.len() as u64;
                (compressed, Some(compressed_size))
            } else {
                (chunk_data, None)
            };
            
            // Calculate checksum
            let checksum = self.calculate_checksum(&final_data);
            
            // Save to destination
            let backup_location = format!("backup_{}/{}", record.id, chunk_hash);
            destination.save_chunk(&backup_location, final_data).await?;
            
            // Record chunk info
            record.chunks_manifest.push(ChunkBackupInfo {
                chunk_hash: chunk_hash.clone(),
                original_size,
                backed_up_size: compressed_size.unwrap_or(original_size),
                checksum,
                backup_location,
            });
            
            record.backed_up_chunks += 1;
            record.total_size_bytes += original_size;
            if let Some(comp_size) = compressed_size {
                record.compressed_size_bytes = Some(
                    record.compressed_size_bytes.unwrap_or(0) + comp_size
                );
            }
        }
        
        // Backup metadata
        for metadata_hash in &record.metadata_manifest {
            if let Ok(metadata) = source.load_metadata(metadata_hash).await {
                let metadata_json = serde_json::to_vec(&metadata)?;
                let backup_location = format!("backup_{}/metadata_{}", record.id, metadata_hash);
                destination.save_chunk(&backup_location, metadata_json).await?;
            }
        }
        
        Ok(())
    }
    
    /// Verify backup integrity
    async fn verify_backup(&self, record: &BackupRecord) -> Result<VerificationStatus, BackupError> {
        let backends = self.storage_backends.read().await;
        let destination = backends.get(&record.destination_backend)
            .ok_or_else(|| BackupError::VerificationFailed("Destination backend not found".to_string()))?;
        
        let mut verified_chunks = 0;
        let mut failed_chunks = Vec::new();
        
        for chunk_info in &record.chunks_manifest {
            match destination.load_chunk(&chunk_info.backup_location).await {
                Ok(data) => {
                    let checksum = self.calculate_checksum(&data);
                    if checksum == chunk_info.checksum {
                        verified_chunks += 1;
                    } else {
                        failed_chunks.push(chunk_info.chunk_hash.clone());
                    }
                }
                Err(_) => {
                    failed_chunks.push(chunk_info.chunk_hash.clone());
                }
            }
        }
        
        Ok(VerificationStatus {
            verified_at: Utc::now(),
            total_chunks: record.chunks_manifest.len() as u64,
            verified_chunks,
            failed_chunks,
            integrity_ok: failed_chunks.is_empty(),
        })
    }
    
    /// Restore from backup
    pub async fn restore_backup(
        &self,
        backup_id: &str,
        destination_backend: &str,
        target_time: Option<DateTime<Utc>>,
    ) -> Result<(), BackupError> {
        let backup_record = self.find_backup_record(backup_id).await
            .ok_or_else(|| BackupError::BackupNotFound { id: backup_id.to_string() })?;
        
        let backends = self.storage_backends.read().await;
        let source = backends.get(&backup_record.destination_backend)
            .ok_or_else(|| BackupError::RestoreFailed("Backup source not found".to_string()))?;
        let destination = backends.get(destination_backend)
            .ok_or_else(|| BackupError::RestoreFailed("Restore destination not found".to_string()))?;
        
        // Restore chunks
        for chunk_info in &backup_record.chunks_manifest {
            let backed_up_data = source.load_chunk(&chunk_info.backup_location).await?;
            
            // Decompress if needed
            let restored_data = if backup_record.compressed_size_bytes.is_some() {
                self.decompress_data(&backed_up_data)?
            } else {
                backed_up_data
            };
            
            // Verify checksum
            let checksum = self.calculate_checksum(&restored_data);
            if checksum != chunk_info.checksum {
                return Err(BackupError::RestoreFailed(
                    format!("Checksum mismatch for chunk {}", chunk_info.chunk_hash)
                ));
            }
            
            // Save to destination
            destination.save_chunk(&chunk_info.chunk_hash, restored_data).await?;
        }
        
        // Restore metadata
        for metadata_hash in &backup_record.metadata_manifest {
            let backup_location = format!("backup_{}/metadata_{}", backup_record.id, metadata_hash);
            if let Ok(metadata_data) = source.load_chunk(&backup_location).await {
                let metadata: ChunkMetadata = serde_json::from_slice(&metadata_data)?;
                destination.save_metadata(metadata_hash, metadata).await?;
            }
        }
        
        Ok(())
    }
    
    /// Get available recovery points
    pub async fn get_recovery_points(&self, days: u32) -> Vec<RecoveryPoint> {
        let cutoff = Utc::now() - Duration::days(days as i64);
        let records = self.backup_records.read().await;
        
        records.values()
            .filter(|record| {
                record.started_at >= cutoff &&
                record.status == BackupStatus::Completed &&
                record.verification_status.as_ref().map_or(true, |v| v.integrity_ok)
            })
            .map(|record| RecoveryPoint {
                timestamp: record.started_at,
                backup_id: record.id.clone(),
                description: format!("{} backup", record.strategy),
                total_size: record.total_size_bytes,
                chunk_count: record.total_chunks,
                can_restore: true,
            })
            .collect()
    }
    
    /// Helper methods
    async fn filter_incremental_chunks(
        &self,
        all_chunks: Vec<String>,
        schedule: &BackupSchedule,
    ) -> Result<Vec<String>, BackupError> {
        // Simplified: return all chunks (would compare with last backup in real implementation)
        Ok(all_chunks)
    }
    
    async fn filter_differential_chunks(
        &self,
        all_chunks: Vec<String>,
        schedule: &BackupSchedule,
    ) -> Result<Vec<String>, BackupError> {
        // Simplified: return all chunks (would compare with last full backup in real implementation)
        Ok(all_chunks)
    }
    
    fn calculate_next_run(&self, frequency: &BackupFrequency, from: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match frequency {
            BackupFrequency::Once { at } => Some(*at),
            BackupFrequency::Minutes { interval } => {
                Some(from + Duration::minutes(*interval as i64))
            }
            BackupFrequency::Hours { interval } => {
                Some(from + Duration::hours(*interval as i64))
            }
            BackupFrequency::Daily { hour } => {
                Some(from.date_naive().and_hms_opt(*hour as u32, 0, 0).unwrap().and_utc() + Duration::days(1))
            }
            BackupFrequency::Weekly { day: _, hour } => {
                Some(from + Duration::days(7))
            }
            BackupFrequency::Monthly { day: _, hour: _ } => {
                Some(from + Duration::days(30)) // Simplified
            }
            BackupFrequency::Cron { expression: _ } => {
                // Would use a cron parser in real implementation
                Some(from + Duration::hours(1))
            }
        }
    }
    
    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>, BackupError> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        let compressed = encoder.finish()?;
        Ok(compressed)
    }
    
    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>, BackupError> {
        use flate2::read::GzDecoder;
        use std::io::Read;
        
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }
    
    fn calculate_checksum(&self, data: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
    
    async fn find_backup_record(&self, backup_id: &str) -> Option<BackupRecord> {
        let records = self.backup_records.read().await;
        records.values()
            .find(|record| record.id == backup_id)
            .cloned()
    }
    
    async fn update_scheduler(&self) -> Result<(), BackupError> {
        // Update the scheduler with current schedules
        let schedules = self.schedules.read().await;
        let mut scheduler = self.scheduler.lock().await;
        scheduler.update_schedules(schedules.values().cloned().collect());
        Ok(())
    }
    
    // Persistence methods
    fn load_data(&self) -> Result<(), BackupError> {
        // Load schedules, records, and recovery plans from disk
        // Simplified implementation
        Ok(())
    }
    
    async fn save_schedules(&self) -> Result<(), BackupError> {
        let schedules = self.schedules.read().await;
        let schedules_file = self.backup_dir.join("schedules.json");
        let json = serde_json::to_string_pretty(&*schedules)?;
        tokio::fs::write(schedules_file, json).await?;
        Ok(())
    }
    
    async fn save_backup_records(&self) -> Result<(), BackupError> {
        let records = self.backup_records.read().await;
        let records_file = self.backup_dir.join("backup_records.json");
        let json = serde_json::to_string_pretty(&*records)?;
        tokio::fs::write(records_file, json).await?;
        Ok(())
    }
}

/// Backup scheduler for managing scheduled backups
pub struct BackupScheduler {
    schedules: Vec<BackupSchedule>,
    running: bool,
}

impl BackupScheduler {
    pub fn new() -> Self {
        Self {
            schedules: Vec::new(),
            running: false,
        }
    }
    
    pub fn update_schedules(&mut self, schedules: Vec<BackupSchedule>) {
        self.schedules = schedules;
    }
    
    pub async fn start(&mut self) -> Result<(), BackupError> {
        self.running = true;
        // Would start background scheduler task
        Ok(())
    }
    
    pub fn stop(&mut self) {
        self.running = false;
    }
    
    pub fn get_next_scheduled_backup(&self) -> Option<&BackupSchedule> {
        let now = Utc::now();
        self.schedules.iter()
            .filter(|s| s.enabled && s.next_run.map_or(false, |next| next <= now))
            .min_by_key(|s| s.next_run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::storage::backends::LocalBackend;
    
    #[tokio::test]
    async fn test_backup_schedule_creation() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let backup_manager = BackupManager::new(temp_dir.path())?;
        
        // Register test backends
        let source_backend = Arc::new(LocalBackend::new(temp_dir.path().join("source"), true)?);
        let dest_backend = Arc::new(LocalBackend::new(temp_dir.path().join("dest"), true)?);
        
        backup_manager.register_backend("source".to_string(), source_backend).await;
        backup_manager.register_backend("dest".to_string(), dest_backend).await;
        
        // Create backup schedule
        let schedule_id = backup_manager.create_schedule(
            "Daily Backup".to_string(),
            BackupStrategy::Full,
            BackupFrequency::Daily { hour: 2 },
            RetentionPolicy {
                keep_days: Some(30),
                keep_count: None,
                keep_daily: Some(7),
                keep_weekly: Some(4),
                keep_monthly: Some(12),
                custom_rules: Vec::new(),
            },
            "source".to_string(),
            "dest".to_string(),
        ).await?;
        
        assert!(!schedule_id.is_empty());
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_backup_execution() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let backup_manager = BackupManager::new(temp_dir.path())?;
        
        // Setup test data and execute backup
        // This would test the full backup flow
        
        Ok(())
    }
}