use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Performance profiler for system and application performance monitoring
#[derive(Clone)]
pub struct PerformanceProfiler {
    config: PerformanceConfig,
    performance_data: Arc<RwLock<Vec<PerformanceSnapshot>>>,
    resource_usage: Arc<RwLock<ResourceUsage>>,
    is_running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub collection_interval_seconds: u64,
    pub max_snapshots: usize,
    pub enable_cpu_profiling: bool,
    pub enable_memory_profiling: bool,
    pub enable_io_profiling: bool,
    pub enable_network_profiling: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub memory_usage_percent: f64,
    pub disk_read_bytes_per_sec: u64,
    pub disk_write_bytes_per_sec: u64,
    pub network_rx_bytes_per_sec: u64,
    pub network_tx_bytes_per_sec: u64,
    pub active_connections: u32,
    pub thread_count: u32,
    pub file_descriptors: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub timestamp: DateTime<Utc>,
    pub cpu_cores: u32,
    pub total_memory_bytes: u64,
    pub available_memory_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_available_bytes: u64,
    pub load_average: Option<(f64, f64, f64)>,
    pub process_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    pub timestamp: DateTime<Utc>,
    pub metrics: PerformanceMetrics,
    pub resource_usage: ResourceUsage,
    pub custom_metrics: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileReport {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_seconds: f64,
    pub snapshots: Vec<PerformanceSnapshot>,
    pub summary: PerformanceSummary,
    pub anomalies: Vec<PerformanceAnomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub avg_cpu_percent: f64,
    pub max_cpu_percent: f64,
    pub avg_memory_usage: u64,
    pub max_memory_usage: u64,
    pub total_disk_reads: u64,
    pub total_disk_writes: u64,
    pub total_network_rx: u64,
    pub total_network_tx: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAnomaly {
    pub timestamp: DateTime<Utc>,
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub description: String,
    pub metric_name: String,
    pub actual_value: f64,
    pub expected_range: (f64, f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    CpuSpike,
    MemoryLeak,
    DiskIoHigh,
    NetworkTrafficHigh,
    ResponseTimeSlow,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl PerformanceProfiler {
    pub async fn new(config: PerformanceConfig) -> Result<Self, PerformanceError> {
        Ok(Self {
            config,
            performance_data: Arc::new(RwLock::new(Vec::new())),
            resource_usage: Arc::new(RwLock::new(ResourceUsage::default())),
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start(&self) -> Result<(), PerformanceError> {
        let mut running = self.is_running.write().await;
        if *running {
            return Err(PerformanceError::AlreadyRunning);
        }
        *running = true;
        log::info!("Performance profiler started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), PerformanceError> {
        let mut running = self.is_running.write().await;
        *running = false;
        log::info!("Performance profiler stopped");
        Ok(())
    }

    pub async fn get_current_metrics(&self) -> Result<PerformanceMetrics, PerformanceError> {
        // Placeholder implementation
        Ok(PerformanceMetrics {
            cpu_usage_percent: 15.5,
            memory_usage_bytes: 1024 * 1024 * 512, // 512MB
            memory_usage_percent: 25.0,
            disk_read_bytes_per_sec: 1024 * 100,
            disk_write_bytes_per_sec: 1024 * 50,
            network_rx_bytes_per_sec: 1024 * 10,
            network_tx_bytes_per_sec: 1024 * 5,
            active_connections: 10,
            thread_count: 8,
            file_descriptors: 50,
        })
    }

    pub async fn get_profile_report(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<ProfileReport, PerformanceError> {
        let data = self.performance_data.read().await;
        let filtered_snapshots: Vec<_> = data
            .iter()
            .filter(|s| s.timestamp >= start && s.timestamp <= end)
            .cloned()
            .collect();

        let summary = self.calculate_summary(&filtered_snapshots);
        let anomalies = self.detect_anomalies(&filtered_snapshots);

        Ok(ProfileReport {
            start_time: start,
            end_time: end,
            duration_seconds: end.signed_duration_since(start).num_seconds() as f64,
            snapshots: filtered_snapshots,
            summary,
            anomalies,
        })
    }

    fn calculate_summary(&self, snapshots: &[PerformanceSnapshot]) -> PerformanceSummary {
        if snapshots.is_empty() {
            return PerformanceSummary::default();
        }

        let mut total_cpu = 0.0f64;
        let mut max_cpu = 0.0f64;
        let mut total_memory = 0u64;
        let mut max_memory = 0u64;
        let mut total_disk_reads = 0u64;
        let mut total_disk_writes = 0u64;
        let mut total_network_rx = 0u64;
        let mut total_network_tx = 0u64;

        for snapshot in snapshots {
            total_cpu += snapshot.metrics.cpu_usage_percent;
            max_cpu = max_cpu.max(snapshot.metrics.cpu_usage_percent);
            
            total_memory += snapshot.metrics.memory_usage_bytes;
            max_memory = max_memory.max(snapshot.metrics.memory_usage_bytes);
            
            total_disk_reads += snapshot.metrics.disk_read_bytes_per_sec;
            total_disk_writes += snapshot.metrics.disk_write_bytes_per_sec;
            
            total_network_rx += snapshot.metrics.network_rx_bytes_per_sec;
            total_network_tx += snapshot.metrics.network_tx_bytes_per_sec;
        }

        let count = snapshots.len() as f64;
        
        PerformanceSummary {
            avg_cpu_percent: total_cpu / count,
            max_cpu_percent: max_cpu,
            avg_memory_usage: (total_memory as f64 / count) as u64,
            max_memory_usage: max_memory,
            total_disk_reads,
            total_disk_writes,
            total_network_rx,
            total_network_tx,
        }
    }

    fn detect_anomalies(&self, _snapshots: &[PerformanceSnapshot]) -> Vec<PerformanceAnomaly> {
        // Placeholder implementation
        Vec::new()
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            collection_interval_seconds: 30,
            max_snapshots: 2880, // 24 hours at 30-second intervals
            enable_cpu_profiling: true,
            enable_memory_profiling: true,
            enable_io_profiling: true,
            enable_network_profiling: true,
        }
    }
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            cpu_cores: 4,
            total_memory_bytes: 1024 * 1024 * 1024 * 8, // 8GB
            available_memory_bytes: 1024 * 1024 * 1024 * 6, // 6GB available
            disk_total_bytes: 1024 * 1024 * 1024 * 500, // 500GB
            disk_available_bytes: 1024 * 1024 * 1024 * 300, // 300GB available
            load_average: Some((0.5, 0.7, 0.8)),
            process_count: 150,
        }
    }
}

impl Default for PerformanceSummary {
    fn default() -> Self {
        Self {
            avg_cpu_percent: 0.0,
            max_cpu_percent: 0.0,
            avg_memory_usage: 0,
            max_memory_usage: 0,
            total_disk_reads: 0,
            total_disk_writes: 0,
            total_network_rx: 0,
            total_network_tx: 0,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PerformanceError {
    #[error("Performance profiler already running")]
    AlreadyRunning,
    
    #[error("Performance profiler not running")]
    NotRunning,
    
    #[error("Data collection error: {0}")]
    DataCollectionError(String),
}