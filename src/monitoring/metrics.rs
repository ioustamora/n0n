use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Metrics collector for real-time metrics gathering and storage
#[derive(Clone)]
pub struct MetricsCollector {
    config: MetricsConfig,
    metrics_store: Arc<RwLock<MetricsStore>>,
    background_tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    is_running: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub storage_path: PathBuf,
    pub collection_interval_seconds: u64,
    pub buffer_size: usize,
    pub enable_system_metrics: bool,
    pub custom_metrics: Vec<CustomMetricConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomMetricConfig {
    pub name: String,
    pub metric_type: MetricType,
    pub description: String,
    pub labels: Vec<String>,
    pub thresholds: Vec<MetricThreshold>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricThreshold {
    pub level: ThresholdLevel,
    pub value: f64,
    pub comparison: ThresholdComparison,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThresholdLevel {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThresholdComparison {
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Equal,
    NotEqual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram { buckets: Vec<f64>, values: Vec<u64> },
    Summary { quantiles: Vec<(f64, f64)>, sum: f64, count: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricLabel {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesData {
    pub metric_name: String,
    pub labels: HashMap<String, String>,
    pub values: Vec<TimeSeriesPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: DateTime<Utc>,
    pub value: MetricValue,
}

struct MetricsStore {
    metrics: HashMap<String, TimeSeriesData>,
    system_metrics: SystemMetrics,
    last_collection: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default)]
struct SystemMetrics {
    cpu_usage: f64,
    memory_usage: f64,
    disk_usage: f64,
    network_rx_bytes: u64,
    network_tx_bytes: u64,
    open_file_descriptors: u64,
    uptime_seconds: u64,
}

impl MetricsCollector {
    pub async fn new(config: MetricsConfig) -> Result<Self, MetricsError> {
        // Create storage directory if it doesn't exist
        if let Some(parent) = config.storage_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| MetricsError::StorageError(e.to_string()))?;
        }

        let metrics_store = Arc::new(RwLock::new(MetricsStore {
            metrics: HashMap::new(),
            system_metrics: SystemMetrics::default(),
            last_collection: None,
        }));

        Ok(Self {
            config,
            metrics_store,
            background_tasks: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(Mutex::new(false)),
        })
    }

    pub async fn start(&self) -> Result<(), MetricsError> {
        let mut is_running = self.is_running.lock().unwrap();
        if *is_running {
            return Err(MetricsError::AlreadyRunning);
        }

        *is_running = true;
        drop(is_running);

        // Start system metrics collection if enabled
        if self.config.enable_system_metrics {
            let system_metrics_task = self.start_system_metrics_collection();
            let mut tasks = self.background_tasks.lock().unwrap();
            tasks.push(system_metrics_task);
        }

        // Start metrics persistence task
        let persistence_task = self.start_metrics_persistence();
        let mut tasks = self.background_tasks.lock().unwrap();
        tasks.push(persistence_task);

        log::info!("Metrics collector started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), MetricsError> {
        let mut is_running = self.is_running.lock().unwrap();
        if !*is_running {
            return Ok(());
        }

        *is_running = false;
        drop(is_running);

        // Stop background tasks
        let mut tasks = self.background_tasks.lock().unwrap();
        for task in tasks.drain(..) {
            task.abort();
        }

        // Persist any remaining metrics
        self.persist_metrics().await?;

        log::info!("Metrics collector stopped");
        Ok(())
    }

    pub async fn record_metric(
        &self,
        name: &str,
        value: MetricValue,
        labels: Option<HashMap<String, String>>,
    ) -> Result<(), MetricsError> {
        let mut store = self.metrics_store.write().await;
        let labels = labels.unwrap_or_default();
        
        let key = format!("{}:{}", name, self.labels_to_string(&labels));
        
        let time_series = store.metrics.entry(key.clone()).or_insert_with(|| {
            TimeSeriesData {
                metric_name: name.to_string(),
                labels: labels.clone(),
                values: Vec::new(),
            }
        });

        time_series.values.push(TimeSeriesPoint {
            timestamp: Utc::now(),
            value,
        });

        // Limit buffer size
        if time_series.values.len() > self.config.buffer_size {
            time_series.values.remove(0);
        }

        Ok(())
    }

    pub async fn get_current_metrics(&self) -> Result<HashMap<String, MetricValue>, MetricsError> {
        let store = self.metrics_store.read().await;
        let mut current_metrics = HashMap::new();

        // Get latest value from each time series
        for (key, time_series) in &store.metrics {
            if let Some(latest_point) = time_series.values.last() {
                current_metrics.insert(key.clone(), latest_point.value.clone());
            }
        }

        // Add system metrics if enabled
        if self.config.enable_system_metrics {
            current_metrics.insert(
                "system.cpu_usage".to_string(), 
                MetricValue::Gauge(store.system_metrics.cpu_usage)
            );
            current_metrics.insert(
                "system.memory_usage".to_string(), 
                MetricValue::Gauge(store.system_metrics.memory_usage)
            );
            current_metrics.insert(
                "system.disk_usage".to_string(), 
                MetricValue::Gauge(store.system_metrics.disk_usage)
            );
            current_metrics.insert(
                "system.network_rx_bytes".to_string(), 
                MetricValue::Counter(store.system_metrics.network_rx_bytes)
            );
            current_metrics.insert(
                "system.network_tx_bytes".to_string(), 
                MetricValue::Counter(store.system_metrics.network_tx_bytes)
            );
            current_metrics.insert(
                "system.open_file_descriptors".to_string(), 
                MetricValue::Gauge(store.system_metrics.open_file_descriptors as f64)
            );
            current_metrics.insert(
                "system.uptime_seconds".to_string(), 
                MetricValue::Counter(store.system_metrics.uptime_seconds)
            );
        }

        Ok(current_metrics)
    }

    pub async fn get_time_series(
        &self,
        metric_name: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<TimeSeriesData>, MetricsError> {
        let store = self.metrics_store.read().await;
        let mut result = Vec::new();

        for time_series in store.metrics.values() {
            if time_series.metric_name == metric_name {
                let filtered_values: Vec<TimeSeriesPoint> = time_series
                    .values
                    .iter()
                    .filter(|point| point.timestamp >= start_time && point.timestamp <= end_time)
                    .cloned()
                    .collect();

                if !filtered_values.is_empty() {
                    result.push(TimeSeriesData {
                        metric_name: time_series.metric_name.clone(),
                        labels: time_series.labels.clone(),
                        values: filtered_values,
                    });
                }
            }
        }

        Ok(result)
    }

    pub async fn export_prometheus_format(&self) -> Result<String, MetricsError> {
        let metrics = self.get_current_metrics().await?;
        let mut prometheus_output = String::new();

        for (name, value) in metrics {
            let metric_name = name.split(':').next().unwrap_or(&name);
            
            match value {
                MetricValue::Counter(v) => {
                    prometheus_output.push_str(&format!(
                        "# TYPE {} counter\n{} {}\n", 
                        metric_name, metric_name, v
                    ));
                }
                MetricValue::Gauge(v) => {
                    prometheus_output.push_str(&format!(
                        "# TYPE {} gauge\n{} {}\n", 
                        metric_name, metric_name, v
                    ));
                }
                MetricValue::Histogram { buckets, values } => {
                    prometheus_output.push_str(&format!("# TYPE {} histogram\n", metric_name));
                    for (i, bucket) in buckets.iter().enumerate() {
                        if let Some(count) = values.get(i) {
                            prometheus_output.push_str(&format!(
                                "{}_bucket{{le=\"{}\"}} {}\n", 
                                metric_name, bucket, count
                            ));
                        }
                    }
                }
                MetricValue::Summary { quantiles, sum, count } => {
                    prometheus_output.push_str(&format!("# TYPE {} summary\n", metric_name));
                    for (quantile, value) in quantiles {
                        prometheus_output.push_str(&format!(
                            "{}{{quantile=\"{}\"}} {}\n", 
                            metric_name, quantile, value
                        ));
                    }
                    prometheus_output.push_str(&format!("{}_sum {}\n", metric_name, sum));
                    prometheus_output.push_str(&format!("{}_count {}\n", metric_name, count));
                }
            }
        }

        Ok(prometheus_output)
    }

    pub async fn cleanup_old_data(&self, cutoff_date: DateTime<Utc>) -> Result<(), MetricsError> {
        let mut store = self.metrics_store.write().await;
        
        for time_series in store.metrics.values_mut() {
            time_series.values.retain(|point| point.timestamp > cutoff_date);
        }

        // Remove empty time series
        store.metrics.retain(|_, time_series| !time_series.values.is_empty());

        log::info!("Cleaned up metrics data older than {}", cutoff_date);
        Ok(())
    }

    fn start_system_metrics_collection(&self) -> tokio::task::JoinHandle<()> {
        let collector = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                Duration::from_secs(collector.config.collection_interval_seconds)
            );

            loop {
                interval.tick().await;
                
                if !*collector.is_running.lock().unwrap() {
                    break;
                }

                if let Err(e) = collector.collect_system_metrics().await {
                    log::error!("Failed to collect system metrics: {}", e);
                }
            }
        })
    }

    fn start_metrics_persistence(&self) -> tokio::task::JoinHandle<()> {
        let collector = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes

            loop {
                interval.tick().await;
                
                if !*collector.is_running.lock().unwrap() {
                    break;
                }

                if let Err(e) = collector.persist_metrics().await {
                    log::error!("Failed to persist metrics: {}", e);
                }
            }
        })
    }

    async fn collect_system_metrics(&self) -> Result<(), MetricsError> {
        let mut store = self.metrics_store.write().await;
        
        // CPU usage
        store.system_metrics.cpu_usage = self.get_cpu_usage().await?;
        
        // Memory usage
        store.system_metrics.memory_usage = self.get_memory_usage().await?;
        
        // Disk usage
        store.system_metrics.disk_usage = self.get_disk_usage().await?;
        
        // Network statistics
        let (rx_bytes, tx_bytes) = self.get_network_stats().await?;
        store.system_metrics.network_rx_bytes = rx_bytes;
        store.system_metrics.network_tx_bytes = tx_bytes;
        
        // File descriptors
        store.system_metrics.open_file_descriptors = self.get_open_file_descriptors().await?;
        
        // Uptime
        store.system_metrics.uptime_seconds = self.get_uptime_seconds().await?;

        store.last_collection = Some(Utc::now());

        Ok(())
    }

    async fn get_cpu_usage(&self) -> Result<f64, MetricsError> {
        // Simplified CPU usage - in production, use proper system monitoring libraries
        Ok(0.0) // Placeholder
    }

    async fn get_memory_usage(&self) -> Result<f64, MetricsError> {
        // Simplified memory usage - in production, use proper system monitoring libraries
        Ok(0.0) // Placeholder
    }

    async fn get_disk_usage(&self) -> Result<f64, MetricsError> {
        // Simplified disk usage - in production, use proper system monitoring libraries
        Ok(0.0) // Placeholder
    }

    async fn get_network_stats(&self) -> Result<(u64, u64), MetricsError> {
        // Simplified network stats - in production, use proper system monitoring libraries
        Ok((0, 0)) // Placeholder
    }

    async fn get_open_file_descriptors(&self) -> Result<u64, MetricsError> {
        // Simplified file descriptor count - in production, use proper system monitoring libraries
        Ok(0) // Placeholder
    }

    async fn get_uptime_seconds(&self) -> Result<u64, MetricsError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| MetricsError::SystemError(e.to_string()))
    }

    async fn persist_metrics(&self) -> Result<(), MetricsError> {
        let store = self.metrics_store.read().await;
        
        let metrics_data = serde_json::to_string(&*store)
            .map_err(|e| MetricsError::SerializationError(e.to_string()))?;

        let file_path = self.config.storage_path.join(format!(
            "metrics_{}.json", 
            Utc::now().format("%Y%m%d_%H%M%S")
        ));

        tokio::fs::write(&file_path, metrics_data).await
            .map_err(|e| MetricsError::StorageError(e.to_string()))?;

        Ok(())
    }

    fn labels_to_string(&self, labels: &HashMap<String, String>) -> String {
        let mut pairs: Vec<_> = labels.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);
        pairs.into_iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            storage_path: PathBuf::from("./metrics"),
            collection_interval_seconds: 60,
            buffer_size: 10000,
            enable_system_metrics: true,
            custom_metrics: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("System error: {0}")]
    SystemError(String),
    
    #[error("Metrics collector is already running")]
    AlreadyRunning,
    
    #[error("Metrics collector is not running")]
    NotRunning,
    
    #[error("Invalid metric configuration: {0}")]
    InvalidConfig(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_metrics_collection() {
        let temp_dir = TempDir::new().unwrap();
        let config = MetricsConfig {
            storage_path: temp_dir.path().to_path_buf(),
            collection_interval_seconds: 1,
            buffer_size: 100,
            enable_system_metrics: false,
            custom_metrics: Vec::new(),
        };

        let collector = MetricsCollector::new(config).await.unwrap();
        collector.start().await.unwrap();

        // Test recording metrics
        collector.record_metric(
            "test_counter", 
            MetricValue::Counter(42), 
            None
        ).await.unwrap();

        collector.record_metric(
            "test_gauge", 
            MetricValue::Gauge(3.14), 
            Some([("label".to_string(), "value".to_string())].into())
        ).await.unwrap();

        // Test getting current metrics
        let metrics = collector.get_current_metrics().await.unwrap();
        assert!(metrics.len() >= 2);

        // Test Prometheus export
        let prometheus_format = collector.export_prometheus_format().await.unwrap();
        assert!(prometheus_format.contains("test_counter"));
        assert!(prometheus_format.contains("test_gauge"));

        collector.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_time_series_queries() {
        let temp_dir = TempDir::new().unwrap();
        let config = MetricsConfig {
            storage_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let collector = MetricsCollector::new(config).await.unwrap();

        let start_time = Utc::now();
        
        // Record some metrics over time
        for i in 0..5 {
            collector.record_metric(
                "test_series", 
                MetricValue::Counter(i), 
                None
            ).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let end_time = Utc::now();

        // Query time series
        let time_series = collector.get_time_series("test_series", start_time, end_time).await.unwrap();
        assert_eq!(time_series.len(), 1);
        assert_eq!(time_series[0].values.len(), 5);
    }
}