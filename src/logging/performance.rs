use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
use anyhow::Result;

/// Performance metrics for operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Operation name
    pub operation: String,
    /// Number of times the operation was executed
    pub count: u64,
    /// Total duration of all executions
    pub total_duration: Duration,
    /// Minimum execution time
    pub min_duration: Duration,
    /// Maximum execution time
    pub max_duration: Duration,
    /// Average execution time
    pub avg_duration: Duration,
    /// Last execution time
    pub last_duration: Duration,
    /// Timestamp of last execution
    pub last_execution: chrono::DateTime<chrono::Utc>,
    /// Percentile data (50th, 90th, 95th, 99th)
    pub percentiles: HashMap<u8, Duration>,
    /// Recent execution times (for calculating percentiles)
    recent_times: Vec<Duration>,
}

impl PerformanceMetrics {
    pub fn new(operation: String) -> Self {
        Self {
            operation,
            count: 0,
            total_duration: Duration::ZERO,
            min_duration: Duration::MAX,
            max_duration: Duration::ZERO,
            avg_duration: Duration::ZERO,
            last_duration: Duration::ZERO,
            last_execution: chrono::Utc::now(),
            percentiles: HashMap::new(),
            recent_times: Vec::new(),
        }
    }
    
    /// Add a new measurement
    pub fn add_measurement(&mut self, duration: Duration) {
        self.count += 1;
        self.total_duration += duration;
        self.min_duration = self.min_duration.min(duration);
        self.max_duration = self.max_duration.max(duration);
        self.avg_duration = self.total_duration / self.count as u32;
        self.last_duration = duration;
        self.last_execution = chrono::Utc::now();
        
        // Keep recent times for percentile calculation (last 1000 measurements)
        self.recent_times.push(duration);
        if self.recent_times.len() > 1000 {
            self.recent_times.remove(0);
        }
        
        // Update percentiles
        self.calculate_percentiles();
    }
    
    /// Calculate percentiles from recent measurements
    fn calculate_percentiles(&mut self) {
        if self.recent_times.is_empty() {
            return;
        }
        
        let mut sorted_times = self.recent_times.clone();
        sorted_times.sort();
        
        let percentiles_to_calc = vec![50, 90, 95, 99];
        for p in percentiles_to_calc {
            let index = ((p as f64 / 100.0) * (sorted_times.len() - 1) as f64) as usize;
            let index = index.min(sorted_times.len() - 1);
            self.percentiles.insert(p, sorted_times[index]);
        }
    }
    
    /// Get throughput (operations per second)
    pub fn throughput(&self) -> f64 {
        if self.total_duration.is_zero() {
            return 0.0;
        }
        self.count as f64 / self.total_duration.as_secs_f64()
    }
    
    /// Check if performance is degrading (last measurement > 95th percentile)
    pub fn is_degraded(&self) -> bool {
        if let Some(p95) = self.percentiles.get(&95) {
            self.last_duration > *p95 * 2 // Consider degraded if > 2x the 95th percentile
        } else {
            false
        }
    }
}

/// Performance monitoring system
pub struct PerformanceMonitor {
    metrics: Arc<RwLock<HashMap<String, PerformanceMetrics>>>,
    enabled: bool,
}

impl PerformanceMonitor {
    pub fn new(enabled: bool) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            enabled,
        }
    }
    
    /// Record a measurement for an operation
    pub async fn record_measurement(&self, operation: &str, duration: Duration) {
        if !self.enabled {
            return;
        }
        
        let mut metrics = self.metrics.write().await;
        let entry = metrics.entry(operation.to_string())
            .or_insert_with(|| PerformanceMetrics::new(operation.to_string()));
        
        entry.add_measurement(duration);
        
        // Log performance info
        tracing::info!(
            operation = operation,
            duration_ms = duration.as_millis(),
            count = entry.count,
            avg_ms = entry.avg_duration.as_millis(),
            throughput = entry.throughput(),
            category = "performance",
            "Performance measurement recorded"
        );
        
        // Log warning if performance is degraded
        if entry.is_degraded() {
            tracing::warn!(
                operation = operation,
                duration_ms = duration.as_millis(),
                p95_ms = entry.percentiles.get(&95).map(|d| d.as_millis()),
                category = "performance",
                "Performance degradation detected"
            );
        }
    }
    
    /// Get metrics for a specific operation
    pub async fn get_metrics(&self, operation: &str) -> Option<PerformanceMetrics> {
        let metrics = self.metrics.read().await;
        metrics.get(operation).cloned()
    }
    
    /// Get all metrics
    pub async fn get_all_metrics(&self) -> HashMap<String, PerformanceMetrics> {
        let metrics = self.metrics.read().await;
        metrics.clone()
    }
    
    /// Get performance summary
    pub async fn get_performance_summary(&self) -> PerformanceSummary {
        let metrics = self.metrics.read().await;
        
        let mut summary = PerformanceSummary {
            total_operations: 0,
            total_measurements: 0,
            slowest_operation: None,
            fastest_operation: None,
            degraded_operations: Vec::new(),
            top_operations: Vec::new(),
        };
        
        summary.total_operations = metrics.len();
        
        for (name, metric) in metrics.iter() {
            summary.total_measurements += metric.count;
            
            // Find slowest operation
            if let Some(ref slowest) = summary.slowest_operation {
                if metric.avg_duration > slowest.1 {
                    summary.slowest_operation = Some((name.clone(), metric.avg_duration));
                }
            } else {
                summary.slowest_operation = Some((name.clone(), metric.avg_duration));
            }
            
            // Find fastest operation
            if let Some(ref fastest) = summary.fastest_operation {
                if metric.avg_duration < fastest.1 {
                    summary.fastest_operation = Some((name.clone(), metric.avg_duration));
                }
            } else {
                summary.fastest_operation = Some((name.clone(), metric.avg_duration));
            }
            
            // Check for degraded operations
            if metric.is_degraded() {
                summary.degraded_operations.push(name.clone());
            }
            
            // Add to top operations by count
            summary.top_operations.push((name.clone(), metric.count));
        }
        
        // Sort top operations by count
        summary.top_operations.sort_by(|a, b| b.1.cmp(&a.1));
        summary.top_operations.truncate(10); // Keep top 10
        
        summary
    }
    
    /// Reset all metrics
    pub async fn reset_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.clear();
        
        tracing::info!(
            category = "performance",
            "Performance metrics reset"
        );
    }
    
    /// Export metrics to JSON
    pub async fn export_metrics(&self) -> Result<String> {
        let metrics = self.metrics.read().await;
        Ok(serde_json::to_string_pretty(&*metrics)?)
    }
}

/// Performance summary for reporting
#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub total_operations: usize,
    pub total_measurements: u64,
    pub slowest_operation: Option<(String, Duration)>,
    pub fastest_operation: Option<(String, Duration)>,
    pub degraded_operations: Vec<String>,
    pub top_operations: Vec<(String, u64)>, // (operation, count)
}

/// Performance timer that automatically records measurements
pub struct PerformanceTimer {
    monitor: Arc<PerformanceMonitor>,
    operation: String,
    start_time: Instant,
}

impl PerformanceTimer {
    pub fn new(monitor: Arc<PerformanceMonitor>, operation: String) -> Self {
        Self {
            monitor,
            operation,
            start_time: Instant::now(),
        }
    }
}

impl Drop for PerformanceTimer {
    fn drop(&mut self) {
        let duration = self.start_time.elapsed();
        let monitor = self.monitor.clone();
        let operation = self.operation.clone();
        
        tokio::spawn(async move {
            monitor.record_measurement(&operation, duration).await;
        });
    }
}

/// Global performance monitor
static mut PERFORMANCE_MONITOR: Option<Arc<PerformanceMonitor>> = None;
static PERF_INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the global performance monitor
pub fn init_performance_monitor(enabled: bool) {
    PERF_INIT.call_once(|| {
        unsafe {
            PERFORMANCE_MONITOR = Some(Arc::new(PerformanceMonitor::new(enabled)));
        }
    });
}

/// Get the global performance monitor
pub fn get_performance_monitor() -> Option<Arc<PerformanceMonitor>> {
    unsafe { PERFORMANCE_MONITOR.as_ref().cloned() }
}

/// Create a performance timer for an operation
#[macro_export]
macro_rules! perf_timer {
    ($operation:expr) => {
        let _perf_timer = if let Some(monitor) = $crate::logging::performance::get_performance_monitor() {
            Some($crate::logging::performance::PerformanceTimer::new(monitor, $operation.to_string()))
        } else {
            None
        };
    };
}

/// Record a manual performance measurement
#[macro_export]
macro_rules! perf_record {
    ($operation:expr, $duration:expr) => {
        if let Some(monitor) = $crate::logging::performance::get_performance_monitor() {
            tokio::spawn(async move {
                monitor.record_measurement($operation, $duration).await;
            });
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[test]
    fn test_performance_metrics_creation() {
        let mut metrics = PerformanceMetrics::new("test_operation".to_string());
        
        assert_eq!(metrics.operation, "test_operation");
        assert_eq!(metrics.count, 0);
        assert_eq!(metrics.total_duration, Duration::ZERO);
    }

    #[test]
    fn test_performance_metrics_measurements() {
        let mut metrics = PerformanceMetrics::new("test_operation".to_string());
        
        // Add some measurements
        metrics.add_measurement(Duration::from_millis(100));
        metrics.add_measurement(Duration::from_millis(200));
        metrics.add_measurement(Duration::from_millis(150));
        
        assert_eq!(metrics.count, 3);
        assert_eq!(metrics.min_duration, Duration::from_millis(100));
        assert_eq!(metrics.max_duration, Duration::from_millis(200));
        assert_eq!(metrics.avg_duration, Duration::from_millis(150));
        assert!(metrics.throughput() > 0.0);
    }

    #[tokio::test]
    async fn test_performance_monitor() {
        let monitor = PerformanceMonitor::new(true);
        
        // Record some measurements
        monitor.record_measurement("operation1", Duration::from_millis(100)).await;
        monitor.record_measurement("operation1", Duration::from_millis(200)).await;
        monitor.record_measurement("operation2", Duration::from_millis(50)).await;
        
        // Get metrics
        let op1_metrics = monitor.get_metrics("operation1").await.unwrap();
        assert_eq!(op1_metrics.count, 2);
        
        let all_metrics = monitor.get_all_metrics().await;
        assert_eq!(all_metrics.len(), 2);
        
        // Get summary
        let summary = monitor.get_performance_summary().await;
        assert_eq!(summary.total_operations, 2);
        assert_eq!(summary.total_measurements, 3);
    }

    #[tokio::test]
    async fn test_performance_timer() {
        let monitor = Arc::new(PerformanceMonitor::new(true));
        
        {
            let _timer = PerformanceTimer::new(monitor.clone(), "test_timer".to_string());
            sleep(Duration::from_millis(10)).await;
        } // Timer should record when dropped
        
        // Give the async recording time to complete
        sleep(Duration::from_millis(10)).await;
        
        let metrics = monitor.get_metrics("test_timer").await;
        assert!(metrics.is_some());
        assert_eq!(metrics.unwrap().count, 1);
    }

    #[test]
    fn test_percentile_calculation() {
        let mut metrics = PerformanceMetrics::new("test".to_string());
        
        // Add measurements to test percentile calculation
        for i in 1..=100 {
            metrics.add_measurement(Duration::from_millis(i));
        }
        
        // Check percentiles
        assert!(metrics.percentiles.contains_key(&50));
        assert!(metrics.percentiles.contains_key(&90));
        assert!(metrics.percentiles.contains_key(&95));
        assert!(metrics.percentiles.contains_key(&99));
        
        let p50 = metrics.percentiles[&50];
        let p95 = metrics.percentiles[&95];
        assert!(p95 > p50);
    }

    #[tokio::test]
    async fn test_performance_summary() {
        let monitor = PerformanceMonitor::new(true);
        
        // Add various measurements
        monitor.record_measurement("fast_op", Duration::from_millis(10)).await;
        monitor.record_measurement("slow_op", Duration::from_millis(1000)).await;
        monitor.record_measurement("frequent_op", Duration::from_millis(100)).await;
        monitor.record_measurement("frequent_op", Duration::from_millis(100)).await;
        monitor.record_measurement("frequent_op", Duration::from_millis(100)).await;
        
        let summary = monitor.get_performance_summary().await;
        
        assert_eq!(summary.total_operations, 3);
        assert_eq!(summary.total_measurements, 5);
        assert!(summary.slowest_operation.is_some());
        assert!(summary.fastest_operation.is_some());
        assert!(!summary.top_operations.is_empty());
        
        // The most frequent operation should be at the top
        assert_eq!(summary.top_operations[0].0, "frequent_op");
        assert_eq!(summary.top_operations[0].1, 3);
    }
}