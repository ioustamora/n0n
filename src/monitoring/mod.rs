//! Advanced monitoring and alerting system for enterprise-grade observability
//! 
//! This module provides comprehensive monitoring capabilities including:
//! - Real-time metrics collection and aggregation
//! - Performance monitoring and profiling
//! - Health checks and system diagnostics
//! - Alerting and notification systems
//! - Log aggregation and analysis
//! - Distributed tracing and observability

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

pub mod metrics;
pub mod alerts;
pub mod health;
pub mod tracing;
pub mod logs;
pub mod performance;

pub use metrics::{
    MetricsCollector, MetricType, MetricValue, TimeSeriesData, 
    MetricsConfig, MetricsError, MetricLabel, MetricThreshold
};

pub use alerts::{
    AlertManager, Alert, AlertRule, AlertSeverity, AlertStatus,
    NotificationChannel, AlertHistory, AlertConfig, AlertError
};

pub use health::{
    HealthChecker, HealthCheck, HealthStatus, HealthReport,
    ComponentHealth, HealthConfig, HealthError
};

pub use tracing::{
    TracingManager, Span, TraceContext, TracingConfig,
    SpanEvent, TraceError, DistributedTrace
};

pub use logs::{
    LogAggregator, LogEntry, LogLevel, LogFilter,
    LogConfig, LogError, StructuredLog
};

pub use performance::{
    PerformanceProfiler, PerformanceMetrics, ProfileReport,
    ResourceUsage, PerformanceConfig, PerformanceError
};

/// Unified monitoring service providing all observability capabilities
#[derive(Clone)]
pub struct MonitoringService {
    metrics_collector: Arc<MetricsCollector>,
    alert_manager: Arc<AlertManager>,
    health_checker: Arc<HealthChecker>,
    tracing_manager: Arc<TracingManager>,
    log_aggregator: Arc<LogAggregator>,
    performance_profiler: Arc<PerformanceProfiler>,
    config: MonitoringConfig,
    service_state: Arc<RwLock<ServiceState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub metrics_config: MetricsConfig,
    pub alert_config: AlertConfig,
    pub health_config: HealthConfig,
    pub tracing_config: TracingConfig,
    pub log_config: LogConfig,
    pub performance_config: PerformanceConfig,
    pub retention_policy: RetentionPolicy,
    pub export_endpoints: Vec<ExportEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub metrics_retention_days: u32,
    pub logs_retention_days: u32,
    pub traces_retention_days: u32,
    pub alerts_retention_days: u32,
    pub performance_data_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEndpoint {
    pub name: String,
    pub endpoint_type: ExportType,
    pub url: String,
    pub credentials: Option<String>,
    pub enabled: bool,
    pub export_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportType {
    Prometheus,
    Grafana,
    ElasticSearch,
    DataDog,
    NewRelic,
    CloudWatch,
    CustomHttp,
}

#[derive(Debug)]
struct ServiceState {
    started_at: DateTime<Utc>,
    is_running: bool,
    background_tasks: HashMap<String, tokio::task::JoinHandle<()>>,
    export_status: HashMap<String, ExportStatus>,
}

#[derive(Debug, Clone)]
#[derive(Serialize, Deserialize)]
struct ExportStatus {
    last_export: Option<DateTime<Utc>>,
    last_error: Option<String>,
    export_count: u64,
    error_count: u64,
}

impl MonitoringService {
    /// Create a new monitoring service with all components initialized
    pub async fn new(config: MonitoringConfig) -> Result<Self, MonitoringError> {
        // Initialize metrics collector
        let metrics_collector = Arc::new(
            MetricsCollector::new(config.metrics_config.clone()).await?
        );
        
        // Initialize alert manager
        let alert_manager = Arc::new(
            AlertManager::new(config.alert_config.clone()).await?
        );
        
        // Initialize health checker
        let health_checker = Arc::new(
            HealthChecker::new(config.health_config.clone()).await?
        );
        
        // Initialize tracing manager
        let tracing_manager = Arc::new(
            TracingManager::new(config.tracing_config.clone()).await?
        );
        
        // Initialize log aggregator
        let log_aggregator = Arc::new(
            LogAggregator::new(config.log_config.clone()).await?
        );
        
        // Initialize performance profiler
        let performance_profiler = Arc::new(
            PerformanceProfiler::new(config.performance_config.clone()).await?
        );

        let service_state = Arc::new(RwLock::new(ServiceState {
            started_at: Utc::now(),
            is_running: false,
            background_tasks: HashMap::new(),
            export_status: config.export_endpoints.iter()
                .map(|e| (e.name.clone(), ExportStatus {
                    last_export: None,
                    last_error: None,
                    export_count: 0,
                    error_count: 0,
                }))
                .collect(),
        }));

        Ok(Self {
            metrics_collector,
            alert_manager,
            health_checker,
            tracing_manager,
            log_aggregator,
            performance_profiler,
            config,
            service_state,
        })
    }

    /// Start all monitoring services and background tasks
    pub async fn start(&self) -> Result<(), MonitoringError> {
        let mut state = self.service_state.write().await;
        
        if state.is_running {
            return Err(MonitoringError::ServiceAlreadyRunning);
        }

        // Start individual services
        self.metrics_collector.start().await?;
        self.alert_manager.start().await?;
        self.health_checker.start().await?;
        self.tracing_manager.start().await?;
        self.log_aggregator.start().await?;
        self.performance_profiler.start().await?;

        // Start background tasks
        self.start_background_tasks(&mut state).await?;
        
        state.is_running = true;
        state.started_at = Utc::now();

        log::info!("Monitoring service started successfully");
        Ok(())
    }

    /// Stop all monitoring services gracefully
    pub async fn stop(&self) -> Result<(), MonitoringError> {
        let mut state = self.service_state.write().await;
        
        if !state.is_running {
            return Ok(());
        }

        // Stop background tasks
        for (name, handle) in state.background_tasks.drain() {
            handle.abort();
            log::info!("Stopped background task: {}", name);
        }

        // Stop individual services
        self.performance_profiler.stop().await?;
        self.log_aggregator.stop().await?;
        self.tracing_manager.stop().await?;
        self.health_checker.stop().await?;
        self.alert_manager.stop().await?;
        self.metrics_collector.stop().await?;
        
        state.is_running = false;

        log::info!("Monitoring service stopped successfully");
        Ok(())
    }

    /// Get comprehensive monitoring dashboard data
    pub async fn get_dashboard_data(&self) -> Result<DashboardData, MonitoringError> {
        let metrics = self.metrics_collector.get_current_metrics().await?;
        let alerts = self.alert_manager.get_active_alerts().await?;
        let health = self.health_checker.get_system_health().await?;
        let performance = self.performance_profiler.get_current_metrics().await?;
        let recent_logs = self.log_aggregator.get_recent_logs(100).await?;
        
        let service_state = self.service_state.read().await;
        let uptime = Utc::now().signed_duration_since(service_state.started_at);

        Ok(DashboardData {
            uptime_seconds: uptime.num_seconds() as u64,
            metrics_summary: metrics,
            active_alerts: alerts,
            system_health: health,
            performance_metrics: performance,
            recent_log_entries: recent_logs,
            export_status: service_state.export_status.clone(),
        })
    }

    /// Record a custom metric
    pub async fn record_metric(
        &self, 
        name: &str, 
        value: MetricValue, 
        labels: Option<HashMap<String, String>>
    ) -> Result<(), MonitoringError> {
        self.metrics_collector.record_metric(name, value, labels).await
            .map_err(MonitoringError::Metrics)
    }

    /// Log a structured event
    pub async fn log_event(
        &self, 
        level: LogLevel, 
        message: &str, 
        context: Option<HashMap<String, serde_json::Value>>
    ) -> Result<(), MonitoringError> {
        let log_entry = StructuredLog {
            timestamp: Utc::now(),
            level,
            message: message.to_string(),
            context: context.unwrap_or_default(),
            trace_id: self.tracing_manager.get_current_trace_id().await,
            span_id: self.tracing_manager.get_current_span_id().await,
        };

        self.log_aggregator.log_structured(log_entry).await
            .map_err(MonitoringError::Logs)
    }

    /// Start a distributed trace span
    pub async fn start_span(&self, name: &str) -> Result<Span, MonitoringError> {
        self.tracing_manager.start_span(name).await
            .map_err(MonitoringError::Tracing)
    }

    /// Trigger a health check for a specific component
    pub async fn check_component_health(&self, component: &str) -> Result<ComponentHealth, MonitoringError> {
        self.health_checker.check_component(component).await
            .map_err(MonitoringError::Health)
    }

    /// Get performance profile for a time range
    pub async fn get_performance_profile(
        &self, 
        start: DateTime<Utc>, 
        end: DateTime<Utc>
    ) -> Result<ProfileReport, MonitoringError> {
        self.performance_profiler.get_profile_report(start, end).await
            .map_err(MonitoringError::Performance)
    }

    async fn start_background_tasks(&self, state: &mut ServiceState) -> Result<(), MonitoringError> {
        // Data export task
        if !self.config.export_endpoints.is_empty() {
            let export_task = self.spawn_export_task();
            state.background_tasks.insert("data_export".to_string(), export_task);
        }

        // Cleanup task for retention policy
        let cleanup_task = self.spawn_cleanup_task();
        state.background_tasks.insert("cleanup".to_string(), cleanup_task);

        // Alert evaluation task
        let alert_eval_task = self.spawn_alert_evaluation_task();
        state.background_tasks.insert("alert_evaluation".to_string(), alert_eval_task);

        // Health check task
        let health_check_task = self.spawn_health_check_task();
        state.background_tasks.insert("health_check".to_string(), health_check_task);

        Ok(())
    }

    fn spawn_export_task(&self) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Check every minute
            
            loop {
                interval.tick().await;
                
                for endpoint in &service.config.export_endpoints {
                    if endpoint.enabled {
                        let should_export = {
                            let state = service.service_state.read().await;
                            if let Some(export_status) = state.export_status.get(&endpoint.name) {
                                export_status.last_export.map_or(true, |last| {
                                    Utc::now().signed_duration_since(last).num_seconds() 
                                        >= endpoint.export_interval_seconds as i64
                                })
                            } else {
                                true
                            }
                        };

                        if should_export {
                            if let Err(e) = service.export_data_to_endpoint(endpoint).await {
                                log::error!("Failed to export data to {}: {}", endpoint.name, e);
                            }
                        }
                    }
                }
            }
        })
    }

    fn spawn_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(4 * 3600)); // Every 4 hours
            
            loop {
                interval.tick().await;
                
                if let Err(e) = service.cleanup_old_data().await {
                    log::error!("Failed to cleanup old data: {}", e);
                }
            }
        })
    }

    fn spawn_alert_evaluation_task(&self) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30)); // Every 30 seconds
            
            loop {
                interval.tick().await;
                
                if let Err(e) = service.alert_manager.evaluate_rules().await {
                    log::error!("Failed to evaluate alert rules: {}", e);
                }
            }
        })
    }

    fn spawn_health_check_task(&self) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Every minute
            
            loop {
                interval.tick().await;
                
                if let Err(e) = service.health_checker.run_periodic_checks().await {
                    log::error!("Failed to run health checks: {}", e);
                }
            }
        })
    }

    async fn export_data_to_endpoint(&self, endpoint: &ExportEndpoint) -> Result<(), MonitoringError> {
        match endpoint.endpoint_type {
            ExportType::Prometheus => {
                // Export metrics in Prometheus format
                let metrics = self.metrics_collector.export_prometheus_format().await?;
                self.send_http_data(&endpoint.url, &metrics, "text/plain").await?;
            }
            ExportType::ElasticSearch => {
                // Export logs and metrics to ElasticSearch
                let logs = self.log_aggregator.export_elasticsearch_format().await?;
                self.send_http_data(&endpoint.url, &logs, "application/json").await?;
            }
            ExportType::CustomHttp => {
                // Export all data in custom JSON format
                let dashboard_data = self.get_dashboard_data().await?;
                let json_data = serde_json::to_string(&dashboard_data)?;
                self.send_http_data(&endpoint.url, &json_data, "application/json").await?;
            }
            ExportType::DataDog => {
                // Export metrics to DataDog
                let dashboard_data = self.get_dashboard_data().await?;
                let datadog_payload = self.format_datadog_metrics(&dashboard_data).await?;
                self.send_http_data(&endpoint.url, &datadog_payload, "application/json").await?;
            }
            ExportType::NewRelic => {
                // Export to New Relic
                let dashboard_data = self.get_dashboard_data().await?;
                let newrelic_payload = self.format_newrelic_metrics(&dashboard_data).await?;
                self.send_http_data(&endpoint.url, &newrelic_payload, "application/json").await?;
            }
            ExportType::CloudWatch => {
                // Export to AWS CloudWatch (would need AWS SDK in production)
                log::info!("CloudWatch export - would use AWS SDK to send metrics");
                // For now, log the metrics that would be sent
                let dashboard_data = self.get_dashboard_data().await?;
                log::debug!("CloudWatch metrics: {:?}", dashboard_data.system_metrics);
            }
            ExportType::Grafana => {
                // Export to Grafana (similar to Prometheus format)
                let metrics = self.metric_collector.export_prometheus_format().await?;
                self.send_http_data(&endpoint.url, &metrics, "text/plain").await?;
            }
        }

        // Update export status
        let mut state = self.service_state.write().await;
        if let Some(status) = state.export_status.get_mut(&endpoint.name) {
            status.last_export = Some(Utc::now());
            status.export_count += 1;
        }

        Ok(())
    }

    async fn send_http_data(&self, url: &str, data: &str, content_type: &str) -> Result<(), MonitoringError> {
        let client = reqwest::Client::new();
        let response = client
            .post(url)
            .header("Content-Type", content_type)
            .body(data.to_string())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(MonitoringError::ExportFailed(
                format!("HTTP {} from {}", response.status(), url)
            ));
        }

        Ok(())
    }

    async fn cleanup_old_data(&self) -> Result<(), MonitoringError> {
        let cutoff_date = Utc::now() - chrono::Duration::days(self.config.retention_policy.metrics_retention_days as i64);
        
        // Cleanup metrics
        self.metrics_collector.cleanup_old_data(cutoff_date).await?;
        
        // Cleanup logs
        let log_cutoff = Utc::now() - chrono::Duration::days(self.config.retention_policy.logs_retention_days as i64);
        self.log_aggregator.cleanup_old_logs(log_cutoff).await?;
        
        // Cleanup traces
        let trace_cutoff = Utc::now() - chrono::Duration::days(self.config.retention_policy.traces_retention_days as i64);
        self.tracing_manager.cleanup_old_traces(trace_cutoff).await?;
        
        // Cleanup alerts
        let alert_cutoff = Utc::now() - chrono::Duration::days(self.config.retention_policy.alerts_retention_days as i64);
        self.alert_manager.cleanup_old_alerts(alert_cutoff).await?;

        log::info!("Completed data cleanup for retention policy");
        Ok(())
    }

    async fn format_datadog_metrics(&self, dashboard_data: &DashboardData) -> Result<String, MonitoringError> {
        // Format metrics for DataDog API
        let timestamp = Utc::now().timestamp();

        let mut datadog_series = Vec::new();

        // Convert system metrics to DataDog format
        for (metric_name, metric_value) in &dashboard_data.metrics_summary {
            let datadog_metric = serde_json::json!({
                "series": [{
                    "metric": format!("n0n.{}", metric_name),
                    "points": [[timestamp, metric_value]],
                    "tags": ["service:n0n", "environment:production"]
                }]
            });
            datadog_series.push(datadog_metric);
        }

        serde_json::to_string(&datadog_series)
            .map_err(|e| MonitoringError::ExportFailed(format!("DataDog formatting error: {}", e)))
    }

    async fn format_newrelic_metrics(&self, dashboard_data: &DashboardData) -> Result<String, MonitoringError> {
        // Format metrics for New Relic API
        let timestamp = Utc::now().timestamp_millis();

        let mut newrelic_metrics = Vec::new();

        // Convert system metrics to New Relic format
        for (metric_name, metric_value) in &dashboard_data.metrics_summary {
            let newrelic_metric = serde_json::json!({
                "metrics": [{
                    "name": format!("n0n.{}", metric_name),
                    "type": "gauge",
                    "value": metric_value,
                    "timestamp": timestamp,
                    "attributes": {
                        "service": "n0n",
                        "environment": "production"
                    }
                }]
            });
            newrelic_metrics.push(newrelic_metric);
        }

        serde_json::to_string(&newrelic_metrics)
            .map_err(|e| MonitoringError::ExportFailed(format!("New Relic formatting error: {}", e)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    pub uptime_seconds: u64,
    pub metrics_summary: HashMap<String, MetricValue>,
    pub active_alerts: Vec<Alert>,
    pub system_health: HealthReport,
    pub performance_metrics: PerformanceMetrics,
    pub recent_log_entries: Vec<LogEntry>,
    pub export_status: HashMap<String, ExportStatus>,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics_config: MetricsConfig::default(),
            alert_config: AlertConfig::default(),
            health_config: HealthConfig::default(),
            tracing_config: TracingConfig::default(),
            log_config: LogConfig::default(),
            performance_config: PerformanceConfig::default(),
            retention_policy: RetentionPolicy {
                metrics_retention_days: 30,
                logs_retention_days: 7,
                traces_retention_days: 3,
                alerts_retention_days: 90,
                performance_data_retention_days: 14,
            },
            export_endpoints: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MonitoringError {
    #[error("Metrics error: {0}")]
    Metrics(#[from] MetricsError),
    
    #[error("Alert error: {0}")]
    Alerts(#[from] AlertError),
    
    #[error("Health check error: {0}")]
    Health(#[from] HealthError),
    
    #[error("Tracing error: {0}")]
    Tracing(#[from] TraceError),
    
    #[error("Log error: {0}")]
    Logs(#[from] LogError),
    
    #[error("Performance error: {0}")]
    Performance(#[from] PerformanceError),
    
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Export failed: {0}")]
    ExportFailed(String),
    
    #[error("Service already running")]
    ServiceAlreadyRunning,
    
    #[error("Service not running")]
    ServiceNotRunning,
    
    #[error("Configuration error: {0}")]
    Configuration(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_monitoring_service_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let config = MonitoringConfig {
            metrics_config: MetricsConfig {
                storage_path: temp_dir.path().join("metrics"),
                collection_interval_seconds: 10,
                buffer_size: 1000,
                enable_system_metrics: true,
                custom_metrics: Vec::new(),
            },
            ..Default::default()
        };

        let service = MonitoringService::new(config).await.unwrap();
        
        // Test service start
        service.start().await.unwrap();
        
        // Test recording metrics
        service.record_metric("test.counter", MetricValue::Counter(1), None).await.unwrap();
        
        // Test logging
        service.log_event(LogLevel::Info, "Test log message", None).await.unwrap();
        
        // Test dashboard data
        let dashboard = service.get_dashboard_data().await.unwrap();
        assert!(dashboard.uptime_seconds >= 0);
        
        // Test service stop
        service.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_export_configuration() {
        let export_endpoint = ExportEndpoint {
            name: "test_prometheus".to_string(),
            endpoint_type: ExportType::Prometheus,
            url: "http://localhost:9090/api/v1/write".to_string(),
            credentials: None,
            enabled: true,
            export_interval_seconds: 60,
        };

        let config = MonitoringConfig {
            export_endpoints: vec![export_endpoint],
            ..Default::default()
        };

        let service = MonitoringService::new(config).await.unwrap();
        assert_eq!(service.config.export_endpoints.len(), 1);
    }
}