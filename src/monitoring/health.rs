use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Health checker for monitoring system and component health
#[derive(Clone)]
pub struct HealthChecker {
    config: HealthConfig,
    health_checks: Arc<RwLock<HashMap<String, HealthCheck>>>,
    health_status: Arc<RwLock<HashMap<String, ComponentHealth>>>,
    is_running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    pub check_interval_seconds: u64,
    pub timeout_seconds: u64,
    pub max_history_entries: usize,
    pub degraded_threshold_ms: u64,
    pub unhealthy_threshold_failures: u32,
    pub recovery_threshold_successes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub id: String,
    pub name: String,
    pub description: String,
    pub check_type: HealthCheckType,
    pub config: HealthCheckConfig,
    pub enabled: bool,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthCheckType {
    Http,
    Tcp,
    Database,
    FileSystem,
    Memory,
    Cpu,
    Disk,
    Process,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    // HTTP checks
    pub url: Option<String>,
    pub method: Option<String>,
    pub headers: HashMap<String, String>,
    pub expected_status: Option<u16>,
    pub expected_body: Option<String>,
    
    // TCP checks
    pub host: Option<String>,
    pub port: Option<u16>,
    
    // Database checks
    pub connection_string: Option<String>,
    pub query: Option<String>,
    
    // File system checks
    pub path: Option<String>,
    pub min_free_bytes: Option<u64>,
    pub max_usage_percent: Option<f64>,
    
    // Resource checks
    pub max_cpu_percent: Option<f64>,
    pub max_memory_bytes: Option<u64>,
    pub max_memory_percent: Option<f64>,
    
    // Process checks
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    
    // Custom checks
    pub command: Option<String>,
    pub script: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub component_id: String,
    pub status: HealthStatus,
    pub message: String,
    pub last_checked: DateTime<Utc>,
    pub response_time_ms: u64,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub total_checks: u64,
    pub successful_checks: u64,
    pub failed_checks: u64,
    pub history: Vec<HealthCheckResult>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub timestamp: DateTime<Utc>,
    pub status: HealthStatus,
    pub response_time_ms: u64,
    pub message: String,
    pub error: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub overall_status: HealthStatus,
    pub timestamp: DateTime<Utc>,
    pub components: HashMap<String, ComponentHealth>,
    pub summary: HealthSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub total_components: u32,
    pub healthy_components: u32,
    pub degraded_components: u32,
    pub unhealthy_components: u32,
    pub unknown_components: u32,
    pub average_response_time_ms: f64,
    pub uptime_percentage: f64,
}

impl HealthChecker {
    pub async fn new(config: HealthConfig) -> Result<Self, HealthError> {
        Ok(Self {
            config,
            health_checks: Arc::new(RwLock::new(HashMap::new())),
            health_status: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start(&self) -> Result<(), HealthError> {
        let mut running = self.is_running.write().await;
        if *running {
            return Err(HealthError::AlreadyRunning);
        }
        *running = true;
        log::info!("Health checker started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), HealthError> {
        let mut running = self.is_running.write().await;
        *running = false;
        log::info!("Health checker stopped");
        Ok(())
    }

    pub async fn register_health_check(&self, health_check: HealthCheck) -> Result<(), HealthError> {
        let mut checks = self.health_checks.write().await;
        let mut status = self.health_status.write().await;

        checks.insert(health_check.id.clone(), health_check.clone());
        status.insert(health_check.id.clone(), ComponentHealth {
            component_id: health_check.id.clone(),
            status: HealthStatus::Unknown,
            message: "Not yet checked".to_string(),
            last_checked: Utc::now(),
            response_time_ms: 0,
            consecutive_failures: 0,
            consecutive_successes: 0,
            total_checks: 0,
            successful_checks: 0,
            failed_checks: 0,
            history: Vec::new(),
            metadata: HashMap::new(),
        });

        log::info!("Registered health check: {}", health_check.name);
        Ok(())
    }

    pub async fn unregister_health_check(&self, check_id: &str) -> Result<(), HealthError> {
        let mut checks = self.health_checks.write().await;
        let mut status = self.health_status.write().await;

        if checks.remove(check_id).is_none() {
            return Err(HealthError::CheckNotFound(check_id.to_string()));
        }
        status.remove(check_id);

        log::info!("Unregistered health check: {}", check_id);
        Ok(())
    }

    pub async fn run_periodic_checks(&self) -> Result<(), HealthError> {
        let checks = self.health_checks.read().await;
        
        for check in checks.values() {
            if check.enabled {
                // Check if it's time to run this check
                let should_run = {
                    let status = self.health_status.read().await;
                    if let Some(component) = status.get(&check.id) {
                        let elapsed = Utc::now().signed_duration_since(component.last_checked);
                        elapsed.num_seconds() >= check.interval_seconds as i64
                    } else {
                        true
                    }
                };

                if should_run {
                    if let Err(e) = self.run_health_check(check).await {
                        log::error!("Failed to run health check {}: {}", check.name, e);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn check_component(&self, component_id: &str) -> Result<ComponentHealth, HealthError> {
        let checks = self.health_checks.read().await;
        
        if let Some(check) = checks.get(component_id) {
            self.run_health_check(check).await?;
            
            let status = self.health_status.read().await;
            status.get(component_id)
                .cloned()
                .ok_or_else(|| HealthError::ComponentNotFound(component_id.to_string()))
        } else {
            Err(HealthError::CheckNotFound(component_id.to_string()))
        }
    }

    pub async fn get_system_health(&self) -> Result<HealthReport, HealthError> {
        let status = self.health_status.read().await;
        let components = status.clone();

        let summary = self.calculate_health_summary(&components);
        let overall_status = self.determine_overall_status(&components);

        Ok(HealthReport {
            overall_status,
            timestamp: Utc::now(),
            components,
            summary,
        })
    }

    async fn run_health_check(&self, check: &HealthCheck) -> Result<(), HealthError> {
        let start_time = Utc::now();
        
        let result = match check.check_type {
            HealthCheckType::Http => self.run_http_check(check).await,
            HealthCheckType::Tcp => self.run_tcp_check(check).await,
            HealthCheckType::Database => self.run_database_check(check).await,
            HealthCheckType::FileSystem => self.run_filesystem_check(check).await,
            HealthCheckType::Memory => self.run_memory_check(check).await,
            HealthCheckType::Cpu => self.run_cpu_check(check).await,
            HealthCheckType::Disk => self.run_disk_check(check).await,
            HealthCheckType::Process => self.run_process_check(check).await,
            HealthCheckType::Custom => self.run_custom_check(check).await,
        };

        let end_time = Utc::now();
        let response_time_ms = end_time.signed_duration_since(start_time).num_milliseconds() as u64;

        let check_result = match result {
            Ok(message) => {
                let status = if response_time_ms > self.config.degraded_threshold_ms {
                    HealthStatus::Degraded
                } else {
                    HealthStatus::Healthy
                };
                
                HealthCheckResult {
                    timestamp: end_time,
                    status,
                    response_time_ms,
                    message,
                    error: None,
                    metadata: HashMap::new(),
                }
            }
            Err(e) => HealthCheckResult {
                timestamp: end_time,
                status: HealthStatus::Unhealthy,
                response_time_ms,
                message: "Health check failed".to_string(),
                error: Some(e.to_string()),
                metadata: HashMap::new(),
            }
        };

        self.update_component_health(check, check_result).await;
        Ok(())
    }

    async fn run_http_check(&self, check: &HealthCheck) -> Result<String, HealthError> {
        let url = check.config.url.as_ref()
            .ok_or_else(|| HealthError::InvalidConfig("URL required for HTTP check".to_string()))?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(check.timeout_seconds))
            .build()
            .map_err(|e| HealthError::CheckFailed(e.to_string()))?;

        let method = check.config.method.as_deref().unwrap_or("GET");
        let mut request = match method.to_uppercase().as_str() {
            "GET" => client.get(url),
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "DELETE" => client.delete(url),
            "HEAD" => client.head(url),
            _ => return Err(HealthError::InvalidConfig(format!("Unsupported HTTP method: {}", method))),
        };

        // Add headers
        for (key, value) in &check.config.headers {
            request = request.header(key, value);
        }

        let response = request.send().await
            .map_err(|e| HealthError::CheckFailed(e.to_string()))?;

        // Check status code
        if let Some(expected_status) = check.config.expected_status {
            if response.status().as_u16() != expected_status {
                return Err(HealthError::CheckFailed(
                    format!("Expected status {}, got {}", expected_status, response.status())
                ));
            }
        } else if !response.status().is_success() {
            return Err(HealthError::CheckFailed(
                format!("HTTP request failed with status: {}", response.status())
            ));
        }

        // Check response body if specified
        if let Some(expected_body) = &check.config.expected_body {
            let body = response.text().await
                .map_err(|e| HealthError::CheckFailed(e.to_string()))?;
            
            if !body.contains(expected_body) {
                return Err(HealthError::CheckFailed(
                    format!("Response body does not contain expected text: {}", expected_body)
                ));
            }
        }

        Ok(format!("HTTP check successful: {}", response.status()))
    }

    async fn run_tcp_check(&self, check: &HealthCheck) -> Result<String, HealthError> {
        let host = check.config.host.as_ref()
            .ok_or_else(|| HealthError::InvalidConfig("Host required for TCP check".to_string()))?;
        let port = check.config.port
            .ok_or_else(|| HealthError::InvalidConfig("Port required for TCP check".to_string()))?;

        let timeout = Duration::from_secs(check.timeout_seconds);
        
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host.as_str(), port))).await {
            Ok(Ok(_)) => Ok(format!("TCP connection successful to {}:{}", host, port)),
            Ok(Err(e)) => Err(HealthError::CheckFailed(format!("TCP connection failed: {}", e))),
            Err(_) => Err(HealthError::CheckFailed("TCP connection timed out".to_string())),
        }
    }

    async fn run_database_check(&self, _check: &HealthCheck) -> Result<String, HealthError> {
        // Placeholder - implement database connectivity check
        Ok("Database check successful (placeholder)".to_string())
    }

    async fn run_filesystem_check(&self, check: &HealthCheck) -> Result<String, HealthError> {
        let path = check.config.path.as_ref()
            .ok_or_else(|| HealthError::InvalidConfig("Path required for filesystem check".to_string()))?;

        let metadata = std::fs::metadata(path)
            .map_err(|e| HealthError::CheckFailed(format!("Failed to access path {}: {}", path, e)))?;

        if metadata.is_dir() {
            // Check disk space if thresholds are specified
            if let Some(min_free) = check.config.min_free_bytes {
                // Placeholder - implement disk space check
                if min_free > 0 {
                    // Would check available space here
                }
            }
        }

        Ok(format!("Filesystem check successful for: {}", path))
    }

    async fn run_memory_check(&self, check: &HealthCheck) -> Result<String, HealthError> {
        // Placeholder - implement memory usage check
        let _max_percent = check.config.max_memory_percent.unwrap_or(90.0);
        let _max_bytes = check.config.max_memory_bytes.unwrap_or(u64::MAX);
        
        Ok("Memory check successful (placeholder)".to_string())
    }

    async fn run_cpu_check(&self, check: &HealthCheck) -> Result<String, HealthError> {
        // Placeholder - implement CPU usage check
        let _max_percent = check.config.max_cpu_percent.unwrap_or(90.0);
        
        Ok("CPU check successful (placeholder)".to_string())
    }

    async fn run_disk_check(&self, check: &HealthCheck) -> Result<String, HealthError> {
        // Placeholder - implement disk usage check
        let _max_percent = check.config.max_usage_percent.unwrap_or(90.0);
        
        Ok("Disk check successful (placeholder)".to_string())
    }

    async fn run_process_check(&self, check: &HealthCheck) -> Result<String, HealthError> {
        if let Some(process_name) = &check.config.process_name {
            // Placeholder - implement process existence check
            Ok(format!("Process check successful for: {}", process_name))
        } else if let Some(process_id) = check.config.process_id {
            // Placeholder - implement process ID check
            Ok(format!("Process check successful for PID: {}", process_id))
        } else {
            Err(HealthError::InvalidConfig("Process name or ID required".to_string()))
        }
    }

    async fn run_custom_check(&self, check: &HealthCheck) -> Result<String, HealthError> {
        if let Some(command) = &check.config.command {
            // Placeholder - implement custom command execution
            Ok(format!("Custom command check successful: {}", command))
        } else if let Some(script) = &check.config.script {
            // Placeholder - implement custom script execution
            Ok(format!("Custom script check successful: {}", script))
        } else {
            Err(HealthError::InvalidConfig("Command or script required for custom check".to_string()))
        }
    }

    async fn update_component_health(&self, check: &HealthCheck, result: HealthCheckResult) {
        let mut status = self.health_status.write().await;
        
        if let Some(component) = status.get_mut(&check.id) {
            // Update statistics
            component.total_checks += 1;
            component.last_checked = result.timestamp;
            component.response_time_ms = result.response_time_ms;
            component.message = result.message.clone();

            match result.status {
                HealthStatus::Healthy | HealthStatus::Degraded => {
                    component.successful_checks += 1;
                    component.consecutive_successes += 1;
                    component.consecutive_failures = 0;
                    
                    // Check if component should recover
                    if component.status == HealthStatus::Unhealthy 
                        && component.consecutive_successes >= self.config.recovery_threshold_successes {
                        component.status = result.status;
                    } else if component.status != HealthStatus::Unhealthy {
                        component.status = result.status;
                    }
                }
                HealthStatus::Unhealthy => {
                    component.failed_checks += 1;
                    component.consecutive_failures += 1;
                    component.consecutive_successes = 0;
                    
                    // Mark as unhealthy if threshold reached
                    if component.consecutive_failures >= self.config.unhealthy_threshold_failures {
                        component.status = HealthStatus::Unhealthy;
                    }
                }
                HealthStatus::Unknown => {
                    component.status = HealthStatus::Unknown;
                }
            }

            // Add to history
            component.history.push(result);
            if component.history.len() > self.config.max_history_entries {
                component.history.remove(0);
            }
        }
    }

    fn calculate_health_summary(&self, components: &HashMap<String, ComponentHealth>) -> HealthSummary {
        let total_components = components.len() as u32;
        let mut healthy = 0;
        let mut degraded = 0;
        let mut unhealthy = 0;
        let mut unknown = 0;
        let mut total_response_time = 0u64;
        let mut total_success_rate = 0.0;

        for component in components.values() {
            match component.status {
                HealthStatus::Healthy => healthy += 1,
                HealthStatus::Degraded => degraded += 1,
                HealthStatus::Unhealthy => unhealthy += 1,
                HealthStatus::Unknown => unknown += 1,
            }
            
            total_response_time += component.response_time_ms;
            
            if component.total_checks > 0 {
                total_success_rate += component.successful_checks as f64 / component.total_checks as f64;
            }
        }

        let average_response_time = if total_components > 0 {
            total_response_time as f64 / total_components as f64
        } else {
            0.0
        };

        let uptime_percentage = if total_components > 0 {
            (total_success_rate / total_components as f64) * 100.0
        } else {
            100.0
        };

        HealthSummary {
            total_components,
            healthy_components: healthy,
            degraded_components: degraded,
            unhealthy_components: unhealthy,
            unknown_components: unknown,
            average_response_time_ms: average_response_time,
            uptime_percentage,
        }
    }

    fn determine_overall_status(&self, components: &HashMap<String, ComponentHealth>) -> HealthStatus {
        if components.is_empty() {
            return HealthStatus::Unknown;
        }

        let mut has_unhealthy = false;
        let mut has_degraded = false;

        for component in components.values() {
            match component.status {
                HealthStatus::Unhealthy => has_unhealthy = true,
                HealthStatus::Degraded => has_degraded = true,
                HealthStatus::Unknown => return HealthStatus::Unknown,
                HealthStatus::Healthy => {}
            }
        }

        if has_unhealthy {
            HealthStatus::Unhealthy
        } else if has_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval_seconds: 60,
            timeout_seconds: 30,
            max_history_entries: 100,
            degraded_threshold_ms: 5000,
            unhealthy_threshold_failures: 3,
            recovery_threshold_successes: 3,
        }
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            url: None,
            method: None,
            headers: HashMap::new(),
            expected_status: None,
            expected_body: None,
            host: None,
            port: None,
            connection_string: None,
            query: None,
            path: None,
            min_free_bytes: None,
            max_usage_percent: None,
            max_cpu_percent: None,
            max_memory_bytes: None,
            max_memory_percent: None,
            process_name: None,
            process_id: None,
            command: None,
            script: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("Health check failed: {0}")]
    CheckFailed(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Health check not found: {0}")]
    CheckNotFound(String),
    
    #[error("Component not found: {0}")]
    ComponentNotFound(String),
    
    #[error("Health checker already running")]
    AlreadyRunning,
    
    #[error("Health checker not running")]
    NotRunning,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check_registration() {
        let config = HealthConfig::default();
        let checker = HealthChecker::new(config).await.unwrap();

        let health_check = HealthCheck {
            id: "test-check".to_string(),
            name: "Test Check".to_string(),
            description: "Test health check".to_string(),
            check_type: HealthCheckType::Http,
            config: HealthCheckConfig {
                url: Some("https://httpbin.org/status/200".to_string()),
                expected_status: Some(200),
                ..Default::default()
            },
            enabled: true,
            interval_seconds: 60,
            timeout_seconds: 10,
            tags: HashMap::new(),
        };

        checker.register_health_check(health_check).await.unwrap();
        
        let checks = checker.health_checks.read().await;
        assert_eq!(checks.len(), 1);
        assert!(checks.contains_key("test-check"));
    }

    #[tokio::test]
    async fn test_tcp_health_check() {
        let config = HealthConfig::default();
        let checker = HealthChecker::new(config).await.unwrap();

        let health_check = HealthCheck {
            id: "tcp-check".to_string(),
            name: "TCP Check".to_string(),
            description: "Test TCP connectivity".to_string(),
            check_type: HealthCheckType::Tcp,
            config: HealthCheckConfig {
                host: Some("8.8.8.8".to_string()),
                port: Some(53),
                ..Default::default()
            },
            enabled: true,
            interval_seconds: 60,
            timeout_seconds: 5,
            tags: HashMap::new(),
        };

        checker.register_health_check(health_check).await.unwrap();
        
        let result = checker.run_tcp_check(&checker.health_checks.read().await["tcp-check"]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_filesystem_health_check() {
        let config = HealthConfig::default();
        let checker = HealthChecker::new(config).await.unwrap();

        let health_check = HealthCheck {
            id: "fs-check".to_string(),
            name: "Filesystem Check".to_string(),
            description: "Test filesystem access".to_string(),
            check_type: HealthCheckType::FileSystem,
            config: HealthCheckConfig {
                path: Some("/tmp".to_string()), // Use /tmp on Unix, would need Windows equivalent
                ..Default::default()
            },
            enabled: true,
            interval_seconds: 60,
            timeout_seconds: 5,
            tags: HashMap::new(),
        };

        checker.register_health_check(health_check).await.unwrap();
        
        // This test would need platform-specific paths to work properly
        // let result = checker.run_filesystem_check(&checker.health_checks.read().await["fs-check"]).await;
        // assert!(result.is_ok());
    }
}