use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Log aggregator for structured logging and analysis
#[derive(Clone)]
pub struct LogAggregator {
    config: LogConfig,
    log_buffer: Arc<RwLock<Vec<LogEntry>>>,
    structured_logs: Arc<RwLock<Vec<StructuredLog>>>,
    is_running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub buffer_size: usize,
    pub flush_interval_seconds: u64,
    pub log_level: LogLevel,
    pub structured_logging: bool,
    pub log_rotation: LogRotation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotation {
    pub enabled: bool,
    pub max_file_size_mb: u64,
    pub max_files: u32,
    pub rotation_pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub module: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub thread: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredLog {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub context: HashMap<String, serde_json::Value>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilter {
    pub level_min: Option<LogLevel>,
    pub level_max: Option<LogLevel>,
    pub modules: Vec<String>,
    pub contains_text: Option<String>,
    pub time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

impl LogAggregator {
    pub async fn new(config: LogConfig) -> Result<Self, LogError> {
        Ok(Self {
            config,
            log_buffer: Arc::new(RwLock::new(Vec::new())),
            structured_logs: Arc::new(RwLock::new(Vec::new())),
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start(&self) -> Result<(), LogError> {
        let mut running = self.is_running.write().await;
        if *running {
            return Err(LogError::AlreadyRunning);
        }
        *running = true;
        log::info!("Log aggregator started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), LogError> {
        let mut running = self.is_running.write().await;
        *running = false;
        log::info!("Log aggregator stopped");
        Ok(())
    }

    pub async fn log_structured(&self, log: StructuredLog) -> Result<(), LogError> {
        let mut logs = self.structured_logs.write().await;
        logs.push(log);
        
        if logs.len() > self.config.buffer_size {
            logs.remove(0);
        }
        
        Ok(())
    }

    pub async fn get_recent_logs(&self, count: usize) -> Result<Vec<LogEntry>, LogError> {
        let buffer = self.log_buffer.read().await;
        let start = if buffer.len() > count { buffer.len() - count } else { 0 };
        Ok(buffer[start..].to_vec())
    }

    pub async fn export_elasticsearch_format(&self) -> Result<String, LogError> {
        let logs = self.structured_logs.read().await;
        let json_logs: Vec<_> = logs.iter().map(|log| {
            serde_json::json!({
                "@timestamp": log.timestamp,
                "level": log.level,
                "message": log.message,
                "context": log.context,
                "trace_id": log.trace_id,
                "span_id": log.span_id
            })
        }).collect();
        
        serde_json::to_string(&json_logs)
            .map_err(|e| LogError::SerializationError(e.to_string()))
    }

    pub async fn cleanup_old_logs(&self, _cutoff_date: DateTime<Utc>) -> Result<(), LogError> {
        // Placeholder implementation
        log::info!("Cleaned up old logs (placeholder)");
        Ok(())
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            buffer_size: 10000,
            flush_interval_seconds: 60,
            log_level: LogLevel::Info,
            structured_logging: true,
            log_rotation: LogRotation {
                enabled: true,
                max_file_size_mb: 100,
                max_files: 10,
                rotation_pattern: "%Y-%m-%d".to_string(),
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("Log aggregator already running")]
    AlreadyRunning,
    
    #[error("Log aggregator not running")]
    NotRunning,
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}