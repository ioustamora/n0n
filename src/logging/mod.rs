use tracing::{Level, Subscriber};
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::UtcTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Registry,
};
use std::path::PathBuf;
use std::sync::Once;
use anyhow::Result;

pub mod audit;
pub mod performance;
pub mod structured;

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: Level,
    /// Whether to enable structured logging (JSON format)
    pub structured: bool,
    /// Log file path (if None, logs only to stdout)
    pub file_path: Option<PathBuf>,
    /// Whether to enable audit logging
    pub audit_enabled: bool,
    /// Audit log file path
    pub audit_file_path: Option<PathBuf>,
    /// Whether to enable performance tracing
    pub performance_tracing: bool,
    /// Whether to include file/line info in logs
    pub include_location: bool,
    /// Whether to include thread info in logs
    pub include_thread: bool,
    /// Maximum log file size in MB before rotation
    pub max_file_size_mb: u64,
    /// Number of rotated log files to keep
    pub max_backup_files: u32,
    /// Environment filter override (e.g., "n0n=debug,tower=warn")
    pub env_filter: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            structured: false,
            file_path: None,
            audit_enabled: true,
            audit_file_path: None,
            performance_tracing: false,
            include_location: true,
            include_thread: false,
            max_file_size_mb: 100,
            max_backup_files: 5,
            env_filter: None,
        }
    }
}

/// Initialize the global tracing subscriber
static INIT: Once = Once::new();

pub fn init_logging(config: LoggingConfig) -> Result<()> {
    INIT.call_once(|| {
        if let Err(e) = setup_tracing(config) {
            eprintln!("Failed to initialize logging: {}", e);
        }
    });
    Ok(())
}

fn setup_tracing(config: LoggingConfig) -> Result<()> {
    let mut _layers: Vec<Box<dyn std::any::Any>> = Vec::new();
    
    // Console layer
    let console_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::CLOSE)
        .with_timer(UtcTime::rfc_3339())
        .with_target(true)
        .with_file(config.include_location)
        .with_line_number(config.include_location)
        .with_thread_ids(config.include_thread)
        .with_thread_names(config.include_thread);

    // File layer if configured
    if let Some(file_path) = &config.file_path {
        let file_appender = tracing_appender::rolling::daily(
            file_path.parent().unwrap_or_else(|| std::path::Path::new(".")),
            file_path.file_name().and_then(|n| n.to_str()).unwrap_or("n0n.log")
        );
        
        let file_layer = tracing_subscriber::fmt::layer::<Registry>()
            .with_writer(file_appender)
            .with_span_events(FmtSpan::CLOSE)
            .with_timer(UtcTime::rfc_3339())
            .with_target(true)
            .with_file(config.include_location)
            .with_line_number(config.include_location)
            .with_thread_ids(config.include_thread)
            .with_thread_names(config.include_thread);
        
        if config.structured {
            let file_layer = file_layer.json();
        }
    }
    
    // Environment filter
    let env_filter = if let Some(filter_str) = config.env_filter {
        EnvFilter::try_new(filter_str)?
    } else {
        EnvFilter::from_default_env()
            .add_directive(format!("n0n={}", config.level).parse()?)
    };

    // Build the registry
    let registry = Registry::default()
        .with(env_filter);
    
    // Add console layer based on configuration
    if config.structured {
        let console_layer = console_layer.json().with_ansi(false);
        registry.with(console_layer).init();
    } else {
        let console_layer = console_layer.with_ansi(true);
        registry.with(console_layer).init();
    }
    
    // Return early since init() is called above
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        level = ?config.level,
        structured = config.structured,
        audit = config.audit_enabled,
        performance = config.performance_tracing,
        "Logging initialized"
    );

    Ok(())
}

/// Structured logging macros with additional context
#[macro_export]
macro_rules! log_operation {
    ($level:ident, $operation:expr, $($key:ident = $value:expr),*) => {
        tracing::$level!(
            operation = $operation,
            $($key = $value,)*
        );
    };
}

#[macro_export]
macro_rules! log_crypto_operation {
    ($level:ident, $operation:expr, $key_id:expr, $($key:ident = $value:expr),*) => {
        tracing::$level!(
            operation = $operation,
            category = "crypto",
            key_id = $key_id,
            $($key = $value,)*
        );
    };
}

#[macro_export]
macro_rules! log_storage_operation {
    ($level:ident, $operation:expr, $backend:expr, $($key:ident = $value:expr),*) => {
        tracing::$level!(
            operation = $operation,
            category = "storage", 
            backend = $backend,
            $($key = $value,)*
        );
    };
}

#[macro_export]
macro_rules! log_user_action {
    ($level:ident, $action:expr, $user:expr, $($key:ident = $value:expr),*) => {
        tracing::$level!(
            action = $action,
            category = "user",
            user_id = $user,
            $($key = $value,)*
        );
    };
}

/// Performance measurement utilities
pub struct PerfTimer {
    name: String,
    start: std::time::Instant,
}

impl PerfTimer {
    pub fn new(name: &str) -> Self {
        tracing::debug!(timer = name, "Starting performance timer");
        Self {
            name: name.to_string(),
            start: std::time::Instant::now(),
        }
    }
}

impl Drop for PerfTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        tracing::info!(
            timer = %self.name,
            duration_ms = duration.as_millis(),
            category = "performance",
            "Performance timer completed"
        );
    }
}


/// Async span helper for tracing function calls
#[macro_export]
macro_rules! traced_function {
    ($name:expr) => {
        let span = tracing::info_span!("function", name = $name);
        let _enter = span.enter();
    };
}

/// Helper for logging errors with context
pub fn log_error_with_context<E: std::fmt::Display>(
    error: &E,
    operation: &str,
    context: &[(&str, &dyn std::fmt::Debug)],
) {
    let mut fields = vec![
        ("error", format!("{}", error)),
        ("operation", operation.to_string()),
        ("category", "error".to_string()),
    ];
    
    for (key, value) in context {
        fields.push((key, format!("{:?}", value)));
    }
    
    // Log with all collected fields
    tracing::error!(
        error = %error,
        operation = operation,
        category = "error",
        context = ?fields
    );
}

/// Security event logging
pub fn log_security_event(event_type: &str, details: &[(&str, &dyn std::fmt::Debug)]) {
    let mut fields = vec![
        ("event_type", event_type.to_string()),
        ("category", "security".to_string()),
    ];
    
    for (key, value) in details {
        fields.push((key, format!("{:?}", value)));
    }
    
    // Log with all collected fields
    tracing::warn!(
        event_type = event_type,
        category = "security",
        details = ?fields
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::path::PathBuf;

    #[test]
    fn test_logging_config_default() {
        let config = LoggingConfig::default();
        
        assert_eq!(config.level, Level::INFO);
        assert!(!config.structured);
        assert!(config.audit_enabled);
        assert!(!config.performance_tracing);
        assert!(config.include_location);
        assert!(!config.include_thread);
    }

    #[test]
    fn test_logging_config_custom() {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("test.log");
        
        let config = LoggingConfig {
            level: Level::DEBUG,
            structured: true,
            file_path: Some(log_path.clone()),
            audit_enabled: false,
            performance_tracing: true,
            include_location: false,
            include_thread: true,
            max_file_size_mb: 50,
            max_backup_files: 3,
            env_filter: Some("n0n=trace".to_string()),
            ..Default::default()
        };
        
        assert_eq!(config.level, Level::DEBUG);
        assert!(config.structured);
        assert_eq!(config.file_path, Some(log_path));
        assert!(!config.audit_enabled);
        assert!(config.performance_tracing);
        assert!(!config.include_location);
        assert!(config.include_thread);
        assert_eq!(config.max_file_size_mb, 50);
        assert_eq!(config.max_backup_files, 3);
        assert_eq!(config.env_filter, Some("n0n=trace".to_string()));
    }

    #[tokio::test]
    async fn test_perf_timer() {
        // Initialize logging for test
        let config = LoggingConfig {
            level: Level::DEBUG,
            ..Default::default()
        };
        let _ = init_logging(config);
        
        {
            let _timer = PerfTimer::new("test_operation");
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        } // Timer should log when dropped
    }
}