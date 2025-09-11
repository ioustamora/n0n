use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;

/// Structured log entry for JSON output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredLogEntry {
    /// Timestamp in RFC3339 format
    pub timestamp: String,
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Logger name/module
    pub target: String,
    /// Log message
    pub message: String,
    /// Structured fields
    pub fields: HashMap<String, Value>,
    /// Span information
    pub span: Option<SpanInfo>,
    /// File location (if enabled)
    pub file: Option<String>,
    /// Line number (if enabled)
    pub line: Option<u32>,
    /// Thread information (if enabled)
    pub thread: Option<ThreadInfo>,
}

/// Span context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanInfo {
    /// Span name
    pub name: String,
    /// Span target/module
    pub target: String,
    /// Span fields
    pub fields: HashMap<String, Value>,
    /// Span ID
    pub id: String,
}

/// Thread information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    /// Thread name (if available)
    pub name: Option<String>,
    /// Thread ID
    pub id: String,
}

/// Custom layer for structured JSON logging
pub struct StructuredJsonLayer;

/// Structured logging utilities for different event types
pub struct StructuredLogger;

impl StructuredLogger {
    /// Log a user action with context
    pub fn log_user_action(
        action: &str,
        user_id: &str,
        resource: Option<&str>,
        metadata: HashMap<String, Value>,
    ) {
        let mut fields = HashMap::new();
        fields.insert("action".to_string(), Value::String(action.to_string()));
        fields.insert("user_id".to_string(), Value::String(user_id.to_string()));
        if let Some(res) = resource {
            fields.insert("resource".to_string(), Value::String(res.to_string()));
        }
        fields.extend(metadata);

        tracing::info!(
            category = "user_action",
            action = action,
            user_id = user_id,
            resource = resource,
            "User action performed"
        );
    }

    /// Log a system event with context
    pub fn log_system_event(
        event_type: &str,
        component: &str,
        status: &str,
        metadata: HashMap<String, Value>,
    ) {
        tracing::info!(
            category = "system",
            event_type = event_type,
            component = component,
            status = status,
            metadata = ?metadata,
            "System event occurred"
        );
    }

    /// Log an error with full context
    pub fn log_error_with_context(
        error: &dyn std::error::Error,
        operation: &str,
        context: HashMap<String, Value>,
    ) {
        let mut error_chain = Vec::new();
        let mut current_error: &dyn std::error::Error = error;
        
        loop {
            error_chain.push(current_error.to_string());
            match current_error.source() {
                Some(source) => current_error = source,
                None => break,
            }
        }

        tracing::error!(
            category = "error",
            operation = operation,
            error = %error,
            error_chain = ?error_chain,
            context = ?context,
            "Operation failed with error"
        );
    }

    /// Log a performance event
    pub fn log_performance(
        operation: &str,
        duration_ms: u64,
        throughput: Option<f64>,
        metadata: HashMap<String, Value>,
    ) {
        tracing::info!(
            category = "performance",
            operation = operation,
            duration_ms = duration_ms,
            throughput = throughput,
            metadata = ?metadata,
            "Performance measurement"
        );
    }

    /// Log a security event
    pub fn log_security_event(
        event_type: &str,
        severity: &str,
        source: Option<&str>,
        details: HashMap<String, Value>,
    ) {
        tracing::warn!(
            category = "security",
            event_type = event_type,
            severity = severity,
            source = source,
            details = ?details,
            "Security event detected"
        );
    }

    /// Log a business event
    pub fn log_business_event(
        event_name: &str,
        entity_type: &str,
        entity_id: &str,
        properties: HashMap<String, Value>,
    ) {
        tracing::info!(
            category = "business",
            event = event_name,
            entity_type = entity_type,
            entity_id = entity_id,
            properties = ?properties,
            "Business event occurred"
        );
    }

    /// Log a configuration change
    pub fn log_config_change(
        setting: &str,
        old_value: Option<&str>,
        new_value: &str,
        changed_by: &str,
    ) {
        tracing::info!(
            category = "configuration",
            setting = setting,
            old_value = old_value,
            new_value = new_value,
            changed_by = changed_by,
            "Configuration changed"
        );
    }

    /// Log an API request/response
    pub fn log_api_call(
        method: &str,
        endpoint: &str,
        status_code: u16,
        duration_ms: u64,
        user_id: Option<&str>,
        metadata: HashMap<String, Value>,
    ) {
        tracing::info!(
            category = "api",
            method = method,
            endpoint = endpoint,
            status_code = status_code,
            duration_ms = duration_ms,
            user_id = user_id,
            metadata = ?metadata,
            "API call completed"
        );
    }

    /// Log a data operation
    pub fn log_data_operation(
        operation: &str,
        table_or_collection: &str,
        record_count: Option<usize>,
        duration_ms: Option<u64>,
        metadata: HashMap<String, Value>,
    ) {
        tracing::info!(
            category = "data",
            operation = operation,
            table_or_collection = table_or_collection,
            record_count = record_count,
            duration_ms = duration_ms,
            metadata = ?metadata,
            "Data operation completed"
        );
    }
}

/// Convenience macros for structured logging
#[macro_export]
macro_rules! structured_info {
    ($category:expr, $($key:ident = $value:expr),*) => {
        tracing::info!(
            category = $category,
            $($key = $value,)*
        );
    };
}

#[macro_export]
macro_rules! structured_warn {
    ($category:expr, $($key:ident = $value:expr),*) => {
        tracing::warn!(
            category = $category,
            $($key = $value,)*
        );
    };
}

#[macro_export]
macro_rules! structured_error {
    ($category:expr, $($key:ident = $value:expr),*) => {
        tracing::error!(
            category = $category,
            $($key = $value,)*
        );
    };
}

#[macro_export]
macro_rules! structured_debug {
    ($category:expr, $($key:ident = $value:expr),*) => {
        tracing::debug!(
            category = $category,
            $($key = $value,)*
        );
    };
}

/// Log correlation utilities
pub struct LogCorrelation {
    correlation_id: String,
}

impl LogCorrelation {
    pub fn new() -> Self {
        Self {
            correlation_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub fn with_id(correlation_id: String) -> Self {
        Self { correlation_id }
    }

    pub fn id(&self) -> &str {
        &self.correlation_id
    }

    /// Create a span with correlation ID
    pub fn span(&self, name: &str) -> tracing::Span {
        tracing::info_span!(name, correlation_id = %self.correlation_id)
    }

    /// Log with correlation context
    pub fn log_info(&self, message: &str, fields: HashMap<String, Value>) {
        tracing::info!(
            correlation_id = %self.correlation_id,
            message = message,
            fields = ?fields,
            "Correlated log entry"
        );
    }

    /// Log error with correlation context
    pub fn log_error(&self, error: &dyn std::error::Error, operation: &str) {
        tracing::error!(
            correlation_id = %self.correlation_id,
            error = %error,
            operation = operation,
            "Correlated error occurred"
        );
    }
}

impl Default for LogCorrelation {
    fn default() -> Self {
        Self::new()
    }
}

/// Request context for HTTP-like operations
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub trace_id: String,
    pub start_time: std::time::Instant,
}

impl RequestContext {
    pub fn new() -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            user_id: None,
            session_id: None,
            trace_id: uuid::Uuid::new_v4().to_string(),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn duration(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Create a span with full request context
    pub fn span(&self, name: &str) -> tracing::Span {
        tracing::info_span!(
            name,
            request_id = %self.request_id,
            user_id = ?self.user_id,
            session_id = ?self.session_id,
            trace_id = %self.trace_id
        )
    }

    /// Log request completion
    pub fn log_completion(&self, operation: &str, status: &str) {
        tracing::info!(
            request_id = %self.request_id,
            user_id = ?self.user_id,
            session_id = ?self.session_id,
            trace_id = %self.trace_id,
            operation = operation,
            status = status,
            duration_ms = self.duration().as_millis(),
            "Request completed"
        );
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_structured_log_entry() {
        let entry = StructuredLogEntry {
            timestamp: "2023-01-01T00:00:00Z".to_string(),
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: "Test message".to_string(),
            fields: HashMap::from([
                ("key1".to_string(), json!("value1")),
                ("key2".to_string(), json!(42)),
            ]),
            span: None,
            file: Some("test.rs".to_string()),
            line: Some(123),
            thread: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("Test message"));
        assert!(json.contains("value1"));
        assert!(json.contains("42"));
    }

    #[test]
    fn test_log_correlation() {
        let correlation = LogCorrelation::new();
        assert!(!correlation.id().is_empty());

        let correlation_with_id = LogCorrelation::with_id("custom-id".to_string());
        assert_eq!(correlation_with_id.id(), "custom-id");
    }

    #[test]
    fn test_request_context() {
        let mut context = RequestContext::new()
            .with_user("user123".to_string())
            .with_session("session456".to_string());

        assert_eq!(context.user_id, Some("user123".to_string()));
        assert_eq!(context.session_id, Some("session456".to_string()));
        assert!(!context.request_id.is_empty());
        assert!(!context.trace_id.is_empty());
        assert!(context.duration().as_nanos() > 0);
    }

    #[test]
    fn test_span_info() {
        let span_info = SpanInfo {
            name: "test_span".to_string(),
            target: "test_target".to_string(),
            fields: HashMap::from([
                ("field1".to_string(), json!("value1")),
            ]),
            id: "span_123".to_string(),
        };

        assert_eq!(span_info.name, "test_span");
        assert_eq!(span_info.target, "test_target");
        assert_eq!(span_info.fields.get("field1").unwrap(), &json!("value1"));
    }

    #[test]
    fn test_thread_info() {
        let thread_info = ThreadInfo {
            name: Some("worker-1".to_string()),
            id: "thread_456".to_string(),
        };

        assert_eq!(thread_info.name, Some("worker-1".to_string()));
        assert_eq!(thread_info.id, "thread_456");
    }
}