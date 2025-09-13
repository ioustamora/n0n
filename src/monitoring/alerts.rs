use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Alert manager for monitoring conditions and triggering notifications
#[derive(Clone)]
pub struct AlertManager {
    config: AlertConfig,
    alert_rules: Arc<RwLock<HashMap<String, AlertRule>>>,
    active_alerts: Arc<RwLock<HashMap<String, Alert>>>,
    alert_history: Arc<RwLock<Vec<AlertHistory>>>,
    notification_channels: Arc<RwLock<HashMap<String, NotificationChannel>>>,
    is_running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub evaluation_interval_seconds: u64,
    pub max_alerts_history: usize,
    pub default_notification_channels: Vec<String>,
    pub alert_grouping_enabled: bool,
    pub alert_grouping_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub metric_query: String,
    pub condition: AlertCondition,
    pub threshold: f64,
    pub severity: AlertSeverity,
    pub evaluation_window_seconds: u64,
    pub notification_channels: Vec<String>,
    pub enabled: bool,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub repeat_interval_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    GreaterThan,
    LessThan,
    Equal,
    NotEqual,
    GreaterThanOrEqual,
    LessThanOrEqual,
    Change,
    NoData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub triggered_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub last_notification: Option<DateTime<Utc>>,
    pub current_value: Option<f64>,
    pub threshold: f64,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub notification_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertStatus {
    Firing,
    Resolved,
    Suppressed,
    Acknowledged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertHistory {
    pub alert_id: String,
    pub event_type: AlertEventType,
    pub timestamp: DateTime<Utc>,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertEventType {
    Triggered,
    Resolved,
    Acknowledged,
    Suppressed,
    Notification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    pub id: String,
    pub name: String,
    pub channel_type: NotificationChannelType,
    pub config: NotificationChannelConfig,
    pub enabled: bool,
    pub filters: Vec<NotificationFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannelType {
    Email,
    Slack,
    Webhook,
    SMS,
    PagerDuty,
    Teams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannelConfig {
    // Email
    pub smtp_server: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub email_recipients: Vec<String>,
    
    // Slack
    pub slack_webhook_url: Option<String>,
    pub slack_channel: Option<String>,
    pub slack_username: Option<String>,
    
    // Webhook
    pub webhook_url: Option<String>,
    pub webhook_method: Option<String>,
    pub webhook_headers: HashMap<String, String>,
    
    // SMS
    pub sms_service_url: Option<String>,
    pub sms_api_key: Option<String>,
    pub sms_phone_numbers: Vec<String>,
    
    // PagerDuty
    pub pagerduty_integration_key: Option<String>,
    
    // Teams
    pub teams_webhook_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationFilter {
    pub severity_min: AlertSeverity,
    pub severity_max: AlertSeverity,
    pub labels: HashMap<String, String>,
    pub time_ranges: Vec<TimeRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start_time: String, // HH:MM format
    pub end_time: String,   // HH:MM format
    pub days_of_week: Vec<u8>, // 0-6, Sunday = 0
}

impl AlertManager {
    pub async fn new(config: AlertConfig) -> Result<Self, AlertError> {
        Ok(Self {
            config,
            alert_rules: Arc::new(RwLock::new(HashMap::new())),
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
            alert_history: Arc::new(RwLock::new(Vec::new())),
            notification_channels: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start(&self) -> Result<(), AlertError> {
        let mut running = self.is_running.write().await;
        if *running {
            return Err(AlertError::AlreadyRunning);
        }
        *running = true;
        log::info!("Alert manager started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), AlertError> {
        let mut running = self.is_running.write().await;
        *running = false;
        log::info!("Alert manager stopped");
        Ok(())
    }

    pub async fn add_alert_rule(&self, rule: AlertRule) -> Result<(), AlertError> {
        if rule.name.is_empty() {
            return Err(AlertError::InvalidRule("Rule name cannot be empty".to_string()));
        }

        let mut rules = self.alert_rules.write().await;
        rules.insert(rule.id.clone(), rule);
        
        log::info!("Added alert rule: {}", rules.len());
        Ok(())
    }

    pub async fn remove_alert_rule(&self, rule_id: &str) -> Result<(), AlertError> {
        let mut rules = self.alert_rules.write().await;
        if rules.remove(rule_id).is_none() {
            return Err(AlertError::RuleNotFound(rule_id.to_string()));
        }
        
        // Also remove any active alerts for this rule
        let mut active_alerts = self.active_alerts.write().await;
        active_alerts.retain(|_, alert| alert.rule_id != rule_id);
        
        log::info!("Removed alert rule: {}", rule_id);
        Ok(())
    }

    pub async fn add_notification_channel(&self, channel: NotificationChannel) -> Result<(), AlertError> {
        let mut channels = self.notification_channels.write().await;
        channels.insert(channel.id.clone(), channel);
        log::info!("Added notification channel");
        Ok(())
    }

    pub async fn evaluate_rules(&self) -> Result<(), AlertError> {
        let rules = self.alert_rules.read().await;
        let mut newly_triggered = Vec::new();
        let mut resolved_alerts = Vec::new();

        for rule in rules.values() {
            if !rule.enabled {
                continue;
            }

            // In a real implementation, this would query the metrics system
            let current_value = self.evaluate_metric_query(&rule.metric_query).await?;
            
            let should_fire = self.evaluate_condition(&rule.condition, current_value, rule.threshold);
            let alert_id = format!("{}:{}", rule.id, self.generate_alert_fingerprint(rule, current_value));

            let mut active_alerts = self.active_alerts.write().await;
            
            if let Some(existing_alert) = active_alerts.get_mut(&alert_id) {
                if should_fire && existing_alert.status == AlertStatus::Resolved {
                    // Re-trigger resolved alert
                    existing_alert.status = AlertStatus::Firing;
                    existing_alert.triggered_at = Utc::now();
                    existing_alert.resolved_at = None;
                    existing_alert.current_value = Some(current_value);
                    newly_triggered.push(existing_alert.clone());
                } else if !should_fire && existing_alert.status == AlertStatus::Firing {
                    // Resolve firing alert
                    existing_alert.status = AlertStatus::Resolved;
                    existing_alert.resolved_at = Some(Utc::now());
                    resolved_alerts.push(existing_alert.clone());
                }
            } else if should_fire {
                // Create new alert
                let alert = Alert {
                    id: alert_id.clone(),
                    rule_id: rule.id.clone(),
                    name: rule.name.clone(),
                    description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    status: AlertStatus::Firing,
                    triggered_at: Utc::now(),
                    resolved_at: None,
                    last_notification: None,
                    current_value: Some(current_value),
                    threshold: rule.threshold,
                    labels: rule.labels.clone(),
                    annotations: rule.annotations.clone(),
                    notification_count: 0,
                };
                
                active_alerts.insert(alert_id, alert.clone());
                newly_triggered.push(alert);
            }
        }

        drop(rules);

        // Send notifications for newly triggered alerts
        for alert in newly_triggered {
            self.send_alert_notifications(&alert).await?;
            self.record_alert_history(&alert, AlertEventType::Triggered).await?;
        }

        // Record resolved alerts
        for alert in resolved_alerts {
            self.record_alert_history(&alert, AlertEventType::Resolved).await?;
        }

        Ok(())
    }

    pub async fn acknowledge_alert(&self, alert_id: &str, user: &str) -> Result<(), AlertError> {
        let mut active_alerts = self.active_alerts.write().await;
        
        if let Some(alert) = active_alerts.get_mut(alert_id) {
            alert.status = AlertStatus::Acknowledged;
            
            let mut details = HashMap::new();
            details.insert("acknowledged_by".to_string(), user.to_string());
            
            self.record_alert_history_with_details(alert, AlertEventType::Acknowledged, details).await?;
            
            log::info!("Alert {} acknowledged by {}", alert_id, user);
            Ok(())
        } else {
            Err(AlertError::AlertNotFound(alert_id.to_string()))
        }
    }

    pub async fn suppress_alert(&self, alert_id: &str, duration_seconds: u64) -> Result<(), AlertError> {
        let mut active_alerts = self.active_alerts.write().await;
        
        if let Some(alert) = active_alerts.get_mut(alert_id) {
            alert.status = AlertStatus::Suppressed;
            
            let mut details = HashMap::new();
            details.insert("suppressed_duration".to_string(), duration_seconds.to_string());
            
            self.record_alert_history_with_details(alert, AlertEventType::Suppressed, details).await?;
            
            // Schedule unsuppression (in a real implementation)
            log::info!("Alert {} suppressed for {} seconds", alert_id, duration_seconds);
            Ok(())
        } else {
            Err(AlertError::AlertNotFound(alert_id.to_string()))
        }
    }

    pub async fn get_active_alerts(&self) -> Result<Vec<Alert>, AlertError> {
        let active_alerts = self.active_alerts.read().await;
        Ok(active_alerts.values().cloned().collect())
    }

    pub async fn get_alert_history(
        &self, 
        start_time: DateTime<Utc>, 
        end_time: DateTime<Utc>
    ) -> Result<Vec<AlertHistory>, AlertError> {
        let history = self.alert_history.read().await;
        Ok(history
            .iter()
            .filter(|h| h.timestamp >= start_time && h.timestamp <= end_time)
            .cloned()
            .collect())
    }

    pub async fn cleanup_old_alerts(&self, cutoff_date: DateTime<Utc>) -> Result<(), AlertError> {
        // Remove resolved alerts older than cutoff
        let mut active_alerts = self.active_alerts.write().await;
        active_alerts.retain(|_, alert| {
            match alert.status {
                AlertStatus::Resolved => {
                    alert.resolved_at.map_or(true, |resolved| resolved > cutoff_date)
                }
                _ => true
            }
        });

        // Cleanup history
        let mut history = self.alert_history.write().await;
        history.retain(|h| h.timestamp > cutoff_date);

        log::info!("Cleaned up old alerts before {}", cutoff_date);
        Ok(())
    }

    async fn evaluate_metric_query(&self, _query: &str) -> Result<f64, AlertError> {
        // Placeholder - in real implementation, this would query the metrics system
        Ok(50.0)
    }

    fn evaluate_condition(&self, condition: &AlertCondition, value: f64, threshold: f64) -> bool {
        match condition {
            AlertCondition::GreaterThan => value > threshold,
            AlertCondition::LessThan => value < threshold,
            AlertCondition::Equal => (value - threshold).abs() < f64::EPSILON,
            AlertCondition::NotEqual => (value - threshold).abs() > f64::EPSILON,
            AlertCondition::GreaterThanOrEqual => value >= threshold,
            AlertCondition::LessThanOrEqual => value <= threshold,
            AlertCondition::Change => false, // Would need previous value
            AlertCondition::NoData => false, // Would need to check data availability
        }
    }

    fn generate_alert_fingerprint(&self, rule: &AlertRule, _current_value: f64) -> String {
        // Generate a stable fingerprint for alert grouping
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        rule.name.hash(&mut hasher);
        rule.metric_query.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    async fn send_alert_notifications(&self, alert: &Alert) -> Result<(), AlertError> {
        let channels = self.notification_channels.read().await;
        let rules = self.alert_rules.read().await;
        
        if let Some(rule) = rules.get(&alert.rule_id) {
            let mut notification_channels = rule.notification_channels.clone();
            
            // Add default channels if none specified
            if notification_channels.is_empty() {
                notification_channels.extend(self.config.default_notification_channels.clone());
            }

            for channel_id in &notification_channels {
                if let Some(channel) = channels.get(channel_id) {
                    if channel.enabled && self.should_notify(channel, alert) {
                        match self.send_notification(channel, alert).await {
                            Ok(_) => {
                                log::info!("Sent notification for alert {} to channel {}", alert.id, channel.name);
                            }
                            Err(e) => {
                                log::error!("Failed to send notification to {}: {}", channel.name, e);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn should_notify(&self, channel: &NotificationChannel, alert: &Alert) -> bool {
        for filter in &channel.filters {
            // Check severity range
            if alert.severity < filter.severity_min || alert.severity > filter.severity_max {
                continue;
            }

            // Check labels
            let mut labels_match = true;
            for (key, value) in &filter.labels {
                if alert.labels.get(key) != Some(value) {
                    labels_match = false;
                    break;
                }
            }

            if !labels_match {
                continue;
            }

            // Check time ranges (simplified - would need proper time zone handling)
            if filter.time_ranges.is_empty() {
                return true;
            }
        }

        true // Allow by default if no filters match
    }

    async fn send_notification(&self, channel: &NotificationChannel, alert: &Alert) -> Result<(), AlertError> {
        match channel.channel_type {
            NotificationChannelType::Email => {
                self.send_email_notification(channel, alert).await
            }
            NotificationChannelType::Slack => {
                self.send_slack_notification(channel, alert).await
            }
            NotificationChannelType::Webhook => {
                self.send_webhook_notification(channel, alert).await
            }
            NotificationChannelType::SMS => {
                self.send_sms_notification(channel, alert).await
            }
            NotificationChannelType::PagerDuty => {
                self.send_pagerduty_notification(channel, alert).await
            }
            NotificationChannelType::Teams => {
                self.send_teams_notification(channel, alert).await
            }
        }
    }

    async fn send_email_notification(&self, _channel: &NotificationChannel, _alert: &Alert) -> Result<(), AlertError> {
        // Placeholder - implement email sending
        log::info!("Sending email notification (placeholder)");
        Ok(())
    }

    async fn send_slack_notification(&self, channel: &NotificationChannel, alert: &Alert) -> Result<(), AlertError> {
        if let Some(webhook_url) = &channel.config.slack_webhook_url {
            let payload = serde_json::json!({
                "text": format!("🚨 Alert: {} - {}", alert.name, alert.description),
                "channel": channel.config.slack_channel.as_deref().unwrap_or("#alerts"),
                "username": channel.config.slack_username.as_deref().unwrap_or("AlertBot"),
                "attachments": [{
                    "color": self.severity_to_color(&alert.severity),
                    "fields": [
                        {
                            "title": "Severity",
                            "value": format!("{:?}", alert.severity),
                            "short": true
                        },
                        {
                            "title": "Current Value",
                            "value": alert.current_value.map_or("N/A".to_string(), |v| v.to_string()),
                            "short": true
                        },
                        {
                            "title": "Threshold",
                            "value": alert.threshold.to_string(),
                            "short": true
                        },
                        {
                            "title": "Triggered At",
                            "value": alert.triggered_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                            "short": true
                        }
                    ]
                }]
            });

            let client = reqwest::Client::new();
            let response = client
                .post(webhook_url)
                .json(&payload)
                .send()
                .await
                .map_err(|e| AlertError::NotificationFailed(e.to_string()))?;

            if !response.status().is_success() {
                return Err(AlertError::NotificationFailed(
                    format!("Slack webhook returned {}", response.status())
                ));
            }
        }

        Ok(())
    }

    async fn send_webhook_notification(&self, channel: &NotificationChannel, alert: &Alert) -> Result<(), AlertError> {
        if let Some(webhook_url) = &channel.config.webhook_url {
            let client = reqwest::Client::new();
            let mut request = client.post(webhook_url);

            // Add headers
            for (key, value) in &channel.config.webhook_headers {
                request = request.header(key, value);
            }

            let payload = serde_json::to_value(alert)
                .map_err(|e| AlertError::SerializationError(e.to_string()))?;

            let response = request
                .json(&payload)
                .send()
                .await
                .map_err(|e| AlertError::NotificationFailed(e.to_string()))?;

            if !response.status().is_success() {
                return Err(AlertError::NotificationFailed(
                    format!("Webhook returned {}", response.status())
                ));
            }
        }

        Ok(())
    }

    async fn send_sms_notification(&self, _channel: &NotificationChannel, _alert: &Alert) -> Result<(), AlertError> {
        // Placeholder - implement SMS sending
        log::info!("Sending SMS notification (placeholder)");
        Ok(())
    }

    async fn send_pagerduty_notification(&self, _channel: &NotificationChannel, _alert: &Alert) -> Result<(), AlertError> {
        // Placeholder - implement PagerDuty integration
        log::info!("Sending PagerDuty notification (placeholder)");
        Ok(())
    }

    async fn send_teams_notification(&self, _channel: &NotificationChannel, _alert: &Alert) -> Result<(), AlertError> {
        // Placeholder - implement Teams webhook
        log::info!("Sending Teams notification (placeholder)");
        Ok(())
    }

    fn severity_to_color(&self, severity: &AlertSeverity) -> &'static str {
        match severity {
            AlertSeverity::Info => "#36a64f",      // Green
            AlertSeverity::Warning => "#ff9500",   // Orange
            AlertSeverity::Critical => "#ff0000",  // Red
            AlertSeverity::Emergency => "#800080", // Purple
        }
    }

    async fn record_alert_history(&self, alert: &Alert, event_type: AlertEventType) -> Result<(), AlertError> {
        self.record_alert_history_with_details(alert, event_type, HashMap::new()).await
    }

    async fn record_alert_history_with_details(
        &self, 
        alert: &Alert, 
        event_type: AlertEventType,
        details: HashMap<String, String>
    ) -> Result<(), AlertError> {
        let mut history = self.alert_history.write().await;
        
        history.push(AlertHistory {
            alert_id: alert.id.clone(),
            event_type,
            timestamp: Utc::now(),
            details,
        });

        // Limit history size
        if history.len() > self.config.max_alerts_history {
            history.remove(0);
        }

        Ok(())
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            evaluation_interval_seconds: 60,
            max_alerts_history: 10000,
            default_notification_channels: Vec::new(),
            alert_grouping_enabled: true,
            alert_grouping_timeout_seconds: 300,
        }
    }
}

impl Default for NotificationChannelConfig {
    fn default() -> Self {
        Self {
            smtp_server: None,
            smtp_port: None,
            smtp_username: None,
            smtp_password: None,
            email_recipients: Vec::new(),
            slack_webhook_url: None,
            slack_channel: None,
            slack_username: None,
            webhook_url: None,
            webhook_method: None,
            webhook_headers: HashMap::new(),
            sms_service_url: None,
            sms_api_key: None,
            sms_phone_numbers: Vec::new(),
            pagerduty_integration_key: None,
            teams_webhook_url: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    #[error("Alert rule error: {0}")]
    InvalidRule(String),
    
    #[error("Alert rule not found: {0}")]
    RuleNotFound(String),
    
    #[error("Alert not found: {0}")]
    AlertNotFound(String),
    
    #[error("Notification failed: {0}")]
    NotificationFailed(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Alert manager already running")]
    AlreadyRunning,
    
    #[error("Alert manager not running")]
    NotRunning,
    
    #[error("Configuration error: {0}")]
    Configuration(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_alert_rule_management() {
        let config = AlertConfig::default();
        let alert_manager = AlertManager::new(config).await.unwrap();

        let rule = AlertRule {
            id: "test-rule".to_string(),
            name: "Test Rule".to_string(),
            description: "Test alert rule".to_string(),
            metric_query: "cpu_usage".to_string(),
            condition: AlertCondition::GreaterThan,
            threshold: 80.0,
            severity: AlertSeverity::Warning,
            evaluation_window_seconds: 300,
            notification_channels: vec!["email".to_string()],
            enabled: true,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            repeat_interval_seconds: None,
        };

        alert_manager.add_alert_rule(rule).await.unwrap();
        
        let rules = alert_manager.alert_rules.read().await;
        assert_eq!(rules.len(), 1);
        assert!(rules.contains_key("test-rule"));
    }

    #[tokio::test]
    async fn test_notification_channel() {
        let config = AlertConfig::default();
        let alert_manager = AlertManager::new(config).await.unwrap();

        let channel = NotificationChannel {
            id: "slack-channel".to_string(),
            name: "Slack Alerts".to_string(),
            channel_type: NotificationChannelType::Slack,
            config: NotificationChannelConfig {
                slack_webhook_url: Some("https://hooks.slack.com/test".to_string()),
                slack_channel: Some("#alerts".to_string()),
                ..Default::default()
            },
            enabled: true,
            filters: Vec::new(),
        };

        alert_manager.add_notification_channel(channel).await.unwrap();
        
        let channels = alert_manager.notification_channels.read().await;
        assert_eq!(channels.len(), 1);
        assert!(channels.contains_key("slack-channel"));
    }
}