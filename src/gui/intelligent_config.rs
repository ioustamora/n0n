use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::storage::backend::StorageType;
use crate::gui::role_based_ui::{UserProfile, ExpertiseLevel};

/// Intelligent configuration assistance system
/// Provides smart recommendations and auto-configuration based on context
#[derive(Debug, Clone)]
pub struct IntelligentConfigManager {
    recommendations: Vec<ConfigRecommendation>,
    auto_config_rules: Vec<AutoConfigRule>,
    user_patterns: UserBehaviorPatterns,
    context_analyzer: ContextAnalyzer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigRecommendation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: ConfigCategory,
    pub priority: Priority,
    pub applicable_contexts: Vec<ConfigContext>,
    pub suggested_values: HashMap<String, String>,
    pub reasoning: String,
    pub learn_more_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigCategory {
    Security,
    Performance,
    Reliability,
    Storage,
    Network,
    Backup,
    Monitoring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Critical,   // Must be addressed
    High,      // Should be addressed soon
    Medium,    // Consider addressing
    Low,       // Optional improvement
    Info,      // Informational only
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigContext {
    FirstTimeSetup,
    StorageBackendChange,
    SecurityUpgrade,
    PerformanceIssue,
    ScaleUp,
    ComplianceRequirement,
    UserRoleChange,
}

#[derive(Debug, Clone)]
pub struct AutoConfigRule {
    pub name: String,
    pub description: String,
    pub condition: ConfigCondition,
    pub actions: Vec<ConfigAction>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum ConfigCondition {
    StorageType(StorageType),
    UserExpertise(ExpertiseLevel),
    SystemMemory(u64), // MB
    NetworkBandwidth(u64), // Mbps
    FileCount(u64),
    TotalSize(u64), // bytes
    ErrorRate(f64), // percentage
    Combined(Vec<ConfigCondition>),
}

#[derive(Debug, Clone)]
pub enum ConfigAction {
    SetValue(String, String),
    EnableFeature(String),
    DisableFeature(String),
    Recommend(String),
    ShowWarning(String),
}

#[derive(Debug, Clone, Default)]
pub struct UserBehaviorPatterns {
    pub frequently_used_features: HashMap<String, u32>,
    pub configuration_preferences: HashMap<String, String>,
    pub error_patterns: Vec<ErrorPattern>,
    pub usage_statistics: UsageStatistics,
}

#[derive(Debug, Clone)]
pub struct ErrorPattern {
    pub error_type: String,
    pub frequency: u32,
    pub context: String,
    pub suggested_fix: String,
}

#[derive(Debug, Clone, Default)]
pub struct UsageStatistics {
    pub sessions_count: u32,
    pub average_session_duration_minutes: f32,
    pub most_used_storage_backend: Option<StorageType>,
    pub common_file_types: HashMap<String, u32>,
    pub peak_usage_hours: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ContextAnalyzer {
    system_info: SystemInfo,
    current_config: HashMap<String, String>,
    performance_metrics: PerformanceMetrics,
}

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub os: String,
    pub cpu_cores: u32,
    pub total_memory_mb: u64,
    pub available_disk_space_gb: u64,
    pub network_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    pub cpu_usage_avg: f64,
    pub memory_usage_avg: f64,
    pub disk_io_rate: f64,
    pub network_throughput: f64,
    pub error_rate: f64,
}

impl IntelligentConfigManager {
    pub fn new() -> Self {
        let mut manager = Self {
            recommendations: Vec::new(),
            auto_config_rules: Vec::new(),
            user_patterns: UserBehaviorPatterns::default(),
            context_analyzer: ContextAnalyzer::new(),
        };

        manager.initialize_recommendations();
        manager.initialize_auto_config_rules();
        manager
    }

    fn initialize_recommendations(&mut self) {
        // Security recommendations
        self.add_recommendation(
            "encrypt_at_rest",
            "Enable Encryption at Rest",
            "Your sensitive data should be encrypted when stored to prevent unauthorized access.",
            ConfigCategory::Security,
            Priority::Critical,
            vec![ConfigContext::FirstTimeSetup, ConfigContext::SecurityUpgrade],
            [("encryption_enabled", "true"), ("encryption_algorithm", "XSalsa20Poly1305")].iter().cloned().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            "Encryption protects your data from unauthorized access even if storage is compromised."
        );

        self.add_recommendation(
            "strong_passwords",
            "Use Strong Authentication",
            "Configure strong password requirements and consider multi-factor authentication.",
            ConfigCategory::Security,
            Priority::High,
            vec![ConfigContext::FirstTimeSetup, ConfigContext::SecurityUpgrade],
            [("min_password_length", "12"), ("require_mfa", "true")].iter().cloned().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            "Strong authentication prevents unauthorized access to your system."
        );

        // Performance recommendations
        self.add_recommendation(
            "optimize_chunk_size",
            "Optimize Chunk Size",
            "Adjust chunk size based on your typical file sizes and network conditions.",
            ConfigCategory::Performance,
            Priority::Medium,
            vec![ConfigContext::PerformanceIssue, ConfigContext::FirstTimeSetup],
            [("chunk_size_mb", "16")].iter().cloned().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            "Optimal chunk size improves transfer speeds and reduces memory usage."
        );

        self.add_recommendation(
            "enable_compression",
            "Enable Data Compression",
            "Compress data before storage to reduce bandwidth and storage costs.",
            ConfigCategory::Performance,
            Priority::Low,
            vec![ConfigContext::ScaleUp, ConfigContext::StorageBackendChange],
            [("compression_enabled", "true"), ("compression_level", "6")].iter().cloned().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            "Compression reduces storage costs and improves transfer speeds for text-based files."
        );

        // Reliability recommendations
        self.add_recommendation(
            "setup_backup_schedule",
            "Configure Automated Backups",
            "Set up regular automated backups to prevent data loss.",
            ConfigCategory::Reliability,
            Priority::Critical,
            vec![ConfigContext::FirstTimeSetup],
            [("backup_enabled", "true"), ("backup_frequency", "daily")].iter().cloned().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            "Regular backups protect against data loss from hardware failures or human error."
        );

        // Storage recommendations
        self.add_recommendation(
            "multicloud_redundancy",
            "Enable Multi-Cloud Redundancy",
            "Replicate data across multiple cloud providers for maximum availability.",
            ConfigCategory::Reliability,
            Priority::Medium,
            vec![ConfigContext::ComplianceRequirement, ConfigContext::ScaleUp],
            [("multicloud_enabled", "true"), ("replication_factor", "2")].iter().cloned().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            "Multi-cloud storage prevents vendor lock-in and improves data availability."
        );
    }

    fn add_recommendation(&mut self, id: &str, title: &str, description: &str,
                         category: ConfigCategory, priority: Priority,
                         contexts: Vec<ConfigContext>, values: HashMap<String, String>,
                         reasoning: &str) {
        self.recommendations.push(ConfigRecommendation {
            id: id.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            category,
            priority,
            applicable_contexts: contexts,
            suggested_values: values,
            reasoning: reasoning.to_string(),
            learn_more_url: None,
        });
    }

    fn initialize_auto_config_rules(&mut self) {
        // Auto-configure based on storage type
        self.auto_config_rules.push(AutoConfigRule {
            name: "S3 Optimization".to_string(),
            description: "Automatically optimize settings for S3 storage".to_string(),
            condition: ConfigCondition::StorageType(StorageType::S3Compatible),
            actions: vec![
                ConfigAction::SetValue("chunk_size_mb".to_string(), "32".to_string()),
                ConfigAction::SetValue("concurrent_uploads".to_string(), "4".to_string()),
                ConfigAction::EnableFeature("multipart_upload".to_string()),
            ],
            enabled: true,
        });

        // Auto-configure for beginners
        self.auto_config_rules.push(AutoConfigRule {
            name: "Beginner Optimization".to_string(),
            description: "Simplified settings for new users".to_string(),
            condition: ConfigCondition::UserExpertise(ExpertiseLevel::Beginner),
            actions: vec![
                ConfigAction::SetValue("encryption_enabled".to_string(), "true".to_string()),
                ConfigAction::SetValue("backup_enabled".to_string(), "true".to_string()),
                ConfigAction::EnableFeature("auto_retry".to_string()),
                ConfigAction::DisableFeature("debug_logging".to_string()),
            ],
            enabled: true,
        });

        // Auto-configure for high memory systems
        self.auto_config_rules.push(AutoConfigRule {
            name: "High Memory Optimization".to_string(),
            description: "Optimize for systems with plenty of RAM".to_string(),
            condition: ConfigCondition::SystemMemory(8192), // 8GB+
            actions: vec![
                ConfigAction::SetValue("cache_size_mb".to_string(), "1024".to_string()),
                ConfigAction::SetValue("concurrent_operations".to_string(), "8".to_string()),
                ConfigAction::EnableFeature("aggressive_caching".to_string()),
            ],
            enabled: true,
        });
    }

    pub fn analyze_context(&mut self, context: ConfigContext) -> Vec<ConfigRecommendation> {
        self.recommendations.iter()
            .filter(|rec| rec.applicable_contexts.contains(&context))
            .cloned()
            .collect()
    }

    pub fn get_recommendations_for_user(&self, profile: &UserProfile) -> Vec<ConfigRecommendation> {
        let mut recommendations = Vec::new();

        for rec in &self.recommendations {
            // Filter by expertise level
            let should_show = match profile.expertise_level {
                ExpertiseLevel::Beginner => {
                    matches!(rec.priority, Priority::Critical | Priority::High)
                }
                ExpertiseLevel::Intermediate => {
                    !matches!(rec.priority, Priority::Info)
                }
                ExpertiseLevel::Advanced | ExpertiseLevel::Expert => true,
            };

            if should_show {
                recommendations.push(rec.clone());
            }
        }

        // Sort by priority
        recommendations.sort_by(|a, b| {
            let priority_order = |p: &Priority| match p {
                Priority::Critical => 0,
                Priority::High => 1,
                Priority::Medium => 2,
                Priority::Low => 3,
                Priority::Info => 4,
            };
            priority_order(&a.priority).cmp(&priority_order(&b.priority))
        });

        recommendations
    }

    pub fn apply_auto_config(&self, current_config: &mut HashMap<String, String>) -> Vec<String> {
        let mut applied_rules = Vec::new();

        for rule in &self.auto_config_rules {
            if !rule.enabled {
                continue;
            }

            if self.evaluate_condition(&rule.condition, current_config) {
                for action in &rule.actions {
                    match action {
                        ConfigAction::SetValue(key, value) => {
                            current_config.insert(key.clone(), value.clone());
                        }
                        ConfigAction::EnableFeature(feature) => {
                            current_config.insert(feature.clone(), "true".to_string());
                        }
                        ConfigAction::DisableFeature(feature) => {
                            current_config.insert(feature.clone(), "false".to_string());
                        }
                        ConfigAction::Recommend(_) | ConfigAction::ShowWarning(_) => {
                            // These are handled in the UI
                        }
                    }
                }
                applied_rules.push(rule.name.clone());
            }
        }

        applied_rules
    }

    fn evaluate_condition(&self, condition: &ConfigCondition, config: &HashMap<String, String>) -> bool {
        match condition {
            ConfigCondition::StorageType(storage_type) => {
                if let Some(current_type) = config.get("storage_type") {
                    current_type == &format!("{:?}", storage_type)
                } else {
                    false
                }
            }
            ConfigCondition::UserExpertise(level) => {
                if let Some(current_level) = config.get("expertise_level") {
                    current_level == &format!("{:?}", level)
                } else {
                    false
                }
            }
            ConfigCondition::SystemMemory(min_mb) => {
                self.context_analyzer.system_info.total_memory_mb >= *min_mb
            }
            ConfigCondition::Combined(conditions) => {
                conditions.iter().all(|c| self.evaluate_condition(c, config))
            }
            _ => false, // Other conditions not implemented yet
        }
    }

    pub fn render_recommendations(&mut self, ui: &mut egui::Ui, profile: &UserProfile) {
        let recommendations = self.get_recommendations_for_user(profile);

        ui.heading("💡 Smart Recommendations");
        ui.add_space(5.0);

        if recommendations.is_empty() {
            ui.label("No recommendations at this time. Your configuration looks good!");
            return;
        }

        egui::ScrollArea::vertical()
            .max_height(400.0)
            .show(ui, |ui| {
                for rec in &recommendations {
                    self.render_recommendation_card(ui, rec);
                    ui.add_space(10.0);
                }
            });
    }

    fn render_recommendation_card(&self, ui: &mut egui::Ui, rec: &ConfigRecommendation) {
        let color = match rec.priority {
            Priority::Critical => egui::Color32::from_rgb(220, 53, 69),
            Priority::High => egui::Color32::from_rgb(255, 193, 7),
            Priority::Medium => egui::Color32::from_rgb(54, 162, 235),
            Priority::Low => egui::Color32::from_rgb(108, 117, 125),
            Priority::Info => egui::Color32::from_rgb(23, 162, 184),
        };

        ui.group(|ui| {
            ui.horizontal(|ui| {
                // Priority indicator
                ui.colored_label(color, "●");

                // Title and category
                ui.vertical(|ui| {
                    ui.strong(&rec.title);
                    ui.small(format!("{:?} • {:?}", rec.category, rec.priority));
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Apply").clicked() {
                        // Apply recommendation logic would go here
                    }
                    if ui.button("Dismiss").clicked() {
                        // Dismiss recommendation logic would go here
                    }
                });
            });

            ui.separator();

            // Description
            ui.label(&rec.description);

            // Reasoning (collapsible)
            ui.collapsing("Why this recommendation?", |ui| {
                ui.small(&rec.reasoning);
            });

            // Suggested values (if any)
            if !rec.suggested_values.is_empty() {
                ui.collapsing("Suggested Configuration", |ui| {
                    for (key, value) in &rec.suggested_values {
                        ui.horizontal(|ui| {
                            ui.small(key);
                            ui.small("→");
                            ui.small(value);
                        });
                    }
                });
            }
        });
    }

    pub fn render_auto_config_panel(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading("🤖 Auto-Configuration");
            ui.separator();

            ui.label("Automatic configuration rules that adapt your settings:");

            for rule in &mut self.auto_config_rules {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut rule.enabled, &rule.name);
                    ui.small(&rule.description);
                });
            }

            ui.add_space(10.0);

            if ui.button("🔍 Analyze & Apply Auto-Config").clicked() {
                let mut temp_config = HashMap::new();
                let applied = self.apply_auto_config(&mut temp_config);

                if !applied.is_empty() {
                    println!("Applied auto-config rules: {:?}", applied);
                }
            }
        });
    }

    pub fn learn_from_user_action(&mut self, action: &str, context: &str, success: bool) {
        // Track user behavior for future recommendations
        *self.user_patterns.frequently_used_features.entry(action.to_string()).or_insert(0) += 1;

        if !success {
            self.user_patterns.error_patterns.push(ErrorPattern {
                error_type: action.to_string(),
                frequency: 1,
                context: context.to_string(),
                suggested_fix: "Check configuration and try again".to_string(),
            });
        }
    }

    pub fn update_usage_statistics(&mut self, session_duration_minutes: f32) {
        self.user_patterns.usage_statistics.sessions_count += 1;

        let sessions = self.user_patterns.usage_statistics.sessions_count as f32;
        let current_avg = self.user_patterns.usage_statistics.average_session_duration_minutes;

        // Update rolling average
        self.user_patterns.usage_statistics.average_session_duration_minutes =
            (current_avg * (sessions - 1.0) + session_duration_minutes) / sessions;
    }
}

impl ContextAnalyzer {
    pub fn new() -> Self {
        Self {
            system_info: SystemInfo::detect(),
            current_config: HashMap::new(),
            performance_metrics: PerformanceMetrics::default(),
        }
    }

    pub fn analyze_performance_trends(&self) -> Vec<String> {
        let mut insights = Vec::new();

        if self.performance_metrics.cpu_usage_avg > 80.0 {
            insights.push("High CPU usage detected. Consider reducing concurrent operations.".to_string());
        }

        if self.performance_metrics.memory_usage_avg > 85.0 {
            insights.push("High memory usage detected. Consider reducing cache size.".to_string());
        }

        if self.performance_metrics.error_rate > 5.0 {
            insights.push("High error rate detected. Check network connectivity and storage backend status.".to_string());
        }

        insights
    }
}

impl SystemInfo {
    pub fn detect() -> Self {
        // In a real implementation, this would detect actual system information
        Self {
            os: std::env::consts::OS.to_string(),
            cpu_cores: num_cpus::get() as u32,
            total_memory_mb: 8192, // Mock value
            available_disk_space_gb: 500, // Mock value
            network_interfaces: vec!["eth0".to_string(), "lo".to_string()],
        }
    }
}

impl Default for IntelligentConfigManager {
    fn default() -> Self {
        Self::new()
    }
}