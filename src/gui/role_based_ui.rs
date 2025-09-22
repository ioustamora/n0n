use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Role-based interface customization system
/// Provides different UI experiences based on user roles and expertise levels
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserRole {
    EndUser,      // Basic file sync operations
    Administrator, // System configuration and management
    SecurityOfficer, // Security policies and audit
    Developer,    // Advanced features and debugging
    Operations,   // Monitoring and maintenance
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpertiseLevel {
    Beginner,     // Guided workflows, minimal options
    Intermediate, // Balanced interface with help
    Advanced,     // Full feature set, minimal guidance
    Expert,       // Power user interface, all options
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub role: UserRole,
    pub expertise_level: ExpertiseLevel,
    pub preferred_features: HashSet<String>,
    pub hidden_features: HashSet<String>,
    pub custom_shortcuts: HashMap<String, String>,
    pub dashboard_layout: DashboardLayout,
    pub notification_preferences: NotificationPreferences,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardLayout {
    pub widgets: Vec<DashboardWidget>,
    pub layout_style: LayoutStyle,
    pub show_advanced_metrics: bool,
    pub refresh_interval_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayoutStyle {
    Compact,    // Dense information display
    Comfortable, // Balanced spacing
    Spacious,   // Generous whitespace
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardWidget {
    pub widget_type: WidgetType,
    pub position: (u32, u32),
    pub size: (u32, u32),
    pub visible: bool,
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WidgetType {
    SystemStatus,
    StorageOverview,
    RecentActivity,
    QuickActions,
    SecurityAlerts,
    PerformanceMetrics,
    BackupStatus,
    NetworkActivity,
    UserActivity,
    ErrorLog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPreferences {
    pub show_success_notifications: bool,
    pub show_warning_notifications: bool,
    pub show_error_notifications: bool,
    pub show_info_notifications: bool,
    pub toast_duration_seconds: u32,
    pub max_notifications: u32,
}

#[derive(Debug, Clone)]
pub struct RoleBasedUIManager {
    pub current_profile: UserProfile,
    pub available_features: HashMap<UserRole, Vec<String>>,
    pub feature_descriptions: HashMap<String, FeatureDescription>,
    pub ui_customizations: UICustomizations,
}

#[derive(Debug, Clone)]
pub struct FeatureDescription {
    pub name: String,
    pub description: String,
    pub expertise_required: ExpertiseLevel,
    pub roles_allowed: Vec<UserRole>,
    pub category: FeatureCategory,
}

#[derive(Debug, Clone)]
pub enum FeatureCategory {
    Core,
    Security,
    Administration,
    Monitoring,
    Advanced,
    Development,
}

#[derive(Debug, Clone)]
pub struct UICustomizations {
    pub simplified_navigation: bool,
    pub contextual_help_enabled: bool,
    pub advanced_options_hidden: bool,
    pub confirmation_dialogs_enabled: bool,
    pub keyboard_shortcuts_enabled: bool,
}

impl Default for UserProfile {
    fn default() -> Self {
        Self {
            role: UserRole::EndUser,
            expertise_level: ExpertiseLevel::Beginner,
            preferred_features: HashSet::new(),
            hidden_features: HashSet::new(),
            custom_shortcuts: HashMap::new(),
            dashboard_layout: DashboardLayout::default(),
            notification_preferences: NotificationPreferences::default(),
        }
    }
}

impl Default for DashboardLayout {
    fn default() -> Self {
        Self {
            widgets: vec![
                DashboardWidget {
                    widget_type: WidgetType::SystemStatus,
                    position: (0, 0),
                    size: (2, 1),
                    visible: true,
                    config: HashMap::new(),
                },
                DashboardWidget {
                    widget_type: WidgetType::StorageOverview,
                    position: (2, 0),
                    size: (2, 1),
                    visible: true,
                    config: HashMap::new(),
                },
                DashboardWidget {
                    widget_type: WidgetType::QuickActions,
                    position: (0, 1),
                    size: (4, 1),
                    visible: true,
                    config: HashMap::new(),
                },
            ],
            layout_style: LayoutStyle::Comfortable,
            show_advanced_metrics: false,
            refresh_interval_seconds: 5,
        }
    }
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            show_success_notifications: true,
            show_warning_notifications: true,
            show_error_notifications: true,
            show_info_notifications: true,
            toast_duration_seconds: 5,
            max_notifications: 50,
        }
    }
}

impl RoleBasedUIManager {
    pub fn new() -> Self {
        let mut manager = Self {
            current_profile: UserProfile::default(),
            available_features: HashMap::new(),
            feature_descriptions: HashMap::new(),
            ui_customizations: UICustomizations::default(),
        };

        manager.initialize_features();
        manager
    }

    pub fn with_profile(profile: UserProfile) -> Self {
        let mut manager = Self::new();
        manager.set_user_profile(profile);
        manager
    }

    fn initialize_features(&mut self) {
        // Define features available to each role
        self.available_features.insert(UserRole::EndUser, vec![
            "file_sync".to_string(),
            "basic_storage".to_string(),
            "simple_backup".to_string(),
            "view_activity".to_string(),
        ]);

        self.available_features.insert(UserRole::Administrator, vec![
            "file_sync".to_string(),
            "storage_management".to_string(),
            "backup_scheduling".to_string(),
            "user_management".to_string(),
            "system_configuration".to_string(),
            "view_logs".to_string(),
        ]);

        self.available_features.insert(UserRole::SecurityOfficer, vec![
            "security_policies".to_string(),
            "audit_logs".to_string(),
            "access_control".to_string(),
            "encryption_management".to_string(),
            "compliance_reporting".to_string(),
            "security_monitoring".to_string(),
        ]);

        self.available_features.insert(UserRole::Developer, vec![
            "api_access".to_string(),
            "debug_mode".to_string(),
            "advanced_configuration".to_string(),
            "custom_scripts".to_string(),
            "performance_profiling".to_string(),
            "raw_data_access".to_string(),
        ]);

        self.available_features.insert(UserRole::Operations, vec![
            "system_monitoring".to_string(),
            "performance_metrics".to_string(),
            "alert_management".to_string(),
            "maintenance_mode".to_string(),
            "backup_verification".to_string(),
            "resource_planning".to_string(),
        ]);

        // Define feature descriptions
        self.add_feature("file_sync", "File Synchronization",
                        "Synchronize files across storage backends",
                        ExpertiseLevel::Beginner,
                        vec![UserRole::EndUser, UserRole::Administrator],
                        FeatureCategory::Core);

        self.add_feature("storage_management", "Storage Management",
                        "Configure and manage storage backends",
                        ExpertiseLevel::Intermediate,
                        vec![UserRole::Administrator],
                        FeatureCategory::Administration);

        self.add_feature("security_policies", "Security Policies",
                        "Define and enforce security policies",
                        ExpertiseLevel::Advanced,
                        vec![UserRole::SecurityOfficer],
                        FeatureCategory::Security);

        self.add_feature("debug_mode", "Debug Mode",
                        "Advanced debugging and troubleshooting tools",
                        ExpertiseLevel::Expert,
                        vec![UserRole::Developer],
                        FeatureCategory::Development);
    }

    fn add_feature(&mut self, key: &str, name: &str, description: &str,
                   expertise: ExpertiseLevel, roles: Vec<UserRole>, category: FeatureCategory) {
        self.feature_descriptions.insert(key.to_string(), FeatureDescription {
            name: name.to_string(),
            description: description.to_string(),
            expertise_required: expertise,
            roles_allowed: roles,
            category,
        });
    }

    pub fn set_user_profile(&mut self, profile: UserProfile) {
        self.current_profile = profile;
        self.update_ui_customizations();
    }

    pub fn update_ui_customizations(&mut self) {
        match self.current_profile.expertise_level {
            ExpertiseLevel::Beginner => {
                self.ui_customizations.simplified_navigation = true;
                self.ui_customizations.contextual_help_enabled = true;
                self.ui_customizations.advanced_options_hidden = true;
                self.ui_customizations.confirmation_dialogs_enabled = true;
                self.ui_customizations.keyboard_shortcuts_enabled = false;
            }
            ExpertiseLevel::Intermediate => {
                self.ui_customizations.simplified_navigation = false;
                self.ui_customizations.contextual_help_enabled = true;
                self.ui_customizations.advanced_options_hidden = false;
                self.ui_customizations.confirmation_dialogs_enabled = true;
                self.ui_customizations.keyboard_shortcuts_enabled = true;
            }
            ExpertiseLevel::Advanced => {
                self.ui_customizations.simplified_navigation = false;
                self.ui_customizations.contextual_help_enabled = false;
                self.ui_customizations.advanced_options_hidden = false;
                self.ui_customizations.confirmation_dialogs_enabled = false;
                self.ui_customizations.keyboard_shortcuts_enabled = true;
            }
            ExpertiseLevel::Expert => {
                self.ui_customizations.simplified_navigation = false;
                self.ui_customizations.contextual_help_enabled = false;
                self.ui_customizations.advanced_options_hidden = false;
                self.ui_customizations.confirmation_dialogs_enabled = false;
                self.ui_customizations.keyboard_shortcuts_enabled = true;
            }
        }
    }

    pub fn is_feature_available(&self, feature: &str) -> bool {
        if let Some(role_features) = self.available_features.get(&self.current_profile.role) {
            role_features.contains(&feature.to_string())
        } else {
            false
        }
    }

    pub fn should_show_feature(&self, feature: &str) -> bool {
        if !self.is_feature_available(feature) {
            return false;
        }

        if self.current_profile.hidden_features.contains(feature) {
            return false;
        }

        if let Some(feature_desc) = self.feature_descriptions.get(feature) {
            match self.current_profile.expertise_level {
                ExpertiseLevel::Beginner => {
                    matches!(feature_desc.expertise_required, ExpertiseLevel::Beginner)
                }
                ExpertiseLevel::Intermediate => {
                    matches!(feature_desc.expertise_required,
                           ExpertiseLevel::Beginner | ExpertiseLevel::Intermediate)
                }
                ExpertiseLevel::Advanced => {
                    !matches!(feature_desc.expertise_required, ExpertiseLevel::Expert)
                }
                ExpertiseLevel::Expert => true,
            }
        } else {
            true
        }
    }

    pub fn get_available_features(&self) -> Vec<String> {
        if let Some(role_features) = self.available_features.get(&self.current_profile.role) {
            role_features.iter()
                .filter(|feature| self.should_show_feature(feature))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn render_role_selector(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading("User Profile");
            ui.separator();

            // Role selection
            ui.horizontal(|ui| {
                ui.label("Role:");
                let current_role = &mut self.current_profile.role;
                egui::ComboBox::from_id_source("role_selector")
                    .selected_text(format!("{:?}", current_role))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(current_role, UserRole::EndUser, "End User");
                        ui.selectable_value(current_role, UserRole::Administrator, "Administrator");
                        ui.selectable_value(current_role, UserRole::SecurityOfficer, "Security Officer");
                        ui.selectable_value(current_role, UserRole::Developer, "Developer");
                        ui.selectable_value(current_role, UserRole::Operations, "Operations");
                    });
            });

            // Expertise level selection
            ui.horizontal(|ui| {
                ui.label("Expertise:");
                let current_level = &mut self.current_profile.expertise_level;
                egui::ComboBox::from_id_source("expertise_selector")
                    .selected_text(format!("{:?}", current_level))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(current_level, ExpertiseLevel::Beginner, "Beginner");
                        ui.selectable_value(current_level, ExpertiseLevel::Intermediate, "Intermediate");
                        ui.selectable_value(current_level, ExpertiseLevel::Advanced, "Advanced");
                        ui.selectable_value(current_level, ExpertiseLevel::Expert, "Expert");
                    });
            });

            if ui.button("Apply Profile").clicked() {
                self.update_ui_customizations();
            }
        });
    }

    pub fn render_feature_customization(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading("Feature Customization");
            ui.separator();

            let available_features = self.get_available_features();

            ui.label(format!("Available features for {:?}:", self.current_profile.role));

            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for feature in &available_features {
                        if let Some(feature_desc) = self.feature_descriptions.get(feature) {
                            ui.horizontal(|ui| {
                                let mut visible = !self.current_profile.hidden_features.contains(feature);
                                if ui.checkbox(&mut visible, &feature_desc.name).changed() {
                                    if visible {
                                        self.current_profile.hidden_features.remove(feature);
                                    } else {
                                        self.current_profile.hidden_features.insert(feature.clone());
                                    }
                                }
                                ui.small(&feature_desc.description);
                            });
                        }
                    }
                });
        });
    }

    pub fn render_dashboard_customization(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading("Dashboard Layout");
            ui.separator();

            // Layout style
            ui.horizontal(|ui| {
                ui.label("Layout Style:");
                let current_style = &mut self.current_profile.dashboard_layout.layout_style;
                egui::ComboBox::from_id_source("layout_style")
                    .selected_text(format!("{:?}", current_style))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(current_style, LayoutStyle::Compact, "Compact");
                        ui.selectable_value(current_style, LayoutStyle::Comfortable, "Comfortable");
                        ui.selectable_value(current_style, LayoutStyle::Spacious, "Spacious");
                    });
            });

            // Advanced metrics toggle
            ui.checkbox(&mut self.current_profile.dashboard_layout.show_advanced_metrics,
                       "Show Advanced Metrics");

            // Refresh interval
            ui.horizontal(|ui| {
                ui.label("Refresh Interval (seconds):");
                ui.add(egui::DragValue::new(&mut self.current_profile.dashboard_layout.refresh_interval_seconds)
                    .clamp_range(1..=60));
            });

            // Widget visibility
            ui.label("Dashboard Widgets:");
            egui::ScrollArea::vertical()
                .max_height(150.0)
                .show(ui, |ui| {
                    for widget in &mut self.current_profile.dashboard_layout.widgets {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut widget.visible, format!("{:?}", widget.widget_type));
                        });
                    }
                });
        });
    }

    pub fn get_dashboard_spacing(&self) -> f32 {
        match self.current_profile.dashboard_layout.layout_style {
            LayoutStyle::Compact => 5.0,
            LayoutStyle::Comfortable => 10.0,
            LayoutStyle::Spacious => 20.0,
        }
    }

    pub fn should_show_contextual_help(&self) -> bool {
        self.ui_customizations.contextual_help_enabled
    }

    pub fn should_show_advanced_options(&self) -> bool {
        !self.ui_customizations.advanced_options_hidden
    }

    pub fn should_confirm_actions(&self) -> bool {
        self.ui_customizations.confirmation_dialogs_enabled
    }

    pub fn save_profile(&self) -> Result<(), Box<dyn std::error::Error>> {
        let profile_json = serde_json::to_string_pretty(&self.current_profile)?;
        std::fs::write("user_profile.json", profile_json)?;
        Ok(())
    }

    pub fn load_profile(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(profile_json) = std::fs::read_to_string("user_profile.json") {
            let profile: UserProfile = serde_json::from_str(&profile_json)?;
            self.set_user_profile(profile);
        }
        Ok(())
    }
}

impl Default for UICustomizations {
    fn default() -> Self {
        Self {
            simplified_navigation: true,
            contextual_help_enabled: true,
            advanced_options_hidden: true,
            confirmation_dialogs_enabled: true,
            keyboard_shortcuts_enabled: false,
        }
    }
}

impl Default for RoleBasedUIManager {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions for role-based UI rendering
impl RoleBasedUIManager {
    pub fn render_contextual_help(&self, ui: &mut egui::Ui, context: &str, help_text: &str) {
        if self.should_show_contextual_help() {
            ui.horizontal(|ui| {
                ui.small("ℹ");
                ui.small(help_text);
            });
        }
    }

    pub fn render_with_confirmation<F>(&self, ui: &mut egui::Ui, button_text: &str,
                                       confirmation_text: &str, action: F)
    where F: FnOnce() {
        if self.should_confirm_actions() {
            // In a real implementation, this would show a confirmation dialog
            if ui.button(button_text).clicked() {
                // Show confirmation popup
                action();
            }
        } else {
            if ui.button(button_text).clicked() {
                action();
            }
        }
    }

    pub fn get_feature_description(&self, feature: &str) -> Option<&FeatureDescription> {
        self.feature_descriptions.get(feature)
    }
}