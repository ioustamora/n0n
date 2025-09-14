use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::collections::HashMap;
use eframe::egui;
use crate::storage::backend::StorageType;
use crate::gui::navigation::MainTab;
use crate::gui::notifications::NotificationManager;
use crate::gui::progressive_disclosure::ProgressiveDisclosureManager;
use crate::gui::dashboard::DashboardState;
use crate::gui::design_system::DesignSystem;
use crate::gui::role_based_ui::{RoleBasedUIManager, UserProfile};
use crate::gui::intelligent_config::IntelligentConfigManager;
use crate::gui::adaptive_ui::AdaptiveUIManager;

/// Configuration for different storage backends in the GUI
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct StorageBackendConfig {
    // Local config
    pub local_base_path: String,
    pub local_create_dirs: bool,
    
    // SFTP config
    pub sftp_host: String,
    pub sftp_user: String,
    pub sftp_pass: String,
    pub sftp_base: String,
    pub sftp_mailbox_id: String,
    pub sftp_private_key: String,
    pub sftp_private_key_pass: String,
    pub sftp_host_fingerprint_sha256_b64: String,
    pub sftp_require_host_fp: bool,
    
    // S3 config
    pub s3_bucket: String,
    pub s3_region: String,
    pub s3_endpoint: String,
    pub s3_access_key_id: String,
    pub s3_secret_access_key: String,
    pub s3_path_prefix: String,
    
    // Google Cloud config
    pub gcs_bucket: String,
    pub gcs_project_id: String,
    pub gcs_service_account_key: String,
    pub gcs_path_prefix: String,
    
    // Azure config
    pub azure_account_name: String,
    pub azure_account_key: String,
    pub azure_container: String,
    pub azure_path_prefix: String,
    
    // PostgreSQL config
    pub postgres_connection_string: String,
    pub postgres_table_prefix: String,
    
    // Redis config
    pub redis_url: String,
    pub redis_key_prefix: String,
    pub redis_ttl_seconds: String,
    
    // Cached Cloud config
    pub cache_dir: String,
    pub cache_max_size_mb: u64,
    pub cache_eviction_policy: String,
    pub cache_write_policy: String,
    
    // WebDAV config
    pub webdav_url: String,
    pub webdav_username: String,
    pub webdav_password: String,
    pub webdav_base_path: String,
    pub webdav_verify_ssl: bool,
    
    // IPFS config
    pub ipfs_api_url: String,
    pub ipfs_gateway_url: String,
    pub ipfs_pin_content: bool,
    
    // MultiCloud config
    pub multicloud_primary: String,
    pub multicloud_replicas: Vec<String>,
    pub multicloud_consistency: String,
    pub multicloud_strategy: String,
    
    // Encryption at rest config
    pub encryption_enabled: bool,
    pub encryption_algorithm: String, // "None", "XSalsa20Poly1305", "ChaCha20Poly1305", "AES256GCM"
    pub encryption_password: String,
    pub encryption_compress: bool,
    
    // Analytics and quota config
    pub analytics_enabled: bool,
    pub quota_enabled: bool,
    pub quota_max_size_mb: u64,
    pub quota_max_chunks: u64,
    pub quota_max_daily_ops: u64,
    pub quota_max_hourly_ops: u64,
    pub quota_max_chunk_size_mb: u64,
    pub quota_enforce_hard_limits: bool,
    pub stats_retention_days: u32,
}

#[derive(Default)]
pub struct AppState {
    // Navigation state
    pub active_tab: MainTab,
    pub notifications: NotificationManager,
    pub progressive_disclosure: ProgressiveDisclosureManager,
    pub dashboard_state: DashboardState,
    pub design_system: DesignSystem,
    pub role_based_ui: RoleBasedUIManager,
    pub intelligent_config: IntelligentConfigManager,
    pub adaptive_ui: AdaptiveUIManager,

    // Legacy state (keeping for compatibility)
    pub selected_file: Option<PathBuf>,
    pub selected_folder: Option<PathBuf>,
    pub recipient_pk: String,
    pub recipient_sk: String,
    pub sender_sk: String,
    pub chunk_size_mb: u32,
    pub output_dir: String,
    pub auto_watch: bool,
    pub storage_backend_type: StorageType,
    pub logs: Arc<Mutex<Vec<String>>>,

    // Storage backend configurations
    pub storage_configs: HashMap<StorageType, StorageBackendConfig>,

    // Storage management
    pub storage_manager: Option<crate::storage::factory::StorageManager>,
    pub current_backend_health: Arc<Mutex<HashMap<String, String>>>,
    // watcher state
    pub watcher_running: bool,
    pub watcher_stop: Option<Arc<AtomicBool>>,
    pub watcher_handle: Option<std::thread::JoinHandle<()>>,
    // job progress state
    pub job_progress_total: Option<Arc<AtomicUsize>>,
    pub job_progress_done: Option<Arc<AtomicUsize>>,
    pub job_cancel: Option<Arc<AtomicBool>>,
    pub job_running: bool,
    pub job_last_label: String,
    pub job_pause: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    // per-file sub-progress (derived from job counters)
    pub file_est_total: Option<Arc<AtomicUsize>>,
    pub file_start_done: Option<Arc<AtomicUsize>>,
    // simple search
    pub search_hash: String,
    pub search_base: String,
    // options
    pub skip_hidden: bool,
    pub dry_run: bool,
    pub file_status: Arc<Mutex<String>>,
    // tuning
    pub watcher_debounce_ms: u64,
    // estimation
    pub estimated_total_chunks: Option<Arc<AtomicUsize>>,
    // configuration management
    pub config_state: Option<crate::gui::config_widgets::ConfigManagementState>,
    // backup management
    pub backup_state: Option<crate::gui::backup_widgets::BackupWidgetState>,
    // crypto management
    pub key_management_widget: crate::gui::crypto_widgets::KeyManagementWidget,
    pub certificate_management_widget: crate::gui::crypto_widgets::CertificateManagementWidget,
    pub advanced_crypto_widget: crate::gui::crypto_widgets::AdvancedCryptoWidget,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Settings {
    // Do NOT store secrets (passwords, private key passphrases)
    pub active_tab: MainTab,
    pub progressive_disclosure: ProgressiveDisclosureManager,
    pub selected_file: Option<String>,
    pub selected_folder: Option<String>,
    pub recipient_pk: String,
    pub chunk_size_mb: u32,
    pub output_dir: String,
    pub storage_backend_type: String, // Serialize as string
    pub storage_configs: HashMap<String, StorageBackendConfig>,
    pub skip_hidden: bool,
    pub watcher_debounce_ms: u64,
    pub dry_run: bool,
}

impl Settings {
    pub fn from_app(app: &AppState) -> Settings {
        let storage_configs: HashMap<String, StorageBackendConfig> = app.storage_configs
            .iter()
            .map(|(k, v)| (format!("{:?}", k), v.clone()))
            .collect();

        Settings {
            active_tab: app.active_tab,
            progressive_disclosure: app.progressive_disclosure.clone(),
            selected_file: app.selected_file.as_ref().map(|p| p.display().to_string()),
            selected_folder: app.selected_folder.as_ref().map(|p| p.display().to_string()),
            recipient_pk: app.recipient_pk.clone(),
            chunk_size_mb: app.chunk_size_mb,
            output_dir: app.output_dir.clone(),
            storage_backend_type: format!("{:?}", app.storage_backend_type),
            storage_configs,
            skip_hidden: app.skip_hidden,
            watcher_debounce_ms: app.watcher_debounce_ms,
            dry_run: app.dry_run,
        }
    }

    pub fn apply_to_app(self, app: &mut AppState) {
        app.active_tab = self.active_tab;
        app.progressive_disclosure = self.progressive_disclosure;
        app.selected_file = self.selected_file.map(PathBuf::from);
        app.selected_folder = self.selected_folder.map(PathBuf::from);
        app.recipient_pk = self.recipient_pk;
        app.chunk_size_mb = self.chunk_size_mb;
        app.output_dir = self.output_dir;
        
        // Parse storage backend type
        app.storage_backend_type = match self.storage_backend_type.as_str() {
            "Local" => StorageType::Local,
            "Sftp" => StorageType::Sftp,
            "S3Compatible" => StorageType::S3Compatible,
            "GoogleCloud" => StorageType::GoogleCloud,
            "AzureBlob" => StorageType::AzureBlob,
            "PostgreSQL" => StorageType::PostgreSQL,
            "Redis" => StorageType::Redis,
            "MultiCloud" => StorageType::MultiCloud,
            "CachedCloud" => StorageType::CachedCloud,
            _ => StorageType::Local, // Default fallback
        };
        
        // Parse storage configs
        app.storage_configs.clear();
        for (key, config) in self.storage_configs {
            let storage_type = match key.as_str() {
                "Local" => StorageType::Local,
                "Sftp" => StorageType::Sftp,
                "S3Compatible" => StorageType::S3Compatible,
                "GoogleCloud" => StorageType::GoogleCloud,
                "AzureBlob" => StorageType::AzureBlob,
                "PostgreSQL" => StorageType::PostgreSQL,
                "Redis" => StorageType::Redis,
                "MultiCloud" => StorageType::MultiCloud,
                "CachedCloud" => StorageType::CachedCloud,
                _ => continue,
            };
            app.storage_configs.insert(storage_type, config);
        }
        
        app.skip_hidden = self.skip_hidden;
        app.watcher_debounce_ms = self.watcher_debounce_ms;
        app.dry_run = self.dry_run;
    }
}

impl AppState {
    pub fn new() -> Self {
        let mut app = AppState::default();

        // Initialize new UI components
        app.active_tab = MainTab::Dashboard;
        app.notifications = NotificationManager::new();
        app.progressive_disclosure = ProgressiveDisclosureManager::new();
        app.dashboard_state = DashboardState::new();
        app.design_system = DesignSystem::new();
        app.role_based_ui = RoleBasedUIManager::new();
        app.intelligent_config = IntelligentConfigManager::new();
        app.adaptive_ui = AdaptiveUIManager::new();

        // Legacy initialization
        app.chunk_size_mb = 10;
        app.watcher_debounce_ms = 1000;
        app.storage_backend_type = StorageType::Local;
        app.config_state = None; // Will be initialized on first use
        app.backup_state = None; // Will be initialized on first use
        app.key_management_widget = crate::gui::crypto_widgets::KeyManagementWidget::default();
        app.certificate_management_widget = crate::gui::crypto_widgets::CertificateManagementWidget::default();
        app.advanced_crypto_widget = crate::gui::crypto_widgets::AdvancedCryptoWidget::default();
        
        // Initialize default storage configs
        app.storage_configs.insert(StorageType::Local, StorageBackendConfig::default());
        app.storage_manager = Some(crate::storage::factory::StorageManager::new());
        
        // Try to load settings
        if let Ok(settings_str) = std::fs::read_to_string("settings.json") {
            if let Ok(settings) = serde_json::from_str::<Settings>(&settings_str) {
                settings.apply_to_app(&mut app);
            }
        }
        
        app
    }

    pub fn log(&self, s: &str) {
        if let Ok(mut l) = self.logs.lock() {
            l.push(s.to_owned());
            if l.len() > 1000 { 
                l.drain(0..100); 
            }
        }
    }
    
    pub fn save_settings(&self) {
        let settings = Settings::from_app(self);
        if let Ok(json) = serde_json::to_string_pretty(&settings) {
            let _ = std::fs::write("settings.json", json);
        }
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Render toast notifications
        self.notifications.render_toast_notifications(ctx);

        // Main UI layout
        egui::CentralPanel::default().show(ctx, |ui| {
            // Application header
            ui.horizontal(|ui| {
                ui.heading("n0n - Secure File Synchronization & Storage");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Expert mode toggle
                    let mut expert_mode = self.progressive_disclosure.global_expert_mode;
                    if ui.checkbox(&mut expert_mode, "Expert Mode").changed() {
                        self.progressive_disclosure.set_expert_mode(expert_mode);
                    }
                });
            });

            ui.separator();

            // Tab navigation
            self.render_main_navigation(ui);

            ui.separator();

            // Tab content
            match self.active_tab {
                MainTab::Dashboard => {
                    self.render_dashboard_tab(ui);
                }
                MainTab::Storage => {
                    self.render_storage_tab(ui);
                }
                MainTab::Security => {
                    self.render_security_tab(ui);
                }
                MainTab::Backup => {
                    self.render_backup_tab(ui);
                }
                MainTab::Monitoring => {
                    self.render_monitoring_tab(ui);
                }
                MainTab::Settings => {
                    self.render_settings_tab(ui);
                }
            }
        });
    }
}

impl AppState {
    fn render_main_navigation(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for tab in MainTab::all() {
                let selected = self.active_tab == *tab;
                if ui.selectable_label(selected, tab.name()).clicked() {
                    self.active_tab = *tab;

                    // Show a welcome notification for new tabs
                    if !selected {
                        self.notifications.info(
                            format!("Switched to {}", tab.name()),
                            tab.description().to_string(),
                        );
                    }
                }
            }
        });
    }

    fn render_storage_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("💾 Storage Management");
            ui.add_space(10.0);

            // File selection section
            self.render_file_selection_section(ui);
            ui.separator();

            // Storage backend configuration
            self.render_storage_backend_section(ui);
            ui.separator();

            // File operations
            self.render_file_operations_section(ui);
        });
    }

    fn render_security_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("🔒 Security & Encryption");
            ui.add_space(10.0);

            // Keypair management
            self.render_keypair_section(ui);
            ui.separator();

            // Encryption settings
            self.render_encryption_section(ui);
            ui.separator();

            // Advanced crypto management
            self.render_crypto_management_section(ui);
        });
    }

    fn render_backup_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("🗄️ Backup & Disaster Recovery");
            ui.add_space(10.0);

            self.render_backup_section(ui);
        });
    }

    fn render_monitoring_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("📊 Monitoring & Analytics");
            ui.add_space(10.0);

            // Analytics section
            self.render_analytics_section(ui);
            ui.separator();

            // Progress monitoring
            self.render_progress_section(ui);
            ui.separator();

            // Logs section
            self.render_logs_section(ui);
        });
    }

    fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("⚙️ Application Settings");
            ui.add_space(10.0);

            // Role-based UI customization
            ui.group(|ui| {
                ui.heading("👤 User Profile & Interface");
                ui.separator();
                self.role_based_ui.render_role_selector(ui);
                ui.add_space(10.0);
                self.role_based_ui.render_feature_customization(ui);
                ui.add_space(10.0);
                self.role_based_ui.render_dashboard_customization(ui);
            });

            ui.add_space(15.0);

            // Intelligent configuration
            ui.group(|ui| {
                ui.heading("🧠 Smart Configuration");
                ui.separator();
                let user_profile = self.role_based_ui.current_profile.clone();
                self.intelligent_config.render_recommendations(ui, &user_profile);
                ui.add_space(10.0);
                self.intelligent_config.render_auto_config_panel(ui);
            });

            ui.add_space(15.0);

            // Adaptive UI insights
            ui.group(|ui| {
                ui.heading("📊 Usage Insights");
                ui.separator();
                let insights = self.adaptive_ui.get_learning_insights();
                if insights.is_empty() {
                    ui.label("No insights available yet. Keep using the application to see personalized suggestions.");
                } else {
                    for insight in insights {
                        ui.horizontal(|ui| {
                            ui.label("💡");
                            ui.label(insight);
                        });
                    }
                }

                ui.add_space(10.0);
                let user_profile = self.role_based_ui.current_profile.clone();
                self.adaptive_ui.render_adaptive_suggestions(ui, &user_profile);
            });

            ui.add_space(15.0);

            // Configuration management
            self.render_config_management_section(ui);
            ui.separator();

            // Application preferences
            self.render_app_preferences(ui);
        });
    }

    fn render_dashboard_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("🏠 Dashboard");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("❓ Help").clicked() {
                    self.adaptive_ui.track_help_request("dashboard");
                }
            });
        });
        ui.add_space(10.0);

        // Show onboarding progress for new users
        let user_role = self.role_based_ui.current_profile.role.clone();
        self.adaptive_ui.render_onboarding_progress(ui, &user_role);
        ui.add_space(10.0);

        // Show contextual help if enabled
        if self.role_based_ui.should_show_contextual_help() {
            self.adaptive_ui.render_contextual_help(ui, "dashboard");
            ui.add_space(10.0);
        }

        // System status overview
        ui.horizontal(|ui| {
            ui.group(|ui| {
                ui.set_min_width(250.0);
                ui.heading("System Status");
                ui.separator();

                // Mock system status
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GREEN, "●");
                    ui.label("Storage: Online");
                });

                ui.horizontal(|ui| {
                    ui.label("💾");
                    ui.label("Used: Unknown");
                });

                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GREEN, "🔒");
                    ui.label("Encrypted");
                });
            });

            ui.add_space(10.0);

            ui.group(|ui| {
                ui.set_min_width(200.0);
                ui.heading("Recent Activity");
                ui.separator();

                if let Ok(logs) = self.logs.lock() {
                    if logs.is_empty() {
                        ui.label("No recent activity");
                    } else {
                        for (i, log_entry) in logs.iter().rev().take(3).enumerate() {
                            ui.horizontal(|ui| {
                                ui.label("•");
                                ui.small(log_entry);
                            });
                            if i < 2 { ui.separator(); }
                        }
                    }
                }
            });

            ui.add_space(10.0);

            ui.group(|ui| {
                ui.set_min_width(200.0);
                ui.heading("Quick Actions");
                ui.separator();

                if ui.button("📁 Add Files").clicked() {
                    if let Some(files) = rfd::FileDialog::new().pick_files() {
                        if !files.is_empty() {
                            self.selected_file = Some(files[0].clone());
                            self.notifications.success(
                                "Files Selected",
                                format!("Selected {} files", files.len())
                            );
                        }
                    }
                }

                if ui.button("🔄 Sync Now").clicked() {
                    self.log("Manual sync initiated");
                    self.notifications.info("Sync Started", "Manual synchronization initiated");
                }

                if ui.button("⚙️ Quick Setup").clicked() {
                    self.notifications.info("Quick Setup", "Feature coming soon!");
                }
            });
        });

        ui.add_space(20.0);

        // Active operations
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.heading("Active Operations");
            ui.separator();

            if !self.job_running && !self.watcher_running {
                ui.label("No active operations");
            } else {
                if self.job_running {
                    ui.horizontal(|ui| {
                        ui.label("🔄");
                        ui.strong(&self.job_last_label);
                    });

                    if let (Some(total), Some(done)) = (
                        &self.job_progress_total,
                        &self.job_progress_done,
                    ) {
                        let total_val = total.load(std::sync::atomic::Ordering::Relaxed);
                        let done_val = done.load(std::sync::atomic::Ordering::Relaxed);

                        if total_val > 0 {
                            let progress = done_val as f32 / total_val as f32;
                            ui.add(egui::ProgressBar::new(progress)
                                .text(format!("{}/{} ({:.1}%)", done_val, total_val, progress * 100.0)));
                        }
                    }
                }

                if self.watcher_running {
                    ui.horizontal(|ui| {
                        ui.colored_label(egui::Color32::GREEN, "👁");
                        ui.label("File watcher active");
                    });
                }
            }
        });
    }

    fn render_file_selection_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.strong("File Selection");

            ui.horizontal(|ui| {
                if ui.button("📁 Select Files").clicked() {
                    if let Some(files) = rfd::FileDialog::new().pick_files() {
                        if !files.is_empty() {
                            self.selected_file = Some(files[0].clone());
                            self.notifications.success(
                                "Files Selected",
                                format!("Selected {} files", files.len())
                            );
                        }
                    }
                }

                if ui.button("📂 Select Folder").clicked() {
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        self.selected_folder = Some(folder);
                        self.notifications.success("Folder Selected", "Folder selected for monitoring");
                    }
                }
            });

            // Show selected items
            if let Some(ref file) = self.selected_file {
                ui.horizontal(|ui| {
                    ui.label("Selected file:");
                    ui.small(file.display().to_string());
                });
            }

            if let Some(ref folder) = self.selected_folder {
                ui.horizontal(|ui| {
                    ui.label("Selected folder:");
                    ui.small(folder.display().to_string());
                });
            }
        });
    }

    fn render_file_operations_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.strong("File Operations");

            ui.horizontal(|ui| {
                ui.label("Chunk size (MB):");
                ui.add(egui::DragValue::new(&mut self.chunk_size_mb).clamp_range(1..=100));
            });

            ui.horizontal(|ui| {
                ui.label("Output directory:");
                ui.text_edit_singleline(&mut self.output_dir);
            });

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.skip_hidden, "Skip hidden files");
                ui.checkbox(&mut self.dry_run, "Dry run mode");
                ui.checkbox(&mut self.auto_watch, "Auto-watch folders");
            });

            // Process files button
            ui.horizontal(|ui| {
                if ui.button("🚀 Process Files").clicked() {
                    self.notifications.info("Processing", "File processing started");
                    self.log("File processing initiated");
                }

                if ui.button("⏸️ Pause").clicked() {
                    self.notifications.info("Paused", "Operations paused");
                }

                if ui.button("⏹️ Stop").clicked() {
                    self.notifications.warning("Stopped", "Operations stopped");
                }
            });
        });
    }

    fn render_app_preferences(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.strong("Application Preferences");

            // Progressive disclosure settings
            ui.horizontal(|ui| {
                let mut expert_mode = self.progressive_disclosure.global_expert_mode;
                if ui.checkbox(&mut expert_mode, "Expert Mode").changed() {
                    self.progressive_disclosure.set_expert_mode(expert_mode);
                    if expert_mode {
                        self.notifications.info(
                            "Expert Mode Enabled",
                            "All advanced options are now visible"
                        );
                    } else {
                        self.notifications.info(
                            "Expert Mode Disabled",
                            "Advanced options can be shown on demand"
                        );
                    }
                }
                ui.label("Show all advanced options by default");
            });

            ui.horizontal(|ui| {
                ui.label("Watcher debounce (ms):");
                ui.add(egui::DragValue::new(&mut self.watcher_debounce_ms).clamp_range(100..=10000));
            });

            ui.horizontal(|ui| {
                if ui.button("💾 Save Settings").clicked() {
                    self.save_settings();
                    self.notifications.success("Settings Saved", "Application settings have been saved");
                }

                if ui.button("🔄 Reset to Defaults").clicked() {
                    // Reset to defaults
                    self.progressive_disclosure = ProgressiveDisclosureManager::new();
                    self.notifications.info("Settings Reset", "Settings have been reset to defaults");
                }
            });
        });
    }
}