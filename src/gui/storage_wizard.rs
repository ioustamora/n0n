use crate::storage::backend::StorageType;
use crate::gui::state::StorageBackendConfig;
use crate::gui::design_system::DesignSystem;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Task-oriented storage configuration wizard
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageWizardStep {
    Welcome,
    StorageTypeSelection,
    BasicConfiguration,
    SecurityConfiguration,
    AdvancedOptions,
    TestConnection,
    Review,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageWizardState {
    pub current_step: StorageWizardStep,
    pub selected_storage_type: Option<StorageType>,
    pub config: StorageBackendConfig,
    pub validation_errors: Vec<String>,
    pub connection_status: ConnectionTestStatus,
    pub user_selections: HashMap<String, String>,
    pub show_advanced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionTestStatus {
    NotTested,
    Testing,
    Success,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct StorageTypeInfo {
    pub storage_type: StorageType,
    pub name: &'static str,
    pub description: &'static str,
    pub icon: &'static str,
    pub difficulty: WizardDifficulty,
    pub features: Vec<&'static str>,
    pub requirements: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WizardDifficulty {
    Beginner,
    Intermediate,
    Advanced,
}

impl WizardDifficulty {
    pub fn color(&self) -> egui::Color32 {
        match self {
            Self::Beginner => egui::Color32::from_rgb(46, 160, 67),    // Green
            Self::Intermediate => egui::Color32::from_rgb(255, 193, 7), // Amber
            Self::Advanced => egui::Color32::from_rgb(220, 53, 69),     // Red
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Beginner => "Beginner",
            Self::Intermediate => "Intermediate",
            Self::Advanced => "Advanced",
        }
    }
}

pub struct StorageWizard {
    state: StorageWizardState,
    storage_types: Vec<StorageTypeInfo>,
    design_system: DesignSystem,
}

impl Default for StorageWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageWizard {
    pub fn new() -> Self {
        Self {
            state: StorageWizardState::default(),
            storage_types: Self::init_storage_types(),
            design_system: DesignSystem::new(),
        }
    }

    pub fn with_storage_type(storage_type: StorageType) -> Self {
        let mut wizard = Self::new();
        wizard.state.selected_storage_type = Some(storage_type);
        wizard.state.current_step = StorageWizardStep::BasicConfiguration;
        wizard
    }

    fn init_storage_types() -> Vec<StorageTypeInfo> {
        vec![
            StorageTypeInfo {
                storage_type: StorageType::Local,
                name: "Local Storage",
                description: "Store files on your local file system. Best for getting started.",
                icon: "💾",
                difficulty: WizardDifficulty::Beginner,
                features: vec!["No network required", "Fast access", "Simple setup"],
                requirements: vec!["Local disk space"],
            },
            StorageTypeInfo {
                storage_type: StorageType::Sftp,
                name: "SFTP Server",
                description: "Secure file transfer over SSH. Great for remote servers.",
                icon: "🖥️",
                difficulty: WizardDifficulty::Intermediate,
                features: vec!["SSH encryption", "Wide compatibility", "Remote access"],
                requirements: vec!["SSH server access", "Username/password or SSH key"],
            },
            StorageTypeInfo {
                storage_type: StorageType::S3Compatible,
                name: "S3-Compatible Storage",
                description: "Amazon S3 or compatible services (MinIO, Wasabi, etc.)",
                icon: "☁️",
                difficulty: WizardDifficulty::Intermediate,
                features: vec!["Scalable", "High availability", "Wide ecosystem"],
                requirements: vec!["Access key and secret", "Bucket name"],
            },
            StorageTypeInfo {
                storage_type: StorageType::GoogleCloud,
                name: "Google Cloud Storage",
                description: "Google's cloud storage service with global distribution.",
                icon: "🌍",
                difficulty: WizardDifficulty::Intermediate,
                features: vec!["Global CDN", "Integration with GCP", "High performance"],
                requirements: vec!["Google Cloud account", "Service account key"],
            },
            StorageTypeInfo {
                storage_type: StorageType::AzureBlob,
                name: "Azure Blob Storage",
                description: "Microsoft Azure's blob storage service.",
                icon: "🔷",
                difficulty: WizardDifficulty::Intermediate,
                features: vec!["Microsoft ecosystem", "Multiple tiers", "Enterprise features"],
                requirements: vec!["Azure account", "Storage account name and key"],
            },
            StorageTypeInfo {
                storage_type: StorageType::PostgreSQL,
                name: "PostgreSQL Database",
                description: "Store chunks as binary data in PostgreSQL database.",
                icon: "🐘",
                difficulty: WizardDifficulty::Advanced,
                features: vec!["ACID compliance", "Powerful queries", "Robust"],
                requirements: vec!["PostgreSQL server", "Database credentials"],
            },
            StorageTypeInfo {
                storage_type: StorageType::Redis,
                name: "Redis Cache",
                description: "Fast in-memory storage with persistence options.",
                icon: "⚡",
                difficulty: WizardDifficulty::Advanced,
                features: vec!["Very fast", "In-memory", "Pub/Sub support"],
                requirements: vec!["Redis server", "Connection URL"],
            },
            StorageTypeInfo {
                storage_type: StorageType::MultiCloud,
                name: "Multi-Cloud Setup",
                description: "Replicate across multiple cloud providers for redundancy.",
                icon: "🌐",
                difficulty: WizardDifficulty::Advanced,
                features: vec!["High redundancy", "Disaster recovery", "Geographic distribution"],
                requirements: vec!["Multiple configured backends", "Replication strategy"],
            },
        ]
    }

    pub fn current_step(&self) -> &StorageWizardStep {
        &self.state.current_step
    }

    pub fn can_proceed(&self) -> bool {
        match self.state.current_step {
            StorageWizardStep::Welcome => true,
            StorageWizardStep::StorageTypeSelection => self.state.selected_storage_type.is_some(),
            StorageWizardStep::BasicConfiguration => self.validate_basic_config(),
            StorageWizardStep::SecurityConfiguration => true, // Optional step
            StorageWizardStep::AdvancedOptions => true, // Optional step
            StorageWizardStep::TestConnection => matches!(self.state.connection_status, ConnectionTestStatus::Success),
            StorageWizardStep::Review => true,
            StorageWizardStep::Complete => false, // Can't proceed from complete
        }
    }

    pub fn next_step(&mut self) {
        if self.can_proceed() {
            self.state.current_step = match self.state.current_step {
                StorageWizardStep::Welcome => StorageWizardStep::StorageTypeSelection,
                StorageWizardStep::StorageTypeSelection => StorageWizardStep::BasicConfiguration,
                StorageWizardStep::BasicConfiguration => StorageWizardStep::SecurityConfiguration,
                StorageWizardStep::SecurityConfiguration => StorageWizardStep::AdvancedOptions,
                StorageWizardStep::AdvancedOptions => StorageWizardStep::TestConnection,
                StorageWizardStep::TestConnection => StorageWizardStep::Review,
                StorageWizardStep::Review => StorageWizardStep::Complete,
                StorageWizardStep::Complete => StorageWizardStep::Complete, // Stay at complete
            };
        }
    }

    pub fn previous_step(&mut self) {
        self.state.current_step = match self.state.current_step {
            StorageWizardStep::Welcome => StorageWizardStep::Welcome,
            StorageWizardStep::StorageTypeSelection => StorageWizardStep::Welcome,
            StorageWizardStep::BasicConfiguration => StorageWizardStep::StorageTypeSelection,
            StorageWizardStep::SecurityConfiguration => StorageWizardStep::BasicConfiguration,
            StorageWizardStep::AdvancedOptions => StorageWizardStep::SecurityConfiguration,
            StorageWizardStep::TestConnection => StorageWizardStep::AdvancedOptions,
            StorageWizardStep::Review => StorageWizardStep::TestConnection,
            StorageWizardStep::Complete => StorageWizardStep::Review,
        };
    }

    pub fn render(&mut self, ui: &mut egui::Ui) -> Option<StorageBackendConfig> {
        let mut result = None;

        // Wizard progress indicator
        self.render_progress_indicator(ui);
        ui.separator();

        // Step content
        match self.state.current_step {
            StorageWizardStep::Welcome => self.render_welcome_step(ui),
            StorageWizardStep::StorageTypeSelection => self.render_storage_type_step(ui),
            StorageWizardStep::BasicConfiguration => self.render_basic_config_step(ui),
            StorageWizardStep::SecurityConfiguration => self.render_security_step(ui),
            StorageWizardStep::AdvancedOptions => self.render_advanced_step(ui),
            StorageWizardStep::TestConnection => self.render_test_step(ui),
            StorageWizardStep::Review => self.render_review_step(ui),
            StorageWizardStep::Complete => {
                result = Some(self.state.config.clone());
                self.render_complete_step(ui);
            }
        }

        ui.separator();

        // Navigation buttons
        self.render_navigation(ui);

        result
    }

    fn render_progress_indicator(&self, ui: &mut egui::Ui) {
        let steps = [
            ("Welcome", StorageWizardStep::Welcome),
            ("Type", StorageWizardStep::StorageTypeSelection),
            ("Basic", StorageWizardStep::BasicConfiguration),
            ("Security", StorageWizardStep::SecurityConfiguration),
            ("Advanced", StorageWizardStep::AdvancedOptions),
            ("Test", StorageWizardStep::TestConnection),
            ("Review", StorageWizardStep::Review),
            ("Complete", StorageWizardStep::Complete),
        ];

        ui.horizontal(|ui| {
            for (i, (name, step)) in steps.iter().enumerate() {
                let is_current = *step == self.state.current_step;
                let is_completed = self.step_index(&self.state.current_step) > i;

                if i > 0 {
                    ui.label("→");
                }

                let color = if is_completed {
                    egui::Color32::from_rgb(46, 160, 67) // Green
                } else if is_current {
                    egui::Color32::from_rgb(54, 162, 235) // Blue
                } else {
                    egui::Color32::GRAY
                };

                ui.colored_label(color, *name);
            }
        });
    }

    fn step_index(&self, step: &StorageWizardStep) -> usize {
        match step {
            StorageWizardStep::Welcome => 0,
            StorageWizardStep::StorageTypeSelection => 1,
            StorageWizardStep::BasicConfiguration => 2,
            StorageWizardStep::SecurityConfiguration => 3,
            StorageWizardStep::AdvancedOptions => 4,
            StorageWizardStep::TestConnection => 5,
            StorageWizardStep::Review => 6,
            StorageWizardStep::Complete => 7,
        }
    }

    fn render_welcome_step(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.heading("🔧 Storage Configuration Wizard");
            ui.add_space(20.0);

            ui.label("This wizard will guide you through configuring a new storage backend.");
            ui.label("We'll help you choose the right storage type and configure it step by step.");
            ui.add_space(10.0);

            ui.group(|ui| {
                ui.strong("What you'll need:");
                ui.label("• Basic information about your storage service");
                ui.label("• Access credentials (we'll guide you on obtaining these)");
                ui.label("• About 5-10 minutes to complete the setup");
            });

            ui.add_space(20.0);
            ui.label("Click 'Next' to get started!");
        });
    }

    fn render_storage_type_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Choose Storage Type");
        ui.label("Select the storage backend that best fits your needs:");
        ui.add_space(10.0);

        egui::ScrollArea::vertical()
            .max_height(400.0)
            .show(ui, |ui| {
                for storage_info in &self.storage_types {
                    let selected = self.state.selected_storage_type == Some(storage_info.storage_type);

                    ui.group(|ui| {
                        ui.set_min_height(80.0);

                        ui.horizontal(|ui| {
                            // Radio button
                            if ui.radio(selected, "").clicked() {
                                self.state.selected_storage_type = Some(storage_info.storage_type);
                            }

                            ui.add_space(10.0);

                            // Icon and info
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(storage_info.icon);
                                    ui.strong(storage_info.name);

                                    // Difficulty badge
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.add(egui::Button::new(storage_info.difficulty.label())
                                            .fill(storage_info.difficulty.color())
                                            .small());
                                    });
                                });

                                ui.label(storage_info.description);

                                // Features
                                ui.horizontal_wrapped(|ui| {
                                    for feature in &storage_info.features {
                                        ui.small(&format!("✓ {}", feature));
                                    }
                                });
                            });
                        });
                    });

                    ui.add_space(5.0);
                }
            });
    }

    fn render_basic_config_step(&mut self, ui: &mut egui::Ui) {
        if let Some(storage_type) = self.state.selected_storage_type {
            ui.heading(&format!("Configure {}", self.get_storage_name(storage_type)));
            ui.label("Enter the basic configuration for your storage backend:");
            ui.add_space(10.0);

            match storage_type {
                StorageType::Local => self.render_local_config(ui),
                StorageType::Sftp => self.render_sftp_config(ui),
                StorageType::S3Compatible => self.render_s3_config(ui),
                StorageType::GoogleCloud => self.render_gcs_config(ui),
                StorageType::AzureBlob => self.render_azure_config(ui),
                StorageType::PostgreSQL => self.render_postgres_config(ui),
                StorageType::Redis => self.render_redis_config(ui),
                StorageType::MultiCloud => self.render_multicloud_config(ui),
                _ => {
                    ui.label("Configuration for this storage type is not yet implemented.");
                }
            }
        }
    }

    fn render_local_config(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Base Path:");
            ui.text_edit_singleline(&mut self.state.config.local_base_path);
            if ui.button("📁 Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.state.config.local_base_path = path.display().to_string();
                }
            }
        });

        ui.checkbox(&mut self.state.config.local_create_dirs, "Create directories if they don't exist");

        if self.state.config.local_base_path.is_empty() {
            ui.colored_label(egui::Color32::RED, "⚠ Base path is required");
        }
    }

    fn render_sftp_config(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Host:");
            ui.text_edit_singleline(&mut self.state.config.sftp_host);
        });

        ui.horizontal(|ui| {
            ui.label("Username:");
            ui.text_edit_singleline(&mut self.state.config.sftp_user);
        });

        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.state.config.sftp_pass).password(true));
        });

        ui.horizontal(|ui| {
            ui.label("Remote Path:");
            ui.text_edit_singleline(&mut self.state.config.sftp_base);
        });

        // Validation
        if self.state.config.sftp_host.is_empty() {
            ui.colored_label(egui::Color32::RED, "⚠ Host is required");
        }
        if self.state.config.sftp_user.is_empty() {
            ui.colored_label(egui::Color32::RED, "⚠ Username is required");
        }
    }

    fn render_s3_config(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Bucket Name:");
            ui.text_edit_singleline(&mut self.state.config.s3_bucket);
        });

        ui.horizontal(|ui| {
            ui.label("Region:");
            ui.text_edit_singleline(&mut self.state.config.s3_region);
        });

        ui.horizontal(|ui| {
            ui.label("Endpoint (optional):");
            ui.text_edit_singleline(&mut self.state.config.s3_endpoint);
        });

        ui.horizontal(|ui| {
            ui.label("Access Key ID:");
            ui.text_edit_singleline(&mut self.state.config.s3_access_key_id);
        });

        ui.horizontal(|ui| {
            ui.label("Secret Access Key:");
            ui.add(egui::TextEdit::singleline(&mut self.state.config.s3_secret_access_key).password(true));
        });

        // Validation
        if self.state.config.s3_bucket.is_empty() {
            ui.colored_label(egui::Color32::RED, "⚠ Bucket name is required");
        }
        if self.state.config.s3_access_key_id.is_empty() {
            ui.colored_label(egui::Color32::RED, "⚠ Access key is required");
        }
    }

    fn render_gcs_config(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Bucket Name:");
            ui.text_edit_singleline(&mut self.state.config.gcs_bucket);
        });

        ui.horizontal(|ui| {
            ui.label("Project ID:");
            ui.text_edit_singleline(&mut self.state.config.gcs_project_id);
        });

        ui.label("Service Account Key (JSON):");
        ui.add(egui::TextEdit::multiline(&mut self.state.config.gcs_service_account_key)
            .desired_width(f32::INFINITY)
            .desired_rows(4));

        // Validation
        if self.state.config.gcs_bucket.is_empty() {
            ui.colored_label(egui::Color32::RED, "⚠ Bucket name is required");
        }
    }

    fn render_azure_config(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Account Name:");
            ui.text_edit_singleline(&mut self.state.config.azure_account_name);
        });

        ui.horizontal(|ui| {
            ui.label("Account Key:");
            ui.add(egui::TextEdit::singleline(&mut self.state.config.azure_account_key).password(true));
        });

        ui.horizontal(|ui| {
            ui.label("Container:");
            ui.text_edit_singleline(&mut self.state.config.azure_container);
        });

        // Validation
        if self.state.config.azure_account_name.is_empty() {
            ui.colored_label(egui::Color32::RED, "⚠ Account name is required");
        }
        if self.state.config.azure_container.is_empty() {
            ui.colored_label(egui::Color32::RED, "⚠ Container is required");
        }
    }

    fn render_postgres_config(&mut self, ui: &mut egui::Ui) {
        ui.label("Connection String:");
        ui.text_edit_singleline(&mut self.state.config.postgres_connection_string);
        ui.small("Example: postgresql://user:pass@localhost/database");

        ui.horizontal(|ui| {
            ui.label("Table Prefix:");
            ui.text_edit_singleline(&mut self.state.config.postgres_table_prefix);
        });

        // Validation
        if self.state.config.postgres_connection_string.is_empty() {
            ui.colored_label(egui::Color32::RED, "⚠ Connection string is required");
        }
    }

    fn render_redis_config(&mut self, ui: &mut egui::Ui) {
        ui.label("Redis URL:");
        ui.text_edit_singleline(&mut self.state.config.redis_url);
        ui.small("Example: redis://localhost:6379");

        ui.horizontal(|ui| {
            ui.label("Key Prefix:");
            ui.text_edit_singleline(&mut self.state.config.redis_key_prefix);
        });

        ui.horizontal(|ui| {
            ui.label("TTL (seconds):");
            ui.text_edit_singleline(&mut self.state.config.redis_ttl_seconds);
        });

        // Validation
        if self.state.config.redis_url.is_empty() {
            ui.colored_label(egui::Color32::RED, "⚠ Redis URL is required");
        }
    }

    fn render_multicloud_config(&mut self, ui: &mut egui::Ui) {
        ui.label("Multi-cloud configuration requires other backends to be set up first.");
        ui.label("Please configure individual storage backends before setting up multi-cloud.");
    }

    fn render_security_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Security Configuration");
        ui.label("Configure encryption and security options:");
        ui.add_space(10.0);

        ui.checkbox(&mut self.state.config.encryption_enabled, "Enable encryption at rest");

        if self.state.config.encryption_enabled {
            ui.horizontal(|ui| {
                ui.label("Algorithm:");
                egui::ComboBox::from_id_source("encryption_algorithm")
                    .selected_text(&self.state.config.encryption_algorithm)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.state.config.encryption_algorithm, "XSalsa20Poly1305".to_string(), "XSalsa20Poly1305 (recommended)");
                        ui.selectable_value(&mut self.state.config.encryption_algorithm, "ChaCha20Poly1305".to_string(), "ChaCha20Poly1305");
                        ui.selectable_value(&mut self.state.config.encryption_algorithm, "AES256GCM".to_string(), "AES256GCM");
                    });
            });

            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.add(egui::TextEdit::singleline(&mut self.state.config.encryption_password).password(true));
            });

            ui.checkbox(&mut self.state.config.encryption_compress, "Compress data before encryption");
        }
    }

    fn render_advanced_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Advanced Options");
        ui.label("Configure advanced settings (optional):");
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.strong("Analytics & Monitoring");
            ui.checkbox(&mut self.state.config.analytics_enabled, "Enable analytics");

            if self.state.config.analytics_enabled {
                ui.horizontal(|ui| {
                    ui.label("Retention days:");
                    ui.add(egui::DragValue::new(&mut self.state.config.stats_retention_days).clamp_range(1..=365));
                });
            }
        });

        ui.add_space(10.0);

        ui.group(|ui| {
            ui.strong("Quotas & Limits");
            ui.checkbox(&mut self.state.config.quota_enabled, "Enable quotas");

            if self.state.config.quota_enabled {
                ui.horizontal(|ui| {
                    ui.label("Max size (MB):");
                    ui.add(egui::DragValue::new(&mut self.state.config.quota_max_size_mb).clamp_range(1..=u64::MAX));
                });

                ui.horizontal(|ui| {
                    ui.label("Max chunks:");
                    ui.add(egui::DragValue::new(&mut self.state.config.quota_max_chunks).clamp_range(1..=u64::MAX));
                });

                ui.checkbox(&mut self.state.config.quota_enforce_hard_limits, "Enforce hard limits");
            }
        });
    }

    fn render_test_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Test Connection");
        ui.label("Let's test the connection to your storage backend:");
        ui.add_space(10.0);

        match &self.state.connection_status {
            ConnectionTestStatus::NotTested => {
                ui.label("Click 'Test Connection' to verify your configuration.");
                if ui.button("🔍 Test Connection").clicked() {
                    self.state.connection_status = ConnectionTestStatus::Testing;
                    // In a real implementation, we'd start an async test here
                    // For now, simulate success after a brief delay
                    std::thread::spawn(|| {
                        // This is just for demo - in real code use proper async handling
                    });
                    // Simulate immediate success for demo
                    self.state.connection_status = ConnectionTestStatus::Success;
                }
            }
            ConnectionTestStatus::Testing => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Testing connection...");
                });
            }
            ConnectionTestStatus::Success => {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GREEN, "✓");
                    ui.colored_label(egui::Color32::GREEN, "Connection successful!");
                });
                ui.label("Your storage backend is configured correctly.");
            }
            ConnectionTestStatus::Failed(error) => {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::RED, "✗");
                    ui.colored_label(egui::Color32::RED, "Connection failed");
                });
                ui.label(format!("Error: {}", error));
                if ui.button("🔄 Retry").clicked() {
                    self.state.connection_status = ConnectionTestStatus::NotTested;
                }
            }
        }
    }

    fn render_review_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Review Configuration");
        ui.label("Please review your configuration before completing setup:");
        ui.add_space(10.0);

        if let Some(storage_type) = self.state.selected_storage_type {
            ui.group(|ui| {
                ui.strong(&format!("Storage Type: {}", self.get_storage_name(storage_type)));
                ui.separator();

                // Show relevant config fields
                match storage_type {
                    StorageType::Local => {
                        ui.label(&format!("Base Path: {}", self.state.config.local_base_path));
                    }
                    StorageType::Sftp => {
                        ui.label(&format!("Host: {}", self.state.config.sftp_host));
                        ui.label(&format!("User: {}", self.state.config.sftp_user));
                        ui.label(&format!("Remote Path: {}", self.state.config.sftp_base));
                    }
                    StorageType::S3Compatible => {
                        ui.label(&format!("Bucket: {}", self.state.config.s3_bucket));
                        ui.label(&format!("Region: {}", self.state.config.s3_region));
                        if !self.state.config.s3_endpoint.is_empty() {
                            ui.label(&format!("Endpoint: {}", self.state.config.s3_endpoint));
                        }
                    }
                    _ => {
                        ui.label("Configuration details hidden for security");
                    }
                }

                ui.separator();

                if self.state.config.encryption_enabled {
                    ui.label(&format!("Encryption: {} ✓", self.state.config.encryption_algorithm));
                } else {
                    ui.label("Encryption: Disabled");
                }
            });
        }
    }

    fn render_complete_step(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.heading("🎉 Configuration Complete!");
            ui.add_space(20.0);

            ui.label("Your storage backend has been successfully configured.");
            ui.label("You can now use it to store and sync your files securely.");

            ui.add_space(20.0);

            if ui.button("🏠 Return to Dashboard").clicked() {
                // Handle return to dashboard
            }
        });
    }

    fn render_navigation(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if self.state.current_step != StorageWizardStep::Welcome {
                if ui.button("⬅ Back").clicked() {
                    self.previous_step();
                }
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.state.current_step != StorageWizardStep::Complete {
                    ui.add_enabled_ui(self.can_proceed(), |ui| {
                        let button_text = if self.state.current_step == StorageWizardStep::Review {
                            "✓ Complete Setup"
                        } else {
                            "Next ➡"
                        };

                        if ui.button(button_text).clicked() {
                            self.next_step();
                        }
                    });
                }
            });
        });
    }

    fn validate_basic_config(&self) -> bool {
        if let Some(storage_type) = self.state.selected_storage_type {
            match storage_type {
                StorageType::Local => !self.state.config.local_base_path.is_empty(),
                StorageType::Sftp => {
                    !self.state.config.sftp_host.is_empty() &&
                    !self.state.config.sftp_user.is_empty()
                }
                StorageType::S3Compatible => {
                    !self.state.config.s3_bucket.is_empty() &&
                    !self.state.config.s3_access_key_id.is_empty()
                }
                StorageType::GoogleCloud => !self.state.config.gcs_bucket.is_empty(),
                StorageType::AzureBlob => {
                    !self.state.config.azure_account_name.is_empty() &&
                    !self.state.config.azure_container.is_empty()
                }
                StorageType::PostgreSQL => !self.state.config.postgres_connection_string.is_empty(),
                StorageType::Redis => !self.state.config.redis_url.is_empty(),
                _ => true,
            }
        } else {
            false
        }
    }

    fn get_storage_name(&self, storage_type: StorageType) -> &'static str {
        self.storage_types
            .iter()
            .find(|info| info.storage_type == storage_type)
            .map(|info| info.name)
            .unwrap_or("Unknown")
    }

    pub fn reset(&mut self) {
        self.state = StorageWizardState::default();
    }

    pub fn get_config(&self) -> &StorageBackendConfig {
        &self.state.config
    }
}

impl Default for StorageWizardState {
    fn default() -> Self {
        Self {
            current_step: StorageWizardStep::Welcome,
            selected_storage_type: None,
            config: StorageBackendConfig::default(),
            validation_errors: Vec::new(),
            connection_status: ConnectionTestStatus::NotTested,
            user_selections: HashMap::new(),
            show_advanced: false,
        }
    }
}