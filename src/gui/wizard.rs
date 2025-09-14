use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::storage::backend::StorageType;
use crate::gui::design_system::{DesignSystem, ComponentLibrary};
use crate::gui::notifications::NotificationManager;

/// Multi-step wizard system for guiding users through complex setup processes
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WizardStep {
    Welcome,
    SecuritySetup,
    StorageSelection,
    StorageConfiguration,
    InitialSync,
    Complete,
}

impl WizardStep {
    pub fn title(&self) -> &'static str {
        match self {
            Self::Welcome => "Welcome to n0n",
            Self::SecuritySetup => "Security Configuration",
            Self::StorageSelection => "Storage Backend Selection",
            Self::StorageConfiguration => "Storage Configuration",
            Self::InitialSync => "Initial Synchronization",
            Self::Complete => "Setup Complete",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Welcome => "Let's get you started with secure file synchronization",
            Self::SecuritySetup => "Configure encryption and security settings",
            Self::StorageSelection => "Choose where to store your files",
            Self::StorageConfiguration => "Configure your chosen storage backend",
            Self::InitialSync => "Test your configuration with sample files",
            Self::Complete => "Your n0n setup is complete and ready to use",
        }
    }

    pub fn next(&self) -> Option<WizardStep> {
        match self {
            Self::Welcome => Some(Self::SecuritySetup),
            Self::SecuritySetup => Some(Self::StorageSelection),
            Self::StorageSelection => Some(Self::StorageConfiguration),
            Self::StorageConfiguration => Some(Self::InitialSync),
            Self::InitialSync => Some(Self::Complete),
            Self::Complete => None,
        }
    }

    pub fn previous(&self) -> Option<WizardStep> {
        match self {
            Self::Welcome => None,
            Self::SecuritySetup => Some(Self::Welcome),
            Self::StorageSelection => Some(Self::SecuritySetup),
            Self::StorageConfiguration => Some(Self::StorageSelection),
            Self::InitialSync => Some(Self::StorageConfiguration),
            Self::Complete => Some(Self::InitialSync),
        }
    }

    pub fn all_steps() -> Vec<WizardStep> {
        vec![
            Self::Welcome,
            Self::SecuritySetup,
            Self::StorageSelection,
            Self::StorageConfiguration,
            Self::InitialSync,
            Self::Complete,
        ]
    }

    pub fn step_index(&self) -> usize {
        match self {
            Self::Welcome => 0,
            Self::SecuritySetup => 1,
            Self::StorageSelection => 2,
            Self::StorageConfiguration => 3,
            Self::InitialSync => 4,
            Self::Complete => 5,
        }
    }

    pub fn total_steps() -> usize {
        6
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardData {
    // Security settings
    pub generate_new_keys: bool,
    pub encryption_algorithm: String,
    pub key_derivation_function: String,
    pub import_existing_keys: bool,
    pub recipient_public_key: String,
    pub sender_private_key: String,

    // Storage settings
    pub selected_storage_type: Option<StorageType>,
    pub storage_config: HashMap<String, String>,

    // Initial sync settings
    pub test_with_sample_files: bool,
    pub selected_test_files: Vec<std::path::PathBuf>,
    pub output_directory: String,
}

impl Default for WizardData {
    fn default() -> Self {
        Self {
            generate_new_keys: true,
            encryption_algorithm: "ChaCha20Poly1305".to_string(),
            key_derivation_function: "Argon2".to_string(),
            import_existing_keys: false,
            recipient_public_key: String::new(),
            sender_private_key: String::new(),
            selected_storage_type: None,
            storage_config: HashMap::new(),
            test_with_sample_files: true,
            selected_test_files: Vec::new(),
            output_directory: "output".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct SetupWizard {
    pub current_step: WizardStep,
    pub data: WizardData,
    pub is_active: bool,
    pub completed_steps: Vec<WizardStep>,
    pub validation_errors: HashMap<WizardStep, String>,
}

impl Default for SetupWizard {
    fn default() -> Self {
        Self {
            current_step: WizardStep::Welcome,
            data: WizardData::default(),
            is_active: false,
            completed_steps: Vec::new(),
            validation_errors: HashMap::new(),
        }
    }
}

impl SetupWizard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self) {
        self.is_active = true;
        self.current_step = WizardStep::Welcome;
        self.completed_steps.clear();
        self.validation_errors.clear();
    }

    pub fn finish(&mut self) {
        self.is_active = false;
        self.current_step = WizardStep::Complete;
    }

    pub fn cancel(&mut self) {
        self.is_active = false;
        self.current_step = WizardStep::Welcome;
        self.data = WizardData::default();
        self.completed_steps.clear();
        self.validation_errors.clear();
    }

    pub fn can_go_next(&self) -> bool {
        self.current_step.next().is_some() && self.is_step_valid(&self.current_step)
    }

    pub fn can_go_previous(&self) -> bool {
        self.current_step.previous().is_some()
    }

    pub fn go_next(&mut self) -> bool {
        if self.can_go_next() {
            if !self.completed_steps.contains(&self.current_step) {
                self.completed_steps.push(self.current_step.clone());
            }
            self.current_step = self.current_step.next().unwrap();
            true
        } else {
            false
        }
    }

    pub fn go_previous(&mut self) -> bool {
        if self.can_go_previous() {
            self.current_step = self.current_step.previous().unwrap();
            true
        } else {
            false
        }
    }

    pub fn go_to_step(&mut self, step: WizardStep) {
        self.current_step = step;
    }

    pub fn is_step_completed(&self, step: &WizardStep) -> bool {
        self.completed_steps.contains(step)
    }

    pub fn is_step_valid(&self, step: &WizardStep) -> bool {
        match step {
            WizardStep::Welcome => true,
            WizardStep::SecuritySetup => {
                if self.data.generate_new_keys {
                    !self.data.encryption_algorithm.is_empty()
                } else {
                    !self.data.recipient_public_key.trim().is_empty() &&
                    !self.data.sender_private_key.trim().is_empty()
                }
            }
            WizardStep::StorageSelection => self.data.selected_storage_type.is_some(),
            WizardStep::StorageConfiguration => {
                // Basic validation - at least one config value should be provided
                !self.data.storage_config.is_empty()
            }
            WizardStep::InitialSync => true, // Optional step
            WizardStep::Complete => true,
        }
    }

    pub fn validate_current_step(&mut self) -> bool {
        let is_valid = self.is_step_valid(&self.current_step);
        if !is_valid {
            let error_message = match self.current_step {
                WizardStep::SecuritySetup => {
                    if self.data.generate_new_keys {
                        "Please select an encryption algorithm"
                    } else {
                        "Please provide both recipient public key and sender private key"
                    }
                }
                WizardStep::StorageSelection => "Please select a storage backend",
                WizardStep::StorageConfiguration => "Please configure the selected storage backend",
                _ => "Please complete all required fields",
            };
            self.validation_errors.insert(self.current_step.clone(), error_message.to_string());
        } else {
            self.validation_errors.remove(&self.current_step);
        }
        is_valid
    }

    pub fn render(&mut self, ui: &mut egui::Ui, design: &DesignSystem, notifications: &mut NotificationManager) {
        if !self.is_active {
            return;
        }

        // Wizard dialog
        egui::Window::new("Setup Wizard")
            .collapsible(false)
            .resizable(false)
            .default_width(600.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ui.ctx(), |ui| {
                // Progress indicator
                self.render_progress_indicator(ui, design);

                ui.separator();

                // Step content
                match self.current_step {
                    WizardStep::Welcome => self.render_welcome_step(ui, design),
                    WizardStep::SecuritySetup => self.render_security_step(ui, design),
                    WizardStep::StorageSelection => self.render_storage_selection_step(ui, design),
                    WizardStep::StorageConfiguration => self.render_storage_config_step(ui, design),
                    WizardStep::InitialSync => self.render_initial_sync_step(ui, design),
                    WizardStep::Complete => self.render_complete_step(ui, design),
                }

                ui.separator();

                // Show validation errors
                if let Some(error) = self.validation_errors.get(&self.current_step) {
                    ComponentLibrary::alert(
                        ui,
                        crate::gui::design_system::AlertType::Error,
                        "Validation Error",
                        error,
                        design,
                    );
                    ui.add_space(design.spacing.md);
                }

                // Navigation buttons
                self.render_navigation_buttons(ui, design, notifications);
            });
    }

    fn render_progress_indicator(&self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::section_header(ui, &format!("{} - {}", self.current_step.title(), self.current_step.description()), design);

        // Progress bar
        let current_index = self.current_step.step_index();
        let total_steps = WizardStep::total_steps();
        let progress = (current_index as f32) / (total_steps as f32 - 1.0);

        ComponentLibrary::progress_bar(
            ui,
            progress,
            Some(&format!("Step {} of {}", current_index + 1, total_steps)),
            design,
        );

        ui.add_space(design.spacing.lg);
    }

    fn render_welcome_step(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::card(ui, design, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(design.spacing.lg);

                // Welcome icon/logo placeholder
                ui.colored_label(design.colors.primary, "🔒");
                ui.add_space(design.spacing.md);

                ui.heading("Welcome to n0n");
                ui.add_space(design.spacing.sm);

                ui.label("Secure File Synchronization & Storage");
                ui.add_space(design.spacing.lg);

                ui.label("This wizard will help you set up n0n for secure file synchronization.");
                ui.label("We'll configure your security settings, storage backend, and test everything together.");

                ui.add_space(design.spacing.lg);

                ComponentLibrary::alert(
                    ui,
                    crate::gui::design_system::AlertType::Info,
                    "Getting Started",
                    "The setup process takes about 5-10 minutes and will ensure your files are properly secured.",
                    design,
                );
            });
        });
    }

    fn render_security_step(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::card(ui, design, |ui| {
            ui.heading("Security Configuration");
            ui.add_space(design.spacing.md);

            // Key generation options
            ui.horizontal(|ui| {
                if ui.radio(self.data.generate_new_keys, "Generate new encryption keys").clicked() {
                    self.data.generate_new_keys = true;
                    self.data.import_existing_keys = false;
                }
                ui.label("Recommended for new users");
            });

            ui.horizontal(|ui| {
                if ui.radio(!self.data.generate_new_keys, "Import existing keys").clicked() {
                    self.data.generate_new_keys = false;
                    self.data.import_existing_keys = true;
                }
                ui.label("For users with existing n0n installations");
            });

            ui.add_space(design.spacing.md);

            if self.data.generate_new_keys {
                // New key generation options
                ComponentLibrary::form_field(ui, "Encryption Algorithm", Some("Choose your preferred encryption"), design, |ui| {
                    egui::ComboBox::from_label("")
                        .selected_text(&self.data.encryption_algorithm)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.data.encryption_algorithm, "ChaCha20Poly1305".to_string(), "ChaCha20-Poly1305 (Recommended)");
                            ui.selectable_value(&mut self.data.encryption_algorithm, "AES256GCM".to_string(), "AES-256-GCM");
                            ui.selectable_value(&mut self.data.encryption_algorithm, "XSalsa20Poly1305".to_string(), "XSalsa20-Poly1305");
                        });
                });

                ComponentLibrary::form_field(ui, "Key Derivation Function", Some("For password-based key generation"), design, |ui| {
                    egui::ComboBox::from_label("")
                        .selected_text(&self.data.key_derivation_function)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.data.key_derivation_function, "Argon2".to_string(), "Argon2 (Recommended)");
                            ui.selectable_value(&mut self.data.key_derivation_function, "PBKDF2".to_string(), "PBKDF2");
                            ui.selectable_value(&mut self.data.key_derivation_function, "Scrypt".to_string(), "Scrypt");
                        });
                });

                ComponentLibrary::alert(
                    ui,
                    crate::gui::design_system::AlertType::Info,
                    "Key Generation",
                    "New encryption keys will be generated automatically with strong randomness.",
                    design,
                );
            } else {
                // Import existing keys
                ComponentLibrary::form_field(ui, "Recipient Public Key", Some("Base64 encoded public key"), design, |ui| {
                    ui.text_edit_multiline(&mut self.data.recipient_public_key);
                });

                ComponentLibrary::form_field(ui, "Sender Private Key", Some("Base64 encoded private key"), design, |ui| {
                    ui.text_edit_multiline(&mut self.data.sender_private_key);
                });

                ComponentLibrary::alert(
                    ui,
                    crate::gui::design_system::AlertType::Warning,
                    "Security Notice",
                    "Keep your private keys secure. Never share them with anyone.",
                    design,
                );
            }
        });
    }

    fn render_storage_selection_step(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::card(ui, design, |ui| {
            ui.heading("Choose Storage Backend");
            ui.add_space(design.spacing.md);

            let storage_options = vec![
                (StorageType::Local, "Local Storage", "Store files on your local machine", "🖥️", "Development, Testing"),
                (StorageType::S3Compatible, "Cloud Storage (S3)", "AWS S3, MinIO, CloudFlare R2, DigitalOcean", "☁️", "Production, Teams"),
                (StorageType::Sftp, "SFTP Server", "Secure file transfer to remote servers", "🖲️", "Remote Servers"),
                (StorageType::GoogleCloud, "Google Cloud Storage", "Google Cloud Platform storage", "🌐", "Google Cloud"),
                (StorageType::AzureBlob, "Azure Blob Storage", "Microsoft Azure storage", "🔷", "Microsoft Azure"),
                (StorageType::MultiCloud, "Multi-Cloud", "Replicate across multiple backends", "🌍", "High Availability"),
            ];

            for (storage_type, name, description, icon, use_case) in storage_options {
                let is_selected = self.data.selected_storage_type == Some(storage_type);

                ComponentLibrary::elevated_card(ui, design, |ui| {
                    ui.horizontal(|ui| {
                        if ui.radio(is_selected, "").clicked() {
                            self.data.selected_storage_type = Some(storage_type);
                        }

                        ui.add_space(design.spacing.sm);
                        ui.label(egui::RichText::new(icon).size(24.0));
                        ui.add_space(design.spacing.sm);

                        ui.vertical(|ui| {
                            ui.strong(name);
                            ui.label(description);
                            ui.small(format!("Best for: {}", use_case));
                        });
                    });
                });

                ui.add_space(design.spacing.sm);
            }

            if let Some(selected) = &self.data.selected_storage_type {
                ui.add_space(design.spacing.md);
                let info_text = match selected {
                    StorageType::Local => "Files will be stored on your local machine. Good for development and testing.",
                    StorageType::S3Compatible => "Supports AWS S3, MinIO, CloudFlare R2, and other S3-compatible services.",
                    StorageType::Sftp => "Connect to remote servers via SSH. Requires server credentials.",
                    StorageType::GoogleCloud => "Uses Google Cloud Storage. Requires Google Cloud credentials.",
                    StorageType::AzureBlob => "Uses Microsoft Azure Blob Storage. Requires Azure credentials.",
                    StorageType::MultiCloud => "Replicates files across multiple storage backends for redundancy.",
                    _ => "Configure this storage backend on the next step.",
                };

                ComponentLibrary::alert(
                    ui,
                    crate::gui::design_system::AlertType::Info,
                    "Selection Info",
                    info_text,
                    design,
                );
            }
        });
    }

    fn render_storage_config_step(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::card(ui, design, |ui| {
            if let Some(storage_type) = &self.data.selected_storage_type {
                ui.heading(&format!("Configure {}", self.storage_type_name(storage_type)));
                ui.add_space(design.spacing.md);

                match storage_type {
                    StorageType::Local => self.render_local_config(ui, design),
                    StorageType::S3Compatible => self.render_s3_config(ui, design),
                    StorageType::Sftp => self.render_sftp_config(ui, design),
                    StorageType::GoogleCloud => self.render_gcs_config(ui, design),
                    StorageType::AzureBlob => self.render_azure_config(ui, design),
                    StorageType::MultiCloud => self.render_multicloud_config(ui, design),
                    _ => {
                        ui.label("Configuration for this storage type will be available soon.");
                    }
                }
            } else {
                ui.label("Please go back and select a storage backend first.");
            }
        });
    }

    fn render_local_config(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::form_field(ui, "Storage Directory", Some("Where to store your files locally"), design, |ui| {
            ui.horizontal(|ui| {
                let mut path = self.data.storage_config.get("base_path").cloned().unwrap_or_else(|| "n0n_storage".to_string());
                ui.text_edit_singleline(&mut path);
                self.data.storage_config.insert("base_path".to_string(), path);

                if ui.button("Browse").clicked() {
                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                        self.data.storage_config.insert("base_path".to_string(), folder.display().to_string());
                    }
                }
            });
        });

        ComponentLibrary::form_field(ui, "Options", None, design, |ui| {
            let mut create_dirs = self.data.storage_config.get("create_directories").map(|s| s == "true").unwrap_or(true);
            if ui.checkbox(&mut create_dirs, "Create directories automatically").changed() {
                self.data.storage_config.insert("create_directories".to_string(), create_dirs.to_string());
            }
        });
    }

    fn render_s3_config(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::form_field(ui, "Bucket Name", Some("S3 bucket name"), design, |ui| {
            let mut bucket = self.data.storage_config.get("bucket").cloned().unwrap_or_default();
            ui.text_edit_singleline(&mut bucket);
            self.data.storage_config.insert("bucket".to_string(), bucket);
        });

        ComponentLibrary::form_field(ui, "Region", Some("AWS region or S3 endpoint region"), design, |ui| {
            let mut region = self.data.storage_config.get("region").cloned().unwrap_or_else(|| "us-east-1".to_string());
            ui.text_edit_singleline(&mut region);
            self.data.storage_config.insert("region".to_string(), region);
        });

        ComponentLibrary::form_field(ui, "Endpoint (Optional)", Some("Custom S3 endpoint for MinIO, CloudFlare R2, etc."), design, |ui| {
            let mut endpoint = self.data.storage_config.get("endpoint").cloned().unwrap_or_default();
            ui.text_edit_singleline(&mut endpoint);
            if !endpoint.is_empty() {
                self.data.storage_config.insert("endpoint".to_string(), endpoint);
            }
        });

        ComponentLibrary::alert(
            ui,
            crate::gui::design_system::AlertType::Info,
            "Credentials",
            "Configure AWS credentials via environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) or AWS CLI.",
            design,
        );
    }

    fn render_sftp_config(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::form_field(ui, "Host", Some("SFTP server hostname or IP"), design, |ui| {
            let mut host = self.data.storage_config.get("host").cloned().unwrap_or_default();
            ui.text_edit_singleline(&mut host);
            self.data.storage_config.insert("host".to_string(), host);
        });

        ComponentLibrary::form_field(ui, "Username", Some("SSH username"), design, |ui| {
            let mut username = self.data.storage_config.get("username").cloned().unwrap_or_default();
            ui.text_edit_singleline(&mut username);
            self.data.storage_config.insert("username".to_string(), username);
        });

        ComponentLibrary::form_field(ui, "Remote Path", Some("Base directory on the remote server"), design, |ui| {
            let mut remote_path = self.data.storage_config.get("remote_path").cloned().unwrap_or_else(|| "/home/user/n0n".to_string());
            ui.text_edit_singleline(&mut remote_path);
            self.data.storage_config.insert("remote_path".to_string(), remote_path);
        });

        ComponentLibrary::alert(
            ui,
            crate::gui::design_system::AlertType::Info,
            "Authentication",
            "Configure SSH key authentication or password authentication. SSH keys are recommended for security.",
            design,
        );
    }

    fn render_gcs_config(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::form_field(ui, "Bucket Name", Some("Google Cloud Storage bucket"), design, |ui| {
            let mut bucket = self.data.storage_config.get("bucket").cloned().unwrap_or_default();
            ui.text_edit_singleline(&mut bucket);
            self.data.storage_config.insert("bucket".to_string(), bucket);
        });

        ComponentLibrary::form_field(ui, "Project ID", Some("Google Cloud Project ID"), design, |ui| {
            let mut project = self.data.storage_config.get("project_id").cloned().unwrap_or_default();
            ui.text_edit_singleline(&mut project);
            self.data.storage_config.insert("project_id".to_string(), project);
        });

        ComponentLibrary::alert(
            ui,
            crate::gui::design_system::AlertType::Info,
            "Authentication",
            "Configure Google Cloud credentials via service account key file or application default credentials.",
            design,
        );
    }

    fn render_azure_config(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::form_field(ui, "Account Name", Some("Azure storage account name"), design, |ui| {
            let mut account = self.data.storage_config.get("account_name").cloned().unwrap_or_default();
            ui.text_edit_singleline(&mut account);
            self.data.storage_config.insert("account_name".to_string(), account);
        });

        ComponentLibrary::form_field(ui, "Container Name", Some("Azure blob container name"), design, |ui| {
            let mut container = self.data.storage_config.get("container").cloned().unwrap_or_default();
            ui.text_edit_singleline(&mut container);
            self.data.storage_config.insert("container".to_string(), container);
        });

        ComponentLibrary::alert(
            ui,
            crate::gui::design_system::AlertType::Info,
            "Authentication",
            "Configure Azure credentials via environment variables or Azure CLI.",
            design,
        );
    }

    fn render_multicloud_config(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ui.label("Multi-cloud configuration allows you to replicate your data across multiple storage backends for increased reliability.");

        ComponentLibrary::alert(
            ui,
            crate::gui::design_system::AlertType::Info,
            "Advanced Feature",
            "Multi-cloud setup requires configuring multiple backends. This is recommended for production environments requiring high availability.",
            design,
        );

        // For now, set a basic configuration to allow progression
        self.data.storage_config.insert("primary_backend".to_string(), "s3".to_string());
    }

    fn render_initial_sync_step(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::card(ui, design, |ui| {
            ui.heading("Test Your Configuration");
            ui.add_space(design.spacing.md);

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.data.test_with_sample_files, "Test with sample files");
                ui.label("Recommended to verify your setup");
            });

            if self.data.test_with_sample_files {
                ui.add_space(design.spacing.md);

                ComponentLibrary::form_field(ui, "Test Files", Some("Select files to test synchronization"), design, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(&format!("{} files selected", self.data.selected_test_files.len()));
                        if ui.button("Select Files").clicked() {
                            if let Some(files) = rfd::FileDialog::new().pick_files() {
                                self.data.selected_test_files = files;
                            }
                        }
                        if ui.button("Clear").clicked() {
                            self.data.selected_test_files.clear();
                        }
                    });

                    if !self.data.selected_test_files.is_empty() {
                        ui.add_space(design.spacing.sm);
                        egui::ScrollArea::vertical().max_height(100.0).show(ui, |ui| {
                            for file in &self.data.selected_test_files {
                                ui.small(file.file_name().unwrap_or_default().to_string_lossy().as_ref());
                            }
                        });
                    }
                });

                ComponentLibrary::form_field(ui, "Output Directory", Some("Where to store processed files"), design, |ui| {
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.data.output_directory);
                        if ui.button("Browse").clicked() {
                            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                self.data.output_directory = folder.display().to_string();
                            }
                        }
                    });
                });
            } else {
                ComponentLibrary::alert(
                    ui,
                    crate::gui::design_system::AlertType::Warning,
                    "Skip Testing",
                    "You can test your configuration later from the main application interface.",
                    design,
                );
            }
        });
    }

    fn render_complete_step(&mut self, ui: &mut egui::Ui, design: &DesignSystem) {
        ComponentLibrary::card(ui, design, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(design.spacing.lg);

                // Success icon
                ui.colored_label(design.colors.success, "✅");
                ui.add_space(design.spacing.md);

                ui.heading("Setup Complete!");
                ui.add_space(design.spacing.sm);

                ui.label("Your n0n configuration is ready to use.");
                ui.add_space(design.spacing.lg);

                // Configuration summary
                ComponentLibrary::elevated_card(ui, design, |ui| {
                    ui.strong("Configuration Summary:");
                    ui.add_space(design.spacing.sm);

                    ui.horizontal(|ui| {
                        ui.label("Security:");
                        let security_info = if self.data.generate_new_keys {
                            format!("New keys with {}", self.data.encryption_algorithm)
                        } else {
                            "Imported existing keys".to_string()
                        };
                        ui.small(security_info);
                    });

                    if let Some(storage_type) = &self.data.selected_storage_type {
                        ui.horizontal(|ui| {
                            ui.label("Storage:");
                            ui.small(self.storage_type_name(storage_type));
                        });
                    }

                    if self.data.test_with_sample_files && !self.data.selected_test_files.is_empty() {
                        ui.horizontal(|ui| {
                            ui.label("Test Files:");
                            ui.small(format!("{} files selected", self.data.selected_test_files.len()));
                        });
                    }
                });

                ui.add_space(design.spacing.lg);

                ComponentLibrary::alert(
                    ui,
                    crate::gui::design_system::AlertType::Success,
                    "Ready to Use",
                    "You can now start using n0n to securely synchronize your files. Check the Dashboard for system status and recent activity.",
                    design,
                );
            });
        });
    }

    fn render_navigation_buttons(&mut self, ui: &mut egui::Ui, design: &DesignSystem, notifications: &mut NotificationManager) {
        ui.horizontal(|ui| {
            // Cancel button
            if ui.add(ComponentLibrary::secondary_button("Cancel".to_string(), design)).clicked() {
                self.cancel();
                notifications.info("Setup Cancelled", "You can restart the setup wizard anytime");
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Next/Finish button
                let (button_text, button_enabled) = if self.current_step == WizardStep::Complete {
                    ("Finish", true)
                } else {
                    ("Next", self.can_go_next())
                };

                let button = if self.current_step == WizardStep::Complete {
                    ComponentLibrary::success_button(button_text.to_string(), design)
                } else {
                    ComponentLibrary::primary_button(button_text.to_string(), design)
                };

                if ui.add_enabled(button_enabled, button).clicked() {
                    if self.current_step == WizardStep::Complete {
                        self.finish();
                        notifications.success("Setup Complete", "n0n is now configured and ready to use");
                    } else {
                        if self.validate_current_step() {
                            if self.go_next() {
                                notifications.info("Step Complete", &format!("Moved to {}", self.current_step.title()));
                            }
                        } else {
                            notifications.warning("Validation Failed", "Please complete all required fields");
                        }
                    }
                }

                // Previous button
                if ui.add_enabled(self.can_go_previous(), ComponentLibrary::secondary_button("Previous".to_string(), design)).clicked() {
                    self.go_previous();
                }
            });
        });
    }

    fn storage_type_name(&self, storage_type: &StorageType) -> &'static str {
        match storage_type {
            StorageType::Local => "Local Storage",
            StorageType::S3Compatible => "S3-Compatible Storage",
            StorageType::Sftp => "SFTP Server",
            StorageType::GoogleCloud => "Google Cloud Storage",
            StorageType::AzureBlob => "Azure Blob Storage",
            StorageType::PostgreSQL => "PostgreSQL Database",
            StorageType::Redis => "Redis Cache",
            StorageType::MultiCloud => "Multi-Cloud",
            StorageType::CachedCloud => "Cached Cloud",
            StorageType::WebDav => "WebDAV",
            StorageType::Ipfs => "IPFS",
        }
    }
}