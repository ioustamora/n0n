use eframe::egui;
use std::sync::atomic::Ordering;
use crate::gui::state::{AppState, StorageBackendConfig};
use crate::storage::backend::{StorageType, StorageConfig, LocalConfig, SftpConfig, S3Config, GcsConfig, AzureConfig, PostgreSQLConfig, RedisConfig, CachedCloudConfigSimple};
use crate::storage::factory::{StorageFactory, StorageManager};

impl AppState {
    /// Render the main storage backend selection and configuration section
    pub fn render_enhanced_storage_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading("Storage Backend Configuration");
            
            // Backend selection
            self.render_storage_backend_selection(ui);
            
            ui.separator();
            
            // Backend-specific configuration
            self.render_current_backend_config(ui);
            
            ui.separator();
            
            // Storage actions and status
            self.render_storage_actions(ui);
        });
    }
    
    /// Render storage backend type selection
    fn render_storage_backend_selection(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Storage Backend:");
            
            let available_backends = StorageFactory::available_backends();
            let mut changed = false;
            
            for backend_type in available_backends {
                let is_selected = self.storage_backend_type == backend_type;
                if ui.selectable_label(is_selected, format!("{:?}", backend_type)).clicked() {
                    if !is_selected {
                        self.storage_backend_type = backend_type;
                        changed = true;
                        
                        // Initialize config if not exists
                        if !self.storage_configs.contains_key(&backend_type) {
                            self.storage_configs.insert(backend_type, StorageBackendConfig::default());
                        }
                    }
                }
            }
            
            if changed {
                self.log(&format!("Selected storage backend: {:?}", self.storage_backend_type));
            }
        });
        
        // Show backend description
        let description = match self.storage_backend_type {
            StorageType::Local => "Local filesystem storage - stores chunks on the local machine",
            StorageType::Sftp => "SFTP remote storage - stores chunks on an SFTP server",
            StorageType::S3Compatible => "S3-compatible storage - works with AWS S3, MinIO, R2, etc.",
            StorageType::GoogleCloud => "Google Cloud Storage - Google's object storage service",
            StorageType::AzureBlob => "Azure Blob Storage - Microsoft Azure's object storage",
            StorageType::PostgreSQL => "PostgreSQL database - stores chunks in a relational database",
            StorageType::Redis => "Redis in-memory storage - high-performance with optional TTL",
            StorageType::MultiCloud => "Multi-cloud replication - replicates data across multiple backends",
            StorageType::CachedCloud => "Cached cloud storage - local cache with cloud backing",
            _ => "Unknown storage backend",
        };
        
        ui.label(egui::RichText::new(description).italics().small());
    }
    
    /// Render configuration for the currently selected backend
    fn render_current_backend_config(&mut self, ui: &mut egui::Ui) {
        let backend_type = self.storage_backend_type;
        let config = self.storage_configs.entry(backend_type).or_insert_with(StorageBackendConfig::default);
        
        match backend_type {
            StorageType::Local => self.render_local_config(ui, config),
            StorageType::Sftp => self.render_sftp_config(ui, config),
            StorageType::S3Compatible => self.render_s3_config(ui, config),
            StorageType::GoogleCloud => self.render_gcs_config(ui, config),
            StorageType::AzureBlob => self.render_azure_config(ui, config),
            StorageType::PostgreSQL => self.render_postgres_config(ui, config),
            StorageType::Redis => self.render_redis_config(ui, config),
            StorageType::MultiCloud => self.render_multicloud_config(ui, config),
            StorageType::CachedCloud => self.render_cached_cloud_config(ui, config),
            _ => {
                ui.label("Configuration for this backend is not yet implemented");
            }
        }
    }
    
    /// Render local storage configuration
    fn render_local_config(&mut self, ui: &mut egui::Ui, config: &mut StorageBackendConfig) {
        ui.label("Local Storage Configuration");
        
        ui.horizontal(|ui| {
            ui.label("Base Path:");
            ui.text_edit_singleline(&mut config.local_base_path);
            if ui.button("Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    config.local_base_path = path.display().to_string();
                }
            }
        });
        
        ui.checkbox(&mut config.local_create_dirs, "Create directories automatically");
        
        if !config.local_base_path.is_empty() {
            if ui.button("Open Folder").clicked() {
                let path = std::path::PathBuf::from(&config.local_base_path);
                let _ = crate::gui::open_folder_in_os(&path);
            }
        }
    }
    
    /// Render SFTP configuration
    fn render_sftp_config(&mut self, ui: &mut egui::Ui, config: &mut StorageBackendConfig) {
        ui.label("SFTP Configuration");
        
        ui.horizontal(|ui| {
            ui.label("Host:Port:");
            ui.text_edit_singleline(&mut config.sftp_host);
        });
        
        ui.horizontal(|ui| {
            ui.label("Username:");
            ui.text_edit_singleline(&mut config.sftp_user);
        });
        
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.text_edit_singleline(&mut config.sftp_pass);
        });
        
        ui.horizontal(|ui| {
            ui.label("Base Path:");
            ui.text_edit_singleline(&mut config.sftp_base);
        });
        
        ui.horizontal(|ui| {
            ui.label("Mailbox ID:");
            ui.text_edit_singleline(&mut config.sftp_mailbox_id);
        });
        
        ui.collapsing("Advanced SFTP Settings", |ui| {
            ui.horizontal(|ui| {
                ui.label("Private Key:");
                ui.text_edit_multiline(&mut config.sftp_private_key);
            });
            
            ui.horizontal(|ui| {
                ui.label("Private Key Passphrase:");
                ui.text_edit_singleline(&mut config.sftp_private_key_pass);
            });
            
            ui.horizontal(|ui| {
                ui.label("Host Fingerprint (SHA256):");
                ui.text_edit_singleline(&mut config.sftp_host_fingerprint_sha256_b64);
            });
            
            ui.checkbox(&mut config.sftp_require_host_fp, "Require host fingerprint verification");
        });
    }
    
    /// Render S3-compatible storage configuration
    fn render_s3_config(&mut self, ui: &mut egui::Ui, config: &mut StorageBackendConfig) {
        ui.label("S3-Compatible Storage Configuration");
        
        ui.horizontal(|ui| {
            ui.label("Bucket:");
            ui.text_edit_singleline(&mut config.s3_bucket);
        });
        
        ui.horizontal(|ui| {
            ui.label("Region:");
            ui.text_edit_singleline(&mut config.s3_region);
        });
        
        ui.horizontal(|ui| {
            ui.label("Endpoint (optional):");
            ui.text_edit_singleline(&mut config.s3_endpoint);
        });
        ui.label("Leave empty for AWS S3, or specify for MinIO/R2/DigitalOcean");
        
        ui.horizontal(|ui| {
            ui.label("Access Key ID:");
            ui.text_edit_singleline(&mut config.s3_access_key_id);
        });
        
        ui.horizontal(|ui| {
            ui.label("Secret Access Key:");
            ui.text_edit_singleline(&mut config.s3_secret_access_key);
        });
        
        ui.horizontal(|ui| {
            ui.label("Path Prefix (optional):");
            ui.text_edit_singleline(&mut config.s3_path_prefix);
        });
    }
    
    /// Render Google Cloud Storage configuration
    fn render_gcs_config(&mut self, ui: &mut egui::Ui, config: &mut StorageBackendConfig) {
        ui.label("Google Cloud Storage Configuration");
        
        ui.horizontal(|ui| {
            ui.label("Bucket:");
            ui.text_edit_singleline(&mut config.gcs_bucket);
        });
        
        ui.horizontal(|ui| {
            ui.label("Project ID:");
            ui.text_edit_singleline(&mut config.gcs_project_id);
        });
        
        ui.horizontal(|ui| {
            ui.label("Path Prefix (optional):");
            ui.text_edit_singleline(&mut config.gcs_path_prefix);
        });
        
        ui.collapsing("Authentication", |ui| {
            ui.label("Service Account Key (JSON):");
            ui.text_edit_multiline(&mut config.gcs_service_account_key);
            ui.label("Leave empty to use default application credentials");
        });
    }
    
    /// Render Azure Blob Storage configuration
    fn render_azure_config(&mut self, ui: &mut egui::Ui, config: &mut StorageBackendConfig) {
        ui.label("Azure Blob Storage Configuration");
        
        ui.horizontal(|ui| {
            ui.label("Account Name:");
            ui.text_edit_singleline(&mut config.azure_account_name);
        });
        
        ui.horizontal(|ui| {
            ui.label("Account Key:");
            ui.text_edit_singleline(&mut config.azure_account_key);
        });
        
        ui.horizontal(|ui| {
            ui.label("Container:");
            ui.text_edit_singleline(&mut config.azure_container);
        });
        
        ui.horizontal(|ui| {
            ui.label("Path Prefix (optional):");
            ui.text_edit_singleline(&mut config.azure_path_prefix);
        });
    }
    
    /// Render PostgreSQL configuration
    fn render_postgres_config(&mut self, ui: &mut egui::Ui, config: &mut StorageBackendConfig) {
        ui.label("PostgreSQL Configuration");
        
        ui.horizontal(|ui| {
            ui.label("Connection String:");
            ui.text_edit_singleline(&mut config.postgres_connection_string);
        });
        ui.label("Example: postgresql://user:password@localhost:5432/database");
        
        ui.horizontal(|ui| {
            ui.label("Table Prefix (optional):");
            ui.text_edit_singleline(&mut config.postgres_table_prefix);
        });
    }
    
    /// Render Redis configuration
    fn render_redis_config(&mut self, ui: &mut egui::Ui, config: &mut StorageBackendConfig) {
        ui.label("Redis Configuration");
        
        ui.horizontal(|ui| {
            ui.label("Redis URL:");
            ui.text_edit_singleline(&mut config.redis_url);
        });
        ui.label("Example: redis://localhost:6379");
        
        ui.horizontal(|ui| {
            ui.label("Key Prefix (optional):");
            ui.text_edit_singleline(&mut config.redis_key_prefix);
        });
        
        ui.horizontal(|ui| {
            ui.label("TTL Seconds (optional):");
            ui.text_edit_singleline(&mut config.redis_ttl_seconds);
        });
        ui.label("Leave empty for no expiration");
    }
    
    /// Render MultiCloud configuration
    fn render_multicloud_config(&mut self, ui: &mut egui::Ui, config: &mut StorageBackendConfig) {
        ui.label("Multi-Cloud Replication Configuration");
        
        ui.horizontal(|ui| {
            ui.label("Primary Backend:");
            egui::ComboBox::from_label("")
                .selected_text(&config.multicloud_primary)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut config.multicloud_primary, "Local".to_string(), "Local");
                    ui.selectable_value(&mut config.multicloud_primary, "Sftp".to_string(), "SFTP");
                    ui.selectable_value(&mut config.multicloud_primary, "S3Compatible".to_string(), "S3-Compatible");
                    ui.selectable_value(&mut config.multicloud_primary, "GoogleCloud".to_string(), "Google Cloud");
                    ui.selectable_value(&mut config.multicloud_primary, "AzureBlob".to_string(), "Azure Blob");
                    ui.selectable_value(&mut config.multicloud_primary, "PostgreSQL".to_string(), "PostgreSQL");
                    ui.selectable_value(&mut config.multicloud_primary, "Redis".to_string(), "Redis");
                });
        });
        
        ui.horizontal(|ui| {
            ui.label("Consistency Level:");
            egui::ComboBox::from_label("")
                .selected_text(&config.multicloud_consistency)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut config.multicloud_consistency, "Eventual".to_string(), "Eventual");
                    ui.selectable_value(&mut config.multicloud_consistency, "Strong".to_string(), "Strong");
                    ui.selectable_value(&mut config.multicloud_consistency, "Quorum".to_string(), "Quorum");
                });
        });
        
        ui.horizontal(|ui| {
            ui.label("Replication Strategy:");
            egui::ComboBox::from_label("")
                .selected_text(&config.multicloud_strategy)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut config.multicloud_strategy, "AsyncReplication".to_string(), "Async Replication");
                    ui.selectable_value(&mut config.multicloud_strategy, "SyncReplication".to_string(), "Sync Replication");
                    ui.selectable_value(&mut config.multicloud_strategy, "QuorumWrite".to_string(), "Quorum Write");
                });
        });
        
        ui.label("Note: Configure individual backends above before setting up multi-cloud replication");
    }
    
    /// Render Cached Cloud configuration
    fn render_cached_cloud_config(&mut self, ui: &mut egui::Ui, config: &mut StorageBackendConfig) {
        ui.label("Cached Cloud Storage Configuration");
        
        ui.horizontal(|ui| {
            ui.label("Cache Directory:");
            ui.text_edit_singleline(&mut config.cache_dir);
            if ui.button("Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    config.cache_dir = path.display().to_string();
                }
            }
        });
        
        ui.horizontal(|ui| {
            ui.label("Max Cache Size (MB):");
            ui.add(egui::DragValue::new(&mut config.cache_max_size_mb).range(0..=10240));
        });
        
        ui.horizontal(|ui| {
            ui.label("Eviction Policy:");
            egui::ComboBox::from_label("")
                .selected_text(&config.cache_eviction_policy)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut config.cache_eviction_policy, "lru".to_string(), "LRU (Least Recently Used)");
                    ui.selectable_value(&mut config.cache_eviction_policy, "lfu".to_string(), "LFU (Least Frequently Used)");
                    ui.selectable_value(&mut config.cache_eviction_policy, "fifo".to_string(), "FIFO (First In, First Out)");
                    ui.selectable_value(&mut config.cache_eviction_policy, "ttl_only".to_string(), "TTL Only");
                });
        });
        
        ui.horizontal(|ui| {
            ui.label("Write Policy:");
            egui::ComboBox::from_label("")
                .selected_text(&config.cache_write_policy)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut config.cache_write_policy, "write_through".to_string(), "Write-Through");
                    ui.selectable_value(&mut config.cache_write_policy, "write_back".to_string(), "Write-Back");
                    ui.selectable_value(&mut config.cache_write_policy, "write_around".to_string(), "Write-Around");
                });
        });
        
        ui.label("Note: Configure the underlying cloud backend above");
    }
    
    /// Render storage actions and health monitoring
    fn render_storage_actions(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Test Connection").clicked() {
                self.test_current_backend();
            }
            
            if ui.button("View Health").clicked() {
                self.check_backend_health();
            }
            
            if ui.button("Save Settings").clicked() {
                self.save_settings();
                self.log("Settings saved");
            }
        });
        
        // Display current backend health status
        if let Ok(health) = self.current_backend_health.lock() {
            if !health.is_empty() {
                ui.separator();
                ui.label("Backend Health Status:");
                
                egui::ScrollArea::vertical()
                    .max_height(150.0)
                    .show(ui, |ui| {
                        for (key, value) in health.iter() {
                            ui.horizontal(|ui| {
                                ui.label(format!("{}:", key));
                                ui.label(value);
                            });
                        }
                    });
            }
        }
    }
    
    /// Test the current backend connection
    fn test_current_backend(&mut self) {
        let backend_type = self.storage_backend_type;
        let config = if let Some(config) = self.storage_configs.get(&backend_type) {
            config.clone()
        } else {
            self.log("No configuration found for current backend");
            return;
        };
        
        self.log(&format!("Testing connection to {:?} backend...", backend_type));
        
        let logs = self.logs.clone();
        let health = self.current_backend_health.clone();
        
        // Convert GUI config to storage config
        let storage_config = self.convert_to_storage_config(backend_type, &config);
        
        tokio::spawn(async move {
            match StorageFactory::create_backend(storage_config).await {
                Ok(backend) => {
                    match backend.test_connection().await {
                        Ok(_) => {
                            if let Ok(mut l) = logs.lock() {
                                l.push("✅ Connection test successful!".to_string());
                            }
                            
                            // Get backend info and health
                            let info = backend.get_info();
                            if let Ok(backend_health) = backend.health_check().await {
                                if let Ok(mut h) = health.lock() {
                                    h.clear();
                                    h.extend(info);
                                    h.extend(backend_health);
                                }
                            }
                        }
                        Err(e) => {
                            if let Ok(mut l) = logs.lock() {
                                l.push(format!("❌ Connection test failed: {}", e));
                            }
                        }
                    }
                }
                Err(e) => {
                    if let Ok(mut l) = logs.lock() {
                        l.push(format!("❌ Failed to create backend: {}", e));
                    }
                }
            }
        });
    }
    
    /// Check backend health
    fn check_backend_health(&mut self) {
        let backend_type = self.storage_backend_type;
        let config = if let Some(config) = self.storage_configs.get(&backend_type) {
            config.clone()
        } else {
            self.log("No configuration found for current backend");
            return;
        };
        
        self.log("Checking backend health...");
        
        let logs = self.logs.clone();
        let health = self.current_backend_health.clone();
        let storage_config = self.convert_to_storage_config(backend_type, &config);
        
        tokio::spawn(async move {
            match StorageFactory::create_backend(storage_config).await {
                Ok(backend) => {
                    match backend.health_check().await {
                        Ok(health_data) => {
                            if let Ok(mut h) = health.lock() {
                                h.clear();
                                h.extend(health_data);
                            }
                            if let Ok(mut l) = logs.lock() {
                                l.push("Health check completed".to_string());
                            }
                        }
                        Err(e) => {
                            if let Ok(mut l) = logs.lock() {
                                l.push(format!("Health check failed: {}", e));
                            }
                        }
                    }
                }
                Err(e) => {
                    if let Ok(mut l) = logs.lock() {
                        l.push(format!("Failed to create backend for health check: {}", e));
                    }
                }
            }
        });
    }
    
    /// Convert GUI config to storage config
    fn convert_to_storage_config(&self, backend_type: StorageType, config: &StorageBackendConfig) -> StorageConfig {
        let mut storage_config = StorageConfig {
            backend_type,
            ..Default::default()
        };
        
        match backend_type {
            StorageType::Local => {
                storage_config.local = Some(LocalConfig {
                    base_path: config.local_base_path.clone(),
                    create_dirs: Some(config.local_create_dirs),
                });
            }
            StorageType::Sftp => {
                storage_config.sftp = Some(SftpConfig {
                    host: config.sftp_host.clone(),
                    port: None, // Parse from host if needed
                    username: config.sftp_user.clone(),
                    password: if config.sftp_pass.is_empty() { None } else { Some(config.sftp_pass.clone()) },
                    private_key_path: None,
                    private_key_content: if config.sftp_private_key.is_empty() { None } else { Some(config.sftp_private_key.clone()) },
                    private_key_passphrase: if config.sftp_private_key_pass.is_empty() { None } else { Some(config.sftp_private_key_pass.clone()) },
                    host_fingerprint_sha256: if config.sftp_host_fingerprint_sha256_b64.is_empty() { None } else { Some(config.sftp_host_fingerprint_sha256_b64.clone()) },
                    base_path: config.sftp_base.clone(),
                    connection_timeout: None,
                });
            }
            StorageType::S3Compatible => {
                storage_config.s3 = Some(S3Config {
                    bucket: config.s3_bucket.clone(),
                    region: config.s3_region.clone(),
                    endpoint: if config.s3_endpoint.is_empty() { None } else { Some(config.s3_endpoint.clone()) },
                    access_key_id: config.s3_access_key_id.clone(),
                    secret_access_key: config.s3_secret_access_key.clone(),
                    session_token: None,
                    path_prefix: if config.s3_path_prefix.is_empty() { None } else { Some(config.s3_path_prefix.clone()) },
                    force_path_style: None,
                });
            }
            StorageType::GoogleCloud => {
                storage_config.gcs = Some(GcsConfig {
                    bucket: config.gcs_bucket.clone(),
                    project_id: config.gcs_project_id.clone(),
                    service_account_key: if config.gcs_service_account_key.is_empty() { None } else { Some(config.gcs_service_account_key.clone()) },
                    service_account_path: None,
                    path_prefix: if config.gcs_path_prefix.is_empty() { None } else { Some(config.gcs_path_prefix.clone()) },
                });
            }
            StorageType::AzureBlob => {
                storage_config.azure = Some(AzureConfig {
                    account_name: config.azure_account_name.clone(),
                    account_key: if config.azure_account_key.is_empty() { None } else { Some(config.azure_account_key.clone()) },
                    sas_token: None,
                    container: config.azure_container.clone(),
                    path_prefix: if config.azure_path_prefix.is_empty() { None } else { Some(config.azure_path_prefix.clone()) },
                });
            }
            StorageType::PostgreSQL => {
                storage_config.postgresql = Some(PostgreSQLConfig {
                    connection_string: config.postgres_connection_string.clone(),
                    table_prefix: if config.postgres_table_prefix.is_empty() { None } else { Some(config.postgres_table_prefix.clone()) },
                    pool_size: None,
                });
            }
            StorageType::Redis => {
                storage_config.redis = Some(RedisConfig {
                    url: config.redis_url.clone(),
                    cluster_mode: None,
                    key_prefix: if config.redis_key_prefix.is_empty() { None } else { Some(config.redis_key_prefix.clone()) },
                    ttl: if config.redis_ttl_seconds.is_empty() { None } else { config.redis_ttl_seconds.parse().ok() },
                });
            }
            StorageType::CachedCloud => {
                // For cached cloud, we need the underlying cloud config too
                let underlying_type = StorageType::Local; // Default, should be configurable
                storage_config.cached_cloud = Some(CachedCloudConfigSimple {
                    cloud_backend_type: underlying_type,
                    cache_dir: config.cache_dir.clone(),
                    max_cache_size: config.cache_max_size_mb * 1024 * 1024, // Convert MB to bytes
                    eviction_policy: config.cache_eviction_policy.clone(),
                    write_policy: config.cache_write_policy.clone(),
                    ttl_seconds: None,
                    enable_prefetch: false,
                });
                
                // Also set the underlying backend config
                storage_config.local = Some(LocalConfig {
                    base_path: config.local_base_path.clone(),
                    create_dirs: Some(config.local_create_dirs),
                });
            }
            _ => {
                // MultiCloud and others need more complex setup
            }
        }
        
        storage_config
    }
}