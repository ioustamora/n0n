use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::collections::HashMap;
use eframe::egui;
use crate::storage::backend::StorageType;

/// Configuration for different storage backends in the GUI
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
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
    
    // MultiCloud config
    pub multicloud_primary: String,
    pub multicloud_replicas: Vec<String>,
    pub multicloud_consistency: String,
    pub multicloud_strategy: String,
}

#[derive(Default)]
pub struct AppState {
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
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Settings {
    // Do NOT store secrets (passwords, private key passphrases)
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
        app.chunk_size_mb = 10;
        app.watcher_debounce_ms = 1000;
        app.storage_backend_type = StorageType::Local;
        
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
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("n0n - Secure File Sharing");
            
            // Render different sections
            self.render_keypair_section(ui);
            self.render_storage_backend_section(ui);  
            self.render_sftp_section(ui);
            self.render_progress_section(ui);
            self.render_logs_section(ui);
        });
    }
}