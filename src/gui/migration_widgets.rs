use eframe::egui;
use std::sync::Arc;
use crate::gui::state::AppState;
use crate::storage::backend::{StorageType, StorageConfig};
use crate::storage::migration::{
    StorageMigrationManager, MigrationConfig, MigrationStrategy, MigrationProgress, 
    MigrationUtils, MigrationEstimate
};

/// Migration state for the GUI
#[derive(Default)]
pub struct MigrationState {
    pub source_backend_type: StorageType,
    pub dest_backend_type: StorageType,
    pub migration_strategy: String,
    pub batch_size: u32,
    pub concurrency: u32,
    pub verify_integrity: bool,
    pub delete_source: bool,
    pub resume_from_recipient: String,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    
    // Runtime state
    pub migration_manager: Option<Arc<StorageMigrationManager>>,
    pub migration_running: bool,
    pub migration_progress: Option<MigrationProgress>,
    pub migration_estimate: Option<MigrationEstimate>,
    pub migration_logs: Vec<String>,
}

impl AppState {
    /// Render the storage migration interface
    pub fn render_migration_section(&mut self, ui: &mut egui::Ui) {
        // Initialize migration state if needed
        if !self.storage_configs.contains_key(&StorageType::Local) {
            self.storage_configs.insert(StorageType::Local, 
                crate::gui::state::StorageBackendConfig::default());
        }

        ui.group(|ui| {
            ui.heading("🔄 Storage Migration Tools");
            ui.separator();
            
            // Migration configuration
            self.render_migration_config(ui);
            
            ui.separator();
            
            // Migration actions
            self.render_migration_actions(ui);
            
            ui.separator();
            
            // Migration progress and status
            self.render_migration_status(ui);
        });
    }
    
    /// Render migration configuration options
    fn render_migration_config(&mut self, ui: &mut egui::Ui) {
        ui.heading("Migration Configuration");
        
        // Source backend selection
        ui.horizontal(|ui| {
            ui.label("Source Backend:");
            
            // Get current migration state or create default
            let migration_state = self.get_or_create_migration_state();
            
            egui::ComboBox::from_label("")
                .selected_text(format!("{:?}", migration_state.source_backend_type))
                .show_ui(ui, |ui| {
                    for backend_type in crate::storage::factory::StorageFactory::available_backends() {
                        ui.selectable_value(&mut migration_state.source_backend_type, backend_type, format!("{:?}", backend_type));
                    }
                });
                
            if ui.button("Test Source").clicked() {
                self.test_migration_backend(migration_state.source_backend_type, true);
            }
        });
        
        // Destination backend selection
        ui.horizontal(|ui| {
            ui.label("Destination Backend:");
            
            let migration_state = self.get_or_create_migration_state();
            
            egui::ComboBox::from_label("")
                .selected_text(format!("{:?}", migration_state.dest_backend_type))
                .show_ui(ui, |ui| {
                    for backend_type in crate::storage::factory::StorageFactory::available_backends() {
                        ui.selectable_value(&mut migration_state.dest_backend_type, backend_type, format!("{:?}", backend_type));
                    }
                });
                
            if ui.button("Test Destination").clicked() {
                self.test_migration_backend(migration_state.dest_backend_type, false);
            }
        });
        
        // Migration strategy
        ui.horizontal(|ui| {
            ui.label("Migration Strategy:");
            
            let migration_state = self.get_or_create_migration_state();
            
            egui::ComboBox::from_label("")
                .selected_text(&migration_state.migration_strategy)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut migration_state.migration_strategy, "CopyThenDelete".to_string(), "Copy Then Delete");
                    ui.selectable_value(&mut migration_state.migration_strategy, "StreamingMigration".to_string(), "Streaming Migration");
                    ui.selectable_value(&mut migration_state.migration_strategy, "Synchronize".to_string(), "Synchronize");
                    ui.selectable_value(&mut migration_state.migration_strategy, "VerifyOnly".to_string(), "Verify Only");
                });
        });
        
        // Show strategy description
        let strategy_description = match migration_state.migration_strategy.as_str() {
            "CopyThenDelete" => "Copy all data to destination, then optionally delete from source",
            "StreamingMigration" => "Copy data and immediately delete from source (saves space)",
            "Synchronize" => "Bidirectional synchronization between backends",
            "VerifyOnly" => "Verify data integrity without copying",
            _ => "Unknown strategy",
        };
        ui.label(egui::RichText::new(strategy_description).italics().small());
        
        // Advanced options
        ui.collapsing("Advanced Options", |ui| {
            let migration_state = self.get_or_create_migration_state();
            
            ui.horizontal(|ui| {
                ui.label("Batch Size:");
                ui.add(egui::DragValue::new(&mut migration_state.batch_size).range(1..=1000));
                ui.label("chunks per batch");
            });
            
            ui.horizontal(|ui| {
                ui.label("Concurrency:");
                ui.add(egui::DragValue::new(&mut migration_state.concurrency).range(1..=50));
                ui.label("parallel operations");
            });
            
            ui.horizontal(|ui| {
                ui.label("Max Retries:");
                ui.add(egui::DragValue::new(&mut migration_state.max_retries).range(0..=10));
            });
            
            ui.horizontal(|ui| {
                ui.label("Retry Delay (ms):");
                ui.add(egui::DragValue::new(&mut migration_state.retry_delay_ms).range(100..=10000));
            });
            
            ui.checkbox(&mut migration_state.verify_integrity, "Verify data integrity during migration");
            ui.checkbox(&mut migration_state.delete_source, "Delete source data after successful migration");
            
            ui.horizontal(|ui| {
                ui.label("Resume from recipient (optional):");
                ui.text_edit_singleline(&mut migration_state.resume_from_recipient);
            });
        });
    }
    
    /// Render migration action buttons
    fn render_migration_actions(&mut self, ui: &mut egui::Ui) {
        ui.heading("Migration Actions");
        
        ui.horizontal(|ui| {
            let migration_state = self.get_or_create_migration_state();
            
            // Estimate migration
            if ui.button("📊 Estimate Migration").clicked() {
                self.estimate_migration();
            }
            
            // Start migration
            let can_start = !migration_state.migration_running 
                && self.storage_configs.contains_key(&migration_state.source_backend_type)
                && self.storage_configs.contains_key(&migration_state.dest_backend_type);
                
            if ui.add_enabled(can_start, egui::Button::new("🚀 Start Migration")).clicked() {
                self.start_migration();
            }
            
            // Cancel migration
            if ui.add_enabled(migration_state.migration_running, egui::Button::new("⏹️ Cancel Migration")).clicked() {
                self.cancel_migration();
            }
            
            // Clear logs
            if ui.button("🧹 Clear Logs").clicked() {
                migration_state.migration_logs.clear();
            }
        });
    }
    
    /// Render migration progress and status
    fn render_migration_status(&mut self, ui: &mut egui::Ui) {
        let migration_state = self.get_or_create_migration_state();
        
        // Show estimate if available
        if let Some(ref estimate) = migration_state.migration_estimate {
            ui.heading("Migration Estimate");
            ui.horizontal(|ui| {
                ui.label("Total Chunks:");
                ui.label(format!("{}", estimate.total_chunks));
            });
            ui.horizontal(|ui| {
                ui.label("Total Size:");
                ui.label(format!("{:.2} MB", estimate.total_bytes as f64 / 1024.0 / 1024.0));
            });
            ui.horizontal(|ui| {
                ui.label("Estimated Duration:");
                ui.label(format!("{:.1} hours", estimate.estimated_duration_hours));
            });
            ui.separator();
        }
        
        // Show progress if migration is running or completed
        if let Some(ref progress) = migration_state.migration_progress {
            ui.heading("Migration Progress");
            
            // Recipients progress
            if progress.total_recipients > 0 {
                let recipient_fraction = progress.processed_recipients as f32 / progress.total_recipients as f32;
                ui.add(egui::ProgressBar::new(recipient_fraction)
                    .text(format!("Recipients: {}/{}", progress.processed_recipients, progress.total_recipients)));
            }
            
            // Chunks progress
            if progress.total_chunks > 0 {
                let chunk_fraction = progress.processed_chunks as f32 / progress.total_chunks as f32;
                ui.add(egui::ProgressBar::new(chunk_fraction)
                    .text(format!("Chunks: {}/{}", progress.processed_chunks, progress.total_chunks)));
            }
            
            // Current status
            if let Some(ref current_recipient) = progress.current_recipient {
                ui.horizontal(|ui| {
                    ui.label("Current Recipient:");
                    ui.label(current_recipient);
                });
            }
            
            // Statistics
            ui.horizontal(|ui| {
                ui.label("Bytes Transferred:");
                ui.label(format!("{:.2} MB", progress.bytes_transferred as f64 / 1024.0 / 1024.0));
            });
            
            if progress.failed_chunks > 0 {
                ui.horizontal(|ui| {
                    ui.label("Failed Chunks:");
                    ui.colored_label(egui::Color32::RED, format!("{}", progress.failed_chunks));
                });
            }
            
            // Time information
            ui.horizontal(|ui| {
                ui.label("Started:");
                ui.label(progress.start_time.format("%Y-%m-%d %H:%M:%S").to_string());
            });
            
            if let Some(eta) = progress.estimated_completion {
                ui.horizontal(|ui| {
                    ui.label("ETA:");
                    ui.label(eta.format("%Y-%m-%d %H:%M:%S").to_string());
                });
            }
            
            ui.separator();
        }
        
        // Show migration logs
        ui.heading("Migration Logs");
        egui::ScrollArea::vertical()
            .max_height(200.0)
            .auto_shrink([false; 2])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for log in &migration_state.migration_logs {
                    ui.label(log);
                }
            });
    }
    
    /// Get or create migration state
    fn get_or_create_migration_state(&mut self) -> &mut MigrationState {
        // For simplicity, we'll store migration state as part of AppState
        // In a real implementation, you might want a separate migration state structure
        
        // This is a placeholder - in real implementation you'd have proper state management
        static mut MIGRATION_STATE: Option<MigrationState> = None;
        
        unsafe {
            if MIGRATION_STATE.is_none() {
                MIGRATION_STATE = Some(MigrationState {
                    source_backend_type: StorageType::Local,
                    dest_backend_type: StorageType::Local,
                    migration_strategy: "CopyThenDelete".to_string(),
                    batch_size: 50,
                    concurrency: 10,
                    verify_integrity: true,
                    delete_source: false,
                    resume_from_recipient: String::new(),
                    max_retries: 3,
                    retry_delay_ms: 1000,
                    ..Default::default()
                });
            }
            
            MIGRATION_STATE.as_mut().unwrap()
        }
    }
    
    /// Test a migration backend connection
    fn test_migration_backend(&mut self, backend_type: StorageType, is_source: bool) {
        let backend_name = if is_source { "source" } else { "destination" };
        
        if let Some(config) = self.storage_configs.get(&backend_type) {
            let storage_config = self.convert_gui_to_storage_config(backend_type, config);
            
            self.log(&format!("Testing {} backend connection...", backend_name));
            
            let logs = self.logs.clone();
            tokio::spawn(async move {
                match crate::storage::factory::StorageFactory::create_backend(storage_config).await {
                    Ok(backend) => {
                        match backend.test_connection().await {
                            Ok(_) => {
                                if let Ok(mut l) = logs.lock() {
                                    l.push(format!("✅ {} backend connection successful!", backend_name));
                                }
                            }
                            Err(e) => {
                                if let Ok(mut l) = logs.lock() {
                                    l.push(format!("❌ {} backend connection failed: {}", backend_name, e));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if let Ok(mut l) = logs.lock() {
                            l.push(format!("❌ Failed to create {} backend: {}", backend_name, e));
                        }
                    }
                }
            });
        } else {
            self.log(&format!("No configuration found for {} backend", backend_name));
        }
    }
    
    /// Estimate migration time and resources
    fn estimate_migration(&mut self) {
        let migration_state = self.get_or_create_migration_state();
        
        if let (Some(source_config), Some(dest_config)) = (
            self.storage_configs.get(&migration_state.source_backend_type),
            self.storage_configs.get(&migration_state.dest_backend_type)
        ) {
            let source_storage_config = self.convert_gui_to_storage_config(migration_state.source_backend_type, source_config);
            let dest_storage_config = self.convert_gui_to_storage_config(migration_state.dest_backend_type, dest_config);
            
            self.log("Estimating migration...");
            
            let logs = self.logs.clone();
            tokio::spawn(async move {
                match MigrationUtils::estimate_migration(&source_storage_config, &dest_storage_config).await {
                    Ok(estimate) => {
                        if let Ok(mut l) = logs.lock() {
                            l.push(format!("📊 Migration estimate: {} chunks, {:.2} MB, {:.1} hours", 
                                estimate.total_chunks, 
                                estimate.total_bytes as f64 / 1024.0 / 1024.0,
                                estimate.estimated_duration_hours));
                        }
                    }
                    Err(e) => {
                        if let Ok(mut l) = logs.lock() {
                            l.push(format!("Failed to estimate migration: {}", e));
                        }
                    }
                }
            });
        }
    }
    
    /// Start the migration process
    fn start_migration(&mut self) {
        let migration_state = self.get_or_create_migration_state();
        
        if let (Some(source_config), Some(dest_config)) = (
            self.storage_configs.get(&migration_state.source_backend_type),
            self.storage_configs.get(&migration_state.dest_backend_type)
        ) {
            let source_storage_config = self.convert_gui_to_storage_config(migration_state.source_backend_type, source_config);
            let dest_storage_config = self.convert_gui_to_storage_config(migration_state.dest_backend_type, dest_config);
            
            let strategy = match migration_state.migration_strategy.as_str() {
                "StreamingMigration" => MigrationStrategy::StreamingMigration,
                "Synchronize" => MigrationStrategy::Synchronize,
                "VerifyOnly" => MigrationStrategy::VerifyOnly,
                _ => MigrationStrategy::CopyThenDelete,
            };
            
            let migration_config = MigrationConfig {
                source: source_storage_config,
                destination: dest_storage_config,
                strategy,
                batch_size: migration_state.batch_size as usize,
                concurrency: migration_state.concurrency as usize,
                verify_integrity: migration_state.verify_integrity,
                delete_source: migration_state.delete_source,
                resume_from_recipient: if migration_state.resume_from_recipient.is_empty() { 
                    None 
                } else { 
                    Some(migration_state.resume_from_recipient.clone()) 
                },
                max_retries: migration_state.max_retries,
                retry_delay_ms: migration_state.retry_delay_ms,
            };
            
            self.log("Starting migration...");
            migration_state.migration_running = true;
            
            let logs = self.logs.clone();
            tokio::spawn(async move {
                match StorageMigrationManager::new(migration_config).await {
                    Ok(manager) => {
                        let manager = Arc::new(manager);
                        
                        // Start migration
                        match manager.migrate().await {
                            Ok(final_progress) => {
                                if let Ok(mut l) = logs.lock() {
                                    l.push(format!("✅ Migration completed successfully! Processed {} chunks", 
                                        final_progress.processed_chunks));
                                }
                            }
                            Err(e) => {
                                if let Ok(mut l) = logs.lock() {
                                    l.push(format!("❌ Migration failed: {}", e));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if let Ok(mut l) = logs.lock() {
                            l.push(format!("Failed to create migration manager: {}", e));
                        }
                    }
                }
            });
        }
    }
    
    /// Cancel the migration
    fn cancel_migration(&mut self) {
        let migration_state = self.get_or_create_migration_state();
        
        if let Some(ref manager) = migration_state.migration_manager {
            manager.cancel();
            migration_state.migration_running = false;
            self.log("Migration cancelled by user");
        }
    }
    
    /// Convert GUI config to storage config (placeholder)
    fn convert_gui_to_storage_config(
        &self, 
        backend_type: StorageType, 
        gui_config: &crate::gui::state::StorageBackendConfig
    ) -> StorageConfig {
        // This would use the same logic as in storage_widgets.rs
        // For now, return a basic config
        StorageConfig {
            backend_type,
            ..Default::default()
        }
    }
}