use eframe::egui;
use std::sync::Arc;
use crate::gui::state::AppState;
use crate::storage::backend::{StorageType, StorageConfig};
use crate::storage::migration::{
    StorageMigrationManager, MigrationConfig, MigrationStrategy, MigrationProgress, 
    MigrationUtils, MigrationEstimate
};

/// Migration state for the GUI
#[derive(Default, Clone)]
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

        let mut migration_state = self.get_migration_state();
        let mut changed = false;

        // Source backend selection
        ui.horizontal(|ui| {
            ui.label("Source Backend:");

            let current_source = migration_state.source_backend_type;

            egui::ComboBox::from_label("")
                .selected_text(format!("{:?}", migration_state.source_backend_type))
                .show_ui(ui, |ui| {
                    for backend_type in crate::storage::factory::StorageFactory::available_backends() {
                        if ui.selectable_value(&mut migration_state.source_backend_type, backend_type, format!("{:?}", backend_type)).changed() {
                            changed = true;
                        }
                    }
                });

            // Test button needs to be outside the mutable borrow
            let should_test = ui.button("Test Source").clicked();
            if should_test {
                self.test_migration_backend(current_source, true);
            }
        });

        // Destination backend selection
        ui.horizontal(|ui| {
            ui.label("Destination Backend:");

            let current_dest = migration_state.dest_backend_type;

            egui::ComboBox::from_label("")
                .selected_text(format!("{:?}", migration_state.dest_backend_type))
                .show_ui(ui, |ui| {
                    for backend_type in crate::storage::factory::StorageFactory::available_backends() {
                        if ui.selectable_value(&mut migration_state.dest_backend_type, backend_type, format!("{:?}", backend_type)).changed() {
                            changed = true;
                        }
                    }
                });

            // Test button needs to be outside the mutable borrow
            let should_test = ui.button("Test Destination").clicked();
            if should_test {
                self.test_migration_backend(current_dest, false);
            }
        });

        // Migration strategy
        ui.horizontal(|ui| {
            ui.label("Migration Strategy:");

            if egui::ComboBox::from_label("")
                .selected_text(&migration_state.migration_strategy)
                .show_ui(ui, |ui| {
                    let mut combo_changed = false;
                    if ui.selectable_value(&mut migration_state.migration_strategy, "CopyThenDelete".to_string(), "Copy Then Delete").changed() { combo_changed = true; }
                    if ui.selectable_value(&mut migration_state.migration_strategy, "StreamingMigration".to_string(), "Streaming Migration").changed() { combo_changed = true; }
                    if ui.selectable_value(&mut migration_state.migration_strategy, "Synchronize".to_string(), "Synchronize").changed() { combo_changed = true; }
                    if ui.selectable_value(&mut migration_state.migration_strategy, "VerifyOnly".to_string(), "Verify Only").changed() { combo_changed = true; }
                    combo_changed
                }).inner.unwrap_or(false) {
                    changed = true;
                }


            // Show strategy description
            let strategy_description = match migration_state.migration_strategy.as_str() {
                "CopyThenDelete" => "Copy all data to destination, then optionally delete from source",
                "StreamingMigration" => "Copy data and immediately delete from source (saves space)",
                "Synchronize" => "Bidirectional synchronization between backends",
                "VerifyOnly" => "Verify data integrity without copying",
                _ => "Unknown strategy",
            };
            ui.label(egui::RichText::new(strategy_description).italics().small());
        });

        // Advanced options
        ui.collapsing("Advanced Options", |ui| {
            ui.horizontal(|ui| {
                ui.label("Batch Size:");
                if ui.add(egui::DragValue::new(&mut migration_state.batch_size).clamp_range(1..=1000)).changed() { changed = true; }
                ui.label("chunks per batch");
            });

            ui.horizontal(|ui| {
                ui.label("Concurrency:");
                if ui.add(egui::DragValue::new(&mut migration_state.concurrency).clamp_range(1..=50)).changed() { changed = true; }
                ui.label("parallel operations");
            });

            ui.horizontal(|ui| {
                ui.label("Max Retries:");
                if ui.add(egui::DragValue::new(&mut migration_state.max_retries).clamp_range(0..=10)).changed() { changed = true; }
            });

            ui.horizontal(|ui| {
                ui.label("Retry Delay (ms):");
                if ui.add(egui::DragValue::new(&mut migration_state.retry_delay_ms).clamp_range(100..=10000)).changed() { changed = true; }
            });

            if ui.checkbox(&mut migration_state.verify_integrity, "Verify data integrity during migration").changed() { changed = true; }
            if ui.checkbox(&mut migration_state.delete_source, "Delete source data after successful migration").changed() { changed = true; }

            ui.horizontal(|ui| {
                ui.label("Resume from recipient (optional):");
                if ui.text_edit_singleline(&mut migration_state.resume_from_recipient).changed() { changed = true; }
            });
        });

        if changed {
            self.update_migration_state(|state| {
                *state = migration_state;
            });
        }
    }
    
    /// Render migration action buttons
    fn render_migration_actions(&mut self, ui: &mut egui::Ui) {
        ui.heading("Migration Actions");

        ui.horizontal(|ui| {
            let migration_state = self.get_migration_state();

            // Get values we need before calling other methods
            let migration_running = migration_state.migration_running;
            let source_type = migration_state.source_backend_type;
            let dest_type = migration_state.dest_backend_type;

            // Estimate migration
            if ui.button("📊 Estimate Migration").clicked() {
                self.estimate_migration();
            }

            // Start migration
            let can_start = !migration_running
                && self.storage_configs.contains_key(&source_type)
                && self.storage_configs.contains_key(&dest_type);

            if ui.add_enabled(can_start, egui::Button::new("🚀 Start Migration")).clicked() {
                self.start_migration();
            }

            // Cancel migration
            if ui.add_enabled(migration_running, egui::Button::new("⏹️ Cancel Migration")).clicked() {
                self.cancel_migration();
            }

            // Clear logs
            if ui.button("🧹 Clear Logs").clicked() {
                self.update_migration_state(|state| {
                    state.migration_logs.clear();
                });
            }
        });
    }
    
    /// Render migration progress and status
    fn render_migration_status(&mut self, ui: &mut egui::Ui) {
        let migration_state = self.get_migration_state();

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
    

    
    fn get_migration_state(&self) -> MigrationState {
        self.migration_state.lock().unwrap().clone()
    }

    fn update_migration_state<F>(&mut self, f: F)
    where
        F: FnOnce(&mut MigrationState),
    {
        let mut guard = self.migration_state.lock().unwrap();
        f(&mut guard)
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
        let migration_state = self.get_migration_state();
        let source_type = migration_state.source_backend_type;
        let dest_type = migration_state.dest_backend_type;

        if let (Some(source_config), Some(dest_config)) = (
            self.storage_configs.get(&source_type),
            self.storage_configs.get(&dest_type)
        ) {
            let source_storage_config = self.convert_gui_to_storage_config(source_type, source_config);
            let dest_storage_config = self.convert_gui_to_storage_config(dest_type, dest_config);

            self.log("Estimating migration...");

            let logs = self.logs.clone();
            let migration_state_clone = self.migration_state.clone();
            tokio::spawn(async move {
                match MigrationUtils::estimate_migration(&source_storage_config, &dest_storage_config).await {
                    Ok(estimate) => {
                        if let Ok(mut l) = logs.lock() {
                            l.push(format!("📊 Migration estimate: {} chunks, {:.2} MB, {:.1} hours",
                                estimate.total_chunks,
                                estimate.total_bytes as f64 / 1024.0 / 1024.0,
                                estimate.estimated_duration_hours));
                        }
                        let mut guard = migration_state_clone.lock().unwrap();
                        guard.migration_estimate = Some(estimate);
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
        // Extract all needed values from migration_state before other method calls
        let (source_type, dest_type, migration_strategy, batch_size, concurrency,
                verify_integrity, delete_source, resume_from_recipient, max_retries, retry_delay_ms) = {
            let migration_state = self.get_migration_state();
            (
                migration_state.source_backend_type,
                migration_state.dest_backend_type,
                migration_state.migration_strategy.clone(),
                migration_state.batch_size,
                migration_state.concurrency,
                migration_state.verify_integrity,
                migration_state.delete_source,
                migration_state.resume_from_recipient.clone(),
                migration_state.max_retries,
                migration_state.retry_delay_ms,
            )
        };

        if let (Some(source_config), Some(dest_config)) = (
            self.storage_configs.get(&source_type),
            self.storage_configs.get(&dest_type)
        ) {
            let source_storage_config = self.convert_gui_to_storage_config(source_type, source_config);
            let dest_storage_config = self.convert_gui_to_storage_config(dest_type, dest_config);

            let strategy = match migration_strategy.as_str() {
                "StreamingMigration" => MigrationStrategy::StreamingMigration,
                "Synchronize" => MigrationStrategy::Synchronize,
                "VerifyOnly" => MigrationStrategy::VerifyOnly,
                _ => MigrationStrategy::CopyThenDelete,
            };

            let migration_config = MigrationConfig {
                source: source_storage_config,
                destination: dest_storage_config,
                strategy,
                batch_size: batch_size as usize,
                concurrency: concurrency as usize,
                verify_integrity,
                delete_source,
                resume_from_recipient: if resume_from_recipient.is_empty() {
                    None
                } else {
                    Some(resume_from_recipient)
                },
                max_retries,
                retry_delay_ms,
            };

            // Set migration running flag
            self.update_migration_state(|state| {
                state.migration_running = true;
            });

            self.log("Starting migration...");

            let logs = self.logs.clone();
            let migration_state_clone = self.migration_state.clone();
            tokio::spawn(async move {
                match StorageMigrationManager::new(migration_config).await {
                    Ok(manager) => {
                        let manager = Arc::new(manager);
                        
                        migration_state_clone.lock().unwrap().migration_manager = Some(manager.clone());

                        // Start migration
                        match manager.migrate().await {
                            Ok(final_progress) => {
                                if let Ok(mut l) = logs.lock() {
                                    l.push(format!("✅ Migration completed successfully! Processed {} chunks",
                                        final_progress.processed_chunks));
                                }
                                let mut guard = migration_state_clone.lock().unwrap();
                                guard.migration_progress = Some(final_progress);
                                guard.migration_running = false;
                            }
                            Err(e) => {
                                if let Ok(mut l) = logs.lock() {
                                    l.push(format!("❌ Migration failed: {}", e));
                                }
                                let mut guard = migration_state_clone.lock().unwrap();
                                guard.migration_running = false;
                            }
                        }
                    }
                    Err(e) => {
                        if let Ok(mut l) = logs.lock() {
                            l.push(format!("Failed to create migration manager: {}", e));
                        }
                        let mut guard = migration_state_clone.lock().unwrap();
                        guard.migration_running = false;
                    }
                }
            });
        }
    }
    
    /// Cancel the migration
    fn cancel_migration(&mut self) {
        self.update_migration_state(|state| {
            if let Some(ref manager) = state.migration_manager {
                manager.cancel();
                state.migration_running = false;
            }
        });
        self.log("Migration cancelled by user");
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