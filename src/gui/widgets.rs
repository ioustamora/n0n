use eframe::egui;
use std::sync::atomic::Ordering;
use base64::Engine;
use crate::gui::state::AppState;
use crate::gui::backup_widgets;
use crate::crypto;

impl AppState {
    pub fn render_keypair_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label("Keys (base64)");
            ui.horizontal(|ui| {
                ui.label("Recipient public key:");
                ui.text_edit_singleline(&mut self.recipient_pk);
            });
            ui.horizontal(|ui| {
                ui.label("Recipient secret key:");
                ui.text_edit_singleline(&mut self.recipient_sk);
            });
            if ui.button("Generate keypair").clicked() {
                crypto::init();
                let (pk, sk) = crypto::generate_keypair();
                let pk_b64 = base64::engine::general_purpose::STANDARD.encode(pk.0);
                let sk_b64 = base64::engine::general_purpose::STANDARD.encode(&sk.0);
                self.recipient_pk = pk_b64;
                self.recipient_sk = sk_b64;
                self.log("Generated new keypair");
            }
        });
    }

    pub fn render_storage_backend_section(&mut self, ui: &mut egui::Ui) {
        // Use the enhanced storage section
        self.render_enhanced_storage_section(ui);
        
        // Legacy output directory setting (still useful for some workflows)
        ui.horizontal(|ui| {
            ui.label("Output/mailbox dir:");
            ui.text_edit_singleline(&mut self.output_dir);
            if ui.button("Browse").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.output_dir = path.display().to_string();
                }
            }
            if ui.button("Open").clicked()
                && !self.output_dir.is_empty() {
                    let p = std::path::PathBuf::from(self.output_dir.clone());
                    let _ = crate::gui::open_folder_in_os(&p);
            }
        });
    }

    pub fn render_sftp_section(&mut self, ui: &mut egui::Ui) {
        // This section is now integrated into the enhanced storage section
        // We keep this method for backward compatibility but it's largely empty
        use crate::storage::backend::StorageType;
        
        if self.storage_backend_type == StorageType::Sftp {
            ui.label("SFTP configuration is now handled in the Storage Backend section above.");
        }
    }

    pub fn render_progress_section(&mut self, ui: &mut egui::Ui) {
        if let (Some(total), Some(done)) = (&self.job_progress_total, &self.job_progress_done) {
            let total_val = total.load(Ordering::Relaxed);
            let done_val = done.load(Ordering::Relaxed);
            
            if total_val > 0 {
                let fraction = done_val as f32 / total_val as f32;
                ui.add(egui::ProgressBar::new(fraction).text(format!("{}/{} chunks", done_val, total_val)));
                
                if !self.job_last_label.is_empty() {
                    ui.label(&self.job_last_label);
                }
            }
        }
    }

    pub fn render_logs_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label("Logs");
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .auto_shrink([false; 2])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    if let Ok(logs) = self.logs.lock() {
                        for log in logs.iter() {
                            ui.label(log);
                        }
                    }
                });
            
            if ui.button("Clear Logs").clicked() {
                if let Ok(mut logs) = self.logs.lock() {
                    logs.clear();
                }
            }
        });
    }

    pub fn render_backup_section(&mut self, ui: &mut egui::Ui) {
        // Initialize backup state if not already done
        if self.backup_state.is_none() {
            self.backup_state = Some(backup_widgets::BackupWidgetState::new());
        }

        if let Some(backup_state) = &mut self.backup_state {
            backup_widgets::render_backup_section(ui, backup_state);
        }
    }

    pub fn render_crypto_management_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label("🔐 Enterprise Cryptographic Management");
            ui.separator();
            
            ui.horizontal(|ui| {
                if ui.selectable_label(true, "🔑 Key Management").clicked() {
                    // Key management tab is selected by default
                }
                ui.separator();
                if ui.selectable_label(false, "📜 Certificate Management").clicked() {
                    // Switch to certificate management tab
                }
                ui.separator();
                if ui.selectable_label(false, "🧮 Advanced Crypto Operations").clicked() {
                    // Switch to advanced crypto operations tab
                }
            });
            
            ui.separator();
            
            // For now, show all tabs in a collapsing header format
            ui.collapsing("🔑 Key Management", |ui| {
                self.key_management_widget.ui(ui);
            });
            
            ui.collapsing("📜 Certificate Management", |ui| {
                self.certificate_management_widget.ui(ui);
            });
            
            ui.collapsing("🧮 Advanced Crypto Operations", |ui| {
                self.advanced_crypto_widget.ui(ui);
            });
        });
    }
}