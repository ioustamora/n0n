use eframe::egui;
use std::sync::atomic::Ordering;
use base64::Engine;
use crate::gui::state::AppState;
use crate::{storage, crypto};

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
        ui.horizontal(|ui| {
            ui.label("Storage backend:");
            ui.radio_value(&mut self.storage_backend, 0, "Local");
            ui.radio_value(&mut self.storage_backend, 1, "SFTP");
        });
        
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
        if self.storage_backend == 1 {
            ui.group(|ui| {
                ui.label("SFTP Configuration");
                ui.horizontal(|ui| { 
                    ui.label("Host (host:port):"); 
                    ui.text_edit_singleline(&mut self.sftp_host); 
                });
                ui.horizontal(|ui| { 
                    ui.label("Username:"); 
                    ui.text_edit_singleline(&mut self.sftp_user); 
                });
                ui.horizontal(|ui| { 
                    ui.label("Password:"); 
                    ui.text_edit_singleline(&mut self.sftp_pass); 
                });
                ui.horizontal(|ui| { 
                    ui.label("Remote base path:"); 
                    ui.text_edit_singleline(&mut self.sftp_base); 
                });
                ui.horizontal(|ui| { 
                    ui.label("Mailbox ID:"); 
                    ui.text_edit_singleline(&mut self.sftp_mailbox_id); 
                });
                
                // Test connection button
                if ui.button("Test Connection").clicked() {
                    self.log("Testing SFTP connection...");
                    let host = self.sftp_host.clone();
                    let user = self.sftp_user.clone();
                    let pass = self.sftp_pass.clone();
                    let base = self.sftp_base.clone();
                    let pk = self.sftp_private_key.clone();
                    let pk_pass = self.sftp_private_key_pass.clone();
                    let host_fp = self.sftp_host_fingerprint_sha256_b64.clone();
                    let logs = self.logs.clone();
                    std::thread::spawn(move || {
                        crate::crypto::init();
                        let res = if !pk.is_empty() || !host_fp.is_empty() {
                            storage::test_sftp_connection_auth(
                                &host,
                                &user,
                                if pass.is_empty() { None } else { Some(&pass) },
                                if pk.is_empty() { None } else { Some(&pk) },
                                if pk_pass.is_empty() { None } else { Some(&pk_pass) },
                                if host_fp.is_empty() { None } else { Some(&host_fp) },
                                &base,
                            )
                        } else {
                            storage::test_sftp_connection(&host, &user, &pass, &base)
                        };
                        
                        if let Ok(mut l) = logs.lock() {
                            match res {
                                Ok(()) => l.push("SFTP connection successful!".to_string()),
                                Err(e) => l.push(format!("SFTP connection failed: {}", e)),
                            }
                        }
                    });
                }
            });
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
}