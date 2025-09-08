use eframe::egui;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use crate::model::{ProcessingOptions, StorageBackend};
use anyhow::Result;
use std::thread;
use crate::storage;
use crate::crypto;

#[derive(Default)]
pub struct AppState {
    pub selected_file: Option<PathBuf>,
    pub selected_folder: Option<PathBuf>,
    pub recipient_pk: String,
    pub sender_sk: String,
    pub chunk_size_mb: u32,
    pub output_dir: String,
    pub auto_watch: bool,
    pub storage_backend: usize,
    pub logs: Arc<Mutex<Vec<String>>>,
}

impl AppState {
    fn log(&self, s: &str) {
        if let Ok(mut l) = self.logs.lock() {
            l.push(s.to_owned());
            if l.len() > 1000 { l.drain(0..100); }
        }
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("n0n — secure file chunking & mailbox");

            ui.horizontal(|ui| {
                if ui.button("Select File").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.selected_file = Some(path);
                        self.log("Selected file");
                    }
                }

                if ui.button("Select Folder").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        self.selected_folder = Some(path);
                        self.log("Selected folder");
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("Recipient public key (base64/hex):");
                ui.text_edit_singleline(&mut self.recipient_pk);
            });

            ui.horizontal(|ui| {
                ui.label("Sender private key (optional):");
                ui.text_edit_singleline(&mut self.sender_sk);
            });

            ui.horizontal(|ui| {
                ui.label("Chunk size (MB):");
                ui.add(egui::DragValue::new(&mut self.chunk_size_mb).clamp_range(1..=1024));
                ui.label("Output dir:");
                ui.text_edit_singleline(&mut self.output_dir);
            });

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.auto_watch, "Auto-process watched folder");
                ui.label("Storage backend:");
                ui.selectable_value(&mut self.storage_backend, 0, "Local");
                ui.selectable_value(&mut self.storage_backend, 1, "SFTP (placeholder)");
            });

            ui.horizontal(|ui| {
                if ui.button("Split & Encrypt").clicked() {
                    let logs = self.logs.clone();
                    let selected_file = self.selected_file.clone();
                    let selected_folder = self.selected_folder.clone();
                    let recipient = self.recipient_pk.clone();
                    let sender = if self.sender_sk.is_empty() { None } else { Some(self.sender_sk.clone()) };
                    let output = PathBuf::from(self.output_dir.clone());
                    let _chunk_mb = self.chunk_size_mb;

                    self.log("Starting background encryption...");
                    thread::spawn(move || {
                        // initialize crypto
                        crypto::init();
                        let log = |s: &str| {
                            if let Ok(mut l) = logs.lock() { l.push(s.to_string()); }
                        };

                        if let Some(file) = selected_file {
                            log(&format!("Encrypting file: {:?}", file));
                            let _ = storage::process_file_encrypt(&file, &file.parent().unwrap_or(&output), &recipient, sender.as_deref(), &output);
                            log("File encryption completed");
                        } else if let Some(folder) = selected_folder {
                            log(&format!("Encrypting folder: {:?}", folder));
                            // walk folder recursively
                            for entry in walkdir::WalkDir::new(&folder).into_iter().filter_map(|e| e.ok()) {
                                if entry.file_type().is_file() {
                                    let path = entry.path().to_path_buf();
                                    let _ = storage::process_file_encrypt(&path, &folder, &recipient, sender.as_deref(), &output);
                                    log(&format!("Encrypted {:?}", path));
                                }
                            }
                            log("Folder encryption completed");
                        } else {
                            log("No file or folder selected");
                        }
                    });
                }
                if ui.button("Assemble & Decrypt").clicked() {
                    let output = PathBuf::from(self.output_dir.clone());
                    let mailbox = self.selected_folder.clone().unwrap_or_else(|| output.clone());
                    let recipient_sk = self.recipient_pk.clone();
                    self.log("Starting assemble in background...");
                    let logs_clone = self.logs.clone();
                    std::thread::spawn(move || {
                        let _ = crypto::init();
                        if let Ok(mut l) = logs_clone.lock() { l.push("Assembling from mailbox...".to_string()); }
                        let logs_for_call = logs_clone.clone();
                        let _ = storage::assemble_from_mailbox_with_logs(&mailbox, &recipient_sk, &output, logs_for_call);
                        if let Ok(mut l) = logs_clone.lock() { l.push("Assemble complete".to_string()); }
                    });
                }
            });

            ui.separator();
            ui.label("Logs:");
            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                if let Ok(l) = self.logs.lock() {
                    for line in l.iter() {
                        ui.label(line);
                    }
                }
            });
        });
    }
}

pub fn run_gui() -> Result<()> {
    let options = eframe::NativeOptions::default();
    let app = AppState { chunk_size_mb: 10, ..Default::default() };
    let _ = eframe::run_native("n0n", options, Box::new(|_cc| Box::new(app)));
    Ok(())
}
