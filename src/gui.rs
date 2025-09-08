use eframe::egui;
use base64::Engine as _;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use anyhow::Result;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering, AtomicUsize};
use notify::{recommended_watcher, RecursiveMode, Watcher};
use crate::storage;
use crate::search;
use crate::crypto;

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
    pub storage_backend: usize,
    pub logs: Arc<Mutex<Vec<String>>>,
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
    // simple search
    pub search_hash: String,
    pub search_base: String,
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

            ui.group(|ui| {
                ui.label("Keys");
                ui.horizontal(|ui| {
                    ui.label("Recipient public key (encrypt):");
                    ui.text_edit_singleline(&mut self.recipient_pk);
                });
                ui.horizontal(|ui| {
                    ui.label("Recipient private key (assemble):");
                    ui.text_edit_singleline(&mut self.recipient_sk);
                });
                if ui.button("Generate keypair").clicked() {
                    crypto::init();
                    let (pk, sk) = crypto::generate_keypair();
                    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&pk.0);
                    let sk_b64 = base64::engine::general_purpose::STANDARD.encode(&sk.0);
                    self.recipient_pk = pk_b64;
                    self.recipient_sk = sk_b64;
                    self.log("Generated new keypair");
                }
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
                ui.selectable_value(&mut self.storage_backend, 1, "SFTP");
            });

    if self.storage_backend == 1 {
                ui.group(|ui| {
                    ui.label("SFTP Settings");
                    ui.horizontal(|ui| { ui.label("Host (host:port):"); ui.text_edit_singleline(&mut self.sftp_host); });
                    ui.horizontal(|ui| { ui.label("User:"); ui.text_edit_singleline(&mut self.sftp_user); });
                    ui.horizontal(|ui| { ui.label("Password:"); ui.text_edit_singleline(&mut self.sftp_pass); });
            ui.horizontal(|ui| { ui.label("Private key path (PEM/OpenSSH):"); ui.text_edit_singleline(&mut self.sftp_private_key); });
            ui.horizontal(|ui| { ui.label("Private key passphrase:"); ui.text_edit_singleline(&mut self.sftp_private_key_pass); });
            ui.horizontal(|ui| { ui.label("Host key SHA-256 (base64) optional:"); ui.text_edit_singleline(&mut self.sftp_host_fingerprint_sha256_b64); });
            ui.horizontal(|ui| { ui.checkbox(&mut self.sftp_require_host_fp, "Require host fingerprint"); });
                    ui.horizontal(|ui| { ui.label("Remote base path:"); ui.text_edit_singleline(&mut self.sftp_base); });
            ui.horizontal(|ui| { ui.label("Mailbox ID (folder name):"); ui.text_edit_singleline(&mut self.sftp_mailbox_id); });
            ui.label("Note: defaults to recipient key string if empty.");
                });
            }

            ui.horizontal(|ui| {
                if ui.button("Split & Encrypt").clicked() {
                    let logs = self.logs.clone();
                    let selected_file = self.selected_file.clone();
                    let selected_folder = self.selected_folder.clone();
                    let recipient = self.recipient_pk.clone();
                    let sender = if self.sender_sk.is_empty() { None } else { Some(self.sender_sk.clone()) };
                    let output = PathBuf::from(self.output_dir.clone());
                    let chunk_mb = self.chunk_size_mb;
                    let sftp_host = self.sftp_host.clone();
                    let sftp_user = self.sftp_user.clone();
                    let sftp_pass = self.sftp_pass.clone();
                    let sftp_base = self.sftp_base.clone();
                    let sftp_pk = self.sftp_private_key.clone();
                    let sftp_pk_pass = self.sftp_private_key_pass.clone();
                    let sftp_host_fp = self.sftp_host_fingerprint_sha256_b64.clone();
                    let sftp_require_host_fp = self.sftp_require_host_fp;
                    let backend = self.storage_backend;
                    let mailbox_id = if self.sftp_mailbox_id.trim().is_empty() { self.recipient_pk.clone() } else { self.sftp_mailbox_id.clone() };

                    if backend == 1 && sftp_require_host_fp && sftp_host_fp.trim().is_empty() {
                        self.log("Host fingerprint required but not provided");
                    } else {
                        // initialize job progress state
                        let total = Arc::new(AtomicUsize::new(0));
                        let done = Arc::new(AtomicUsize::new(0));
                        let cancel = Arc::new(AtomicBool::new(false));
                        self.job_progress_total = Some(total.clone());
                        self.job_progress_done = Some(done.clone());
                        self.job_cancel = Some(cancel.clone());
                        self.job_running = true;
                        self.job_last_label = selected_file
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .or_else(|| selected_folder.as_ref().map(|p| p.display().to_string()))
                            .unwrap_or_else(|| "job".to_string());

                        self.log("Starting background encryption...");
                        thread::spawn(move || {
                            let _ = crypto::init();
                            let log = |s: &str| {
                                if let Ok(mut l) = logs.lock() { l.push(s.to_string()); }
                            };

                            if let Some(file) = selected_file {
                                log(&format!("Encrypting file: {:?}", file));
                                let chunk_bytes = (chunk_mb as usize) * 1024 * 1024;
                                if backend == 0 {
                                    let _ = storage::process_file_encrypt(&file, &file.parent().unwrap_or(&output), &recipient, sender.as_deref(), &output, chunk_bytes, Some((total.clone(), done.clone())), Some(cancel.clone()));
                                } else {
                                    if !sftp_pk.is_empty() || !sftp_host_fp.is_empty() {
                                        let pw_opt = if sftp_pass.is_empty() { None } else { Some(sftp_pass.as_str()) };
                                        let pk_opt = if sftp_pk.is_empty() { None } else { Some(sftp_pk.as_str()) };
                                        let pk_pass_opt = if sftp_pk_pass.is_empty() { None } else { Some(sftp_pk_pass.as_str()) };
                                        let hostfp_opt = if sftp_host_fp.is_empty() { None } else { Some(sftp_host_fp.as_str()) };
                                        let _ = storage::process_file_encrypt_to_sftp_auth(&file, &file.parent().unwrap_or(&output), &recipient, &mailbox_id, sender.as_deref(), &sftp_host, &sftp_user, pw_opt, pk_opt, pk_pass_opt, hostfp_opt, &sftp_base, chunk_bytes, Some((total.clone(), done.clone())), Some(cancel.clone()));
                                    } else {
                                        let _ = storage::process_file_encrypt_to_sftp(&file, &file.parent().unwrap_or(&output), &recipient, &mailbox_id, sender.as_deref(), &sftp_host, &sftp_user, &sftp_pass, &sftp_base, chunk_bytes, Some((total.clone(), done.clone())), Some(cancel.clone()));
                                    }
                                }
                                log("File encryption completed");
                            } else if let Some(folder) = selected_folder {
                                log(&format!("Encrypting folder: {:?}", folder));
                                for entry in walkdir::WalkDir::new(&folder).into_iter().filter_map(|e| e.ok()) {
                                    if entry.file_type().is_file() {
                                        let path = entry.path().to_path_buf();
                                        let chunk_bytes = (chunk_mb as usize) * 1024 * 1024;
                                        if backend == 0 {
                                            let _ = storage::process_file_encrypt(&path, &folder, &recipient, sender.as_deref(), &output, chunk_bytes, None, None);
                                        } else {
                                            if !sftp_pk.is_empty() || !sftp_host_fp.is_empty() {
                                                let pw_opt = if sftp_pass.is_empty() { None } else { Some(sftp_pass.as_str()) };
                                                let pk_opt = if sftp_pk.is_empty() { None } else { Some(sftp_pk.as_str()) };
                                                let pk_pass_opt = if sftp_pk_pass.is_empty() { None } else { Some(sftp_pk_pass.as_str()) };
                                                let hostfp_opt = if sftp_host_fp.is_empty() { None } else { Some(sftp_host_fp.as_str()) };
                                                let _ = storage::process_file_encrypt_to_sftp_auth(&path, &folder, &recipient, &mailbox_id, sender.as_deref(), &sftp_host, &sftp_user, pw_opt, pk_opt, pk_pass_opt, hostfp_opt, &sftp_base, chunk_bytes, None, None);
                                            } else {
                                                let _ = storage::process_file_encrypt_to_sftp(&path, &folder, &recipient, &mailbox_id, sender.as_deref(), &sftp_host, &sftp_user, &sftp_pass, &sftp_base, chunk_bytes, None, None);
                                            }
                                        }
                                        log(&format!("Encrypted {:?}", path));
                                    }
                                }
                                log("Folder encryption completed");
                            } else {
                                log("No file or folder selected");
                            }
                        });
                    }
                }
                if ui.button("Assemble & Decrypt").clicked() {
                    let output = PathBuf::from(self.output_dir.clone());
                    let mailbox = self.selected_folder.clone().unwrap_or_else(|| output.clone());
                    let recipient_sk = self.recipient_sk.clone();
                    let sftp_host = self.sftp_host.clone();
                    let sftp_user = self.sftp_user.clone();
                    let sftp_pass = self.sftp_pass.clone();
                    let sftp_base = self.sftp_base.clone();
                    let sftp_pk = self.sftp_private_key.clone();
                    let sftp_pk_pass = self.sftp_private_key_pass.clone();
                    let sftp_host_fp = self.sftp_host_fingerprint_sha256_b64.clone();
                    let sftp_require_host_fp = self.sftp_require_host_fp;
                    let backend = self.storage_backend;
                    let mailbox_id = if self.sftp_mailbox_id.trim().is_empty() { self.recipient_pk.clone() } else { self.sftp_mailbox_id.clone() };
                    if backend == 1 && sftp_require_host_fp && sftp_host_fp.trim().is_empty() {
                        self.log("Host fingerprint required but not provided");
                    } else {
                    self.log("Starting assemble in background...");
                    let logs_clone = self.logs.clone();
                    std::thread::spawn(move || {
                        let _ = crypto::init();
                        if backend == 0 {
                            if let Ok(mut l) = logs_clone.lock() { l.push("Assembling from local mailbox...".to_string()); }
                            let logs_for_call = logs_clone.clone();
                            let _ = storage::assemble_from_mailbox_with_logs(&mailbox, &recipient_sk, &output, logs_for_call);
                        } else {
                            if let Ok(mut l) = logs_clone.lock() { l.push("Assembling from SFTP mailbox...".to_string()); }
                            let logs_for_call = logs_clone.clone();
                            if !sftp_pk.is_empty() || !sftp_host_fp.is_empty() {
                                let pw_opt = if sftp_pass.is_empty() { None } else { Some(sftp_pass.as_str()) };
                                let pk_opt = if sftp_pk.is_empty() { None } else { Some(sftp_pk.as_str()) };
                                let pk_pass_opt = if sftp_pk_pass.is_empty() { None } else { Some(sftp_pk_pass.as_str()) };
                                let hostfp_opt = if sftp_host_fp.is_empty() { None } else { Some(sftp_host_fp.as_str()) };
                                let _ = storage::assemble_from_sftp_with_logs_auth(&sftp_host, &sftp_user, pw_opt, pk_opt, pk_pass_opt, hostfp_opt, &sftp_base, &mailbox_id, &recipient_sk, &output, logs_for_call);
                            } else {
                                let _ = storage::assemble_from_sftp_with_logs(&sftp_host, &sftp_user, &sftp_pass, &sftp_base, &mailbox_id, &recipient_sk, &output, logs_for_call);
                            }
                        }
                        if let Ok(mut l) = logs_clone.lock() { l.push("Assemble complete".to_string()); }
                    });
                    }
                }
            });

            ui.separator();
            ui.group(|ui| {
                ui.label("Search chunks by SHA (local)");
                ui.horizontal(|ui| {
                    ui.label("SHA-256 (hex or name):");
                    ui.text_edit_singleline(&mut self.search_hash);
                });
                ui.horizontal(|ui| {
                    ui.label("Base dir:");
                    if self.search_base.is_empty() { self.search_base = self.output_dir.clone(); }
                    ui.text_edit_singleline(&mut self.search_base);
                    if ui.button("Browse").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.search_base = path.display().to_string();
                        }
                    }
                    if ui.button("Search").clicked() {
                        let base = std::path::PathBuf::from(self.search_base.clone());
                        match search::search_by_hash_local(&base, &self.search_hash) {
                            Ok(paths) => {
                                if paths.is_empty() { self.log("No matches"); }
                                for p in paths { self.log(&format!("Found: {}", p.display())); }
                            }
                            Err(e) => self.log(&format!("Search error: {e}")),
                        }
                    }
                });
            });

            ui.separator();
            // lightweight progress bar and cancel
            if self.job_running {
                let (mut total, mut done) = (0usize, 0usize);
                if let (Some(t), Some(d)) = (&self.job_progress_total, &self.job_progress_done) {
                    total = t.load(Ordering::Relaxed);
                    done = d.load(Ordering::Relaxed);
                }
                let pct = if total > 0 { (done as f32 / total as f32) * 100.0 } else { 0.0 };
                ui.horizontal(|ui| {
                    ui.label(format!("Job: {}", self.job_last_label));
                    ui.label(format!("Progress: {done}/{total} ({pct:.0}%)"));
                    if ui.button("Cancel").clicked() {
                        if let Some(c) = &self.job_cancel { c.store(true, Ordering::Relaxed); }
                        self.log("Cancel requested");
                    }
                });
                // auto-finish when counters complete
                if total > 0 && done >= total {
                    self.job_running = false;
                    self.job_cancel = None;
                }
            }
            ui.horizontal(|ui| {
                ui.label("Folder watcher:");
                if ui.button(if self.watcher_running { "Stop Watch" } else { "Start Watch" }).clicked() {
                    if self.watcher_running {
                        if let Some(flag) = &self.watcher_stop { flag.store(true, Ordering::Relaxed); }
                        if let Some(h) = self.watcher_handle.take() { let _ = h.join(); }
                        self.watcher_running = false;
                        self.log("Watcher stopped");
                    } else {
                        if let Some(folder) = self.selected_folder.clone() {
                            let logs = self.logs.clone();
                            let stop = Arc::new(AtomicBool::new(false));
                            let stop_clone = stop.clone();
                            let recipient = self.recipient_pk.clone();
                            let sender = if self.sender_sk.is_empty() { None } else { Some(self.sender_sk.clone()) };
                            let backend = self.storage_backend;
                            let output = PathBuf::from(self.output_dir.clone());
                            let sftp_host = self.sftp_host.clone();
                            let sftp_user = self.sftp_user.clone();
                            let sftp_pass = self.sftp_pass.clone();
                            let sftp_base = self.sftp_base.clone();
                            let sftp_pk = self.sftp_private_key.clone();
                            let sftp_pk_pass = self.sftp_private_key_pass.clone();
                            let sftp_host_fp = self.sftp_host_fingerprint_sha256_b64.clone();
                            let mailbox_id = if self.sftp_mailbox_id.trim().is_empty() { recipient.clone() } else { self.sftp_mailbox_id.clone() };
                            let chunk_mb_watcher = self.chunk_size_mb;
                            self.log("Watcher starting...");
                            let handle = std::thread::spawn(move || {
                                let _ = crypto::init();
                                let (tx, rx) = std::sync::mpsc::channel();
                                let mut watcher = recommended_watcher(move |res| {
                                    if let Ok(event) = res { let _ = tx.send(event); }
                                }).expect("watcher create");
                                watcher.watch(&folder, RecursiveMode::Recursive).expect("watch start");

                                while !stop_clone.load(Ordering::Relaxed) {
                                    match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                                        Ok(ev) => {
                                            for p in ev.paths {
                                                if p.is_file() {
                                                    if let Ok(mut l) = logs.lock() { l.push(format!("Detected change: {:?}", p)); }
                                                    if backend == 0 {
                                                        let _ = storage::process_file_encrypt(&p, &folder, &recipient, sender.as_deref(), &output, (chunk_mb_watcher as usize) * 1024 * 1024, None, None);
                                                    } else {
                                                        if !sftp_pk.is_empty() || !sftp_host_fp.is_empty() {
                                                            let pw_opt = if sftp_pass.is_empty() { None } else { Some(sftp_pass.as_str()) };
                                                            let pk_opt = if sftp_pk.is_empty() { None } else { Some(sftp_pk.as_str()) };
                                                            let pk_pass_opt = if sftp_pk_pass.is_empty() { None } else { Some(sftp_pk_pass.as_str()) };
                                                            let hostfp_opt = if sftp_host_fp.is_empty() { None } else { Some(sftp_host_fp.as_str()) };
                                                            let _ = storage::process_file_encrypt_to_sftp_auth(&p, &folder, &recipient, &mailbox_id, sender.as_deref(), &sftp_host, &sftp_user, pw_opt, pk_opt, pk_pass_opt, hostfp_opt, &sftp_base, (chunk_mb_watcher as usize) * 1024 * 1024, None, None);
                                                        } else {
                                                            let _ = storage::process_file_encrypt_to_sftp(&p, &folder, &recipient, &mailbox_id, sender.as_deref(), &sftp_host, &sftp_user, &sftp_pass, &sftp_base, (chunk_mb_watcher as usize) * 1024 * 1024, None, None);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                                        Err(_) => break,
                                    }
                                }
                            });
                            self.watcher_stop = Some(stop);
                            self.watcher_handle = Some(handle);
                            self.watcher_running = true;
                        } else {
                            self.log("Select a folder to watch first");
                        }
                    }
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
    let app = AppState {
        chunk_size_mb: 10,
        recipient_pk: String::new(),
        recipient_sk: String::new(),
        sender_sk: String::new(),
        sftp_host: String::new(),
        sftp_user: String::new(),
        sftp_pass: String::new(),
        sftp_base: String::new(),
        sftp_mailbox_id: String::new(),
        sftp_private_key: String::new(),
        sftp_private_key_pass: String::new(),
        sftp_host_fingerprint_sha256_b64: String::new(),
        sftp_require_host_fp: false,
        watcher_running: false,
        watcher_stop: None,
        watcher_handle: None,
        job_progress_total: None,
        job_progress_done: None,
        job_cancel: None,
        job_running: false,
        job_last_label: String::new(),
    search_hash: String::new(),
    search_base: String::new(),
        ..Default::default()
    };
    let _ = eframe::run_native("n0n", options, Box::new(|_cc| Box::new(app)));
    Ok(())
}
