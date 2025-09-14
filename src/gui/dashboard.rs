use crate::gui::notifications::NotificationManager;
use crate::gui::data_visualization::{DataVisualization, SystemMetrics, StorageAnalytics};

pub struct DashboardState {
    pub system_status: SystemStatusWidget,
    pub recent_activity: ActivityFeedWidget,
    pub quick_actions: QuickActionsWidget,
    pub active_operations: OperationsWidget,
    pub data_visualization: DataVisualization,
    pub show_detailed_metrics: bool,
    pub last_metrics_update: std::time::Instant,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            system_status: SystemStatusWidget::default(),
            recent_activity: ActivityFeedWidget::default(),
            quick_actions: QuickActionsWidget::default(),
            active_operations: OperationsWidget::default(),
            data_visualization: DataVisualization::default(),
            show_detailed_metrics: false,
            last_metrics_update: std::time::Instant::now(),
        }
    }
}

impl DashboardState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(&mut self, ui: &mut egui::Ui, app_state: &mut crate::gui::state::AppState, notifications: &mut NotificationManager) {
        ui.horizontal(|ui| {
            ui.heading("🏠 Dashboard");

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.checkbox(&mut self.show_detailed_metrics, "📊 Detailed Metrics").changed() {
                    if self.show_detailed_metrics {
                        notifications.info("Detailed Metrics", "Real-time charts and graphs enabled");
                    }
                }
            });
        });

        ui.add_space(10.0);

        // Update metrics periodically
        if self.last_metrics_update.elapsed().as_secs() >= 2 {
            self.data_visualization.generate_mock_data(); // In real app, collect actual metrics
            self.last_metrics_update = std::time::Instant::now();
        }

        if self.show_detailed_metrics {
            // Enhanced dashboard with data visualization
            self.render_enhanced_dashboard(ui, app_state, notifications);
        } else {
            // Original compact dashboard
            self.render_compact_dashboard(ui, app_state, notifications);
        }

        ui.add_space(10.0);

        // Notifications panel (contextual notifications would be shown here)
        notifications.render_contextual_status(ui, "dashboard");
    }

    fn render_compact_dashboard(&mut self, ui: &mut egui::Ui, app_state: &mut crate::gui::state::AppState, notifications: &mut NotificationManager) {
        // Top row: Status overview and quick actions
        ui.horizontal(|ui| {
            ui.group(|ui| {
                ui.set_min_width(250.0);
                self.system_status.render(ui, app_state);
            });

            ui.add_space(10.0);

            ui.group(|ui| {
                ui.set_min_width(200.0);
                self.recent_activity.render(ui, app_state);
            });

            ui.add_space(10.0);

            ui.group(|ui| {
                ui.set_min_width(200.0);
                self.quick_actions.render(ui, app_state, notifications);
            });
        });

        ui.add_space(20.0);

        // Active operations section
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            self.active_operations.render(ui, app_state);
        });
    }

    fn render_enhanced_dashboard(&mut self, ui: &mut egui::Ui, app_state: &mut crate::gui::state::AppState, notifications: &mut NotificationManager) {
        // System overview with real-time metrics
        self.data_visualization.render_system_overview(ui);

        ui.add_space(15.0);

        // Combined status and actions row
        ui.horizontal(|ui| {
            // System status with enhanced metrics
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() * 0.3);
                ui.group(|ui| {
                    ui.heading("System Status");
                    ui.separator();

                    // Status indicators with real-time visualization
                    self.data_visualization.render_status_indicator(ui, "cpu_usage");
                    self.data_visualization.render_status_indicator(ui, "memory_usage");
                    self.data_visualization.render_status_indicator(ui, "disk_usage");
                    self.data_visualization.render_status_indicator(ui, "active_connections");
                });
            });

            ui.add_space(10.0);

            // Recent activity
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() * 0.4);
                ui.group(|ui| {
                    self.recent_activity.render(ui, app_state);
                });
            });

            ui.add_space(10.0);

            // Quick actions
            ui.vertical(|ui| {
                ui.set_width(ui.available_width());
                ui.group(|ui| {
                    self.quick_actions.render(ui, app_state, notifications);
                });
            });
        });

        ui.add_space(15.0);

        // Storage analytics
        let storage_analytics = self.collect_storage_analytics(app_state);
        self.data_visualization.render_storage_dashboard(ui, &storage_analytics);

        ui.add_space(15.0);

        // Active operations with enhanced progress visualization
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            self.active_operations.render(ui, app_state);
        });
    }

    fn collect_storage_analytics(&self, app_state: &crate::gui::state::AppState) -> StorageAnalytics {
        let mut analytics = StorageAnalytics::default();

        // Mock data - in real implementation this would collect actual analytics
        use std::collections::HashMap;

        analytics.total_files = 1250;
        analytics.total_size_bytes = 2_500_000_000; // 2.5 GB

        analytics.files_per_backend.insert("Local".to_string(), 800);
        analytics.files_per_backend.insert("SFTP".to_string(), 300);
        analytics.files_per_backend.insert("S3".to_string(), 150);

        analytics.size_per_backend.insert("Local".to_string(), 1_500_000_000);
        analytics.size_per_backend.insert("SFTP".to_string(), 700_000_000);
        analytics.size_per_backend.insert("S3".to_string(), 300_000_000);

        analytics.operations_by_type.insert("Upload".to_string(), 45);
        analytics.operations_by_type.insert("Download".to_string(), 23);
        analytics.operations_by_type.insert("Delete".to_string(), 12);
        analytics.operations_by_type.insert("Sync".to_string(), 156);

        analytics.error_counts.insert("Connection timeout".to_string(), 3);
        analytics.error_counts.insert("Permission denied".to_string(), 1);
        analytics.error_counts.insert("Disk full".to_string(), 0);

        analytics
    }
}

pub struct SystemStatusWidget {
    last_update: std::time::Instant,
    cached_status: Option<SystemStatus>,
}

impl Default for SystemStatusWidget {
    fn default() -> Self {
        Self {
            last_update: std::time::Instant::now(),
            cached_status: None,
        }
    }
}

#[derive(Clone)]
struct SystemStatus {
    storage_backends_online: usize,
    total_storage_backends: usize,
    total_storage_used: String,
    encryption_enabled: bool,
    recent_sync_time: Option<std::time::SystemTime>,
}

impl SystemStatusWidget {
    pub fn render(&mut self, ui: &mut egui::Ui, app_state: &crate::gui::state::AppState) {
        ui.heading("System Status");
        ui.separator();

        // Update status every 30 seconds
        let should_update = self.last_update.elapsed().as_secs() > 30 || self.cached_status.is_none();
        if should_update {
            self.cached_status = Some(self.collect_system_status(app_state));
            self.last_update = std::time::Instant::now();
        }

        if let Some(ref status) = self.cached_status {
            // Storage health
            ui.horizontal(|ui| {
                let color = if status.storage_backends_online == status.total_storage_backends {
                    egui::Color32::GREEN
                } else if status.storage_backends_online > 0 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::RED
                };

                ui.colored_label(color, "●");
                ui.label(format!("Storage: {}/{} Online",
                    status.storage_backends_online,
                    status.total_storage_backends
                ));
            });

            // Storage usage
            ui.horizontal(|ui| {
                ui.label("💾");
                ui.label(format!("Used: {}", status.total_storage_used));
            });

            // Encryption status
            ui.horizontal(|ui| {
                let (icon, color) = if status.encryption_enabled {
                    ("🔒", egui::Color32::GREEN)
                } else {
                    ("🔓", egui::Color32::YELLOW)
                };
                ui.colored_label(color, icon);
                ui.label(if status.encryption_enabled { "Encrypted" } else { "Not Encrypted" });
            });

            // Last sync
            if let Some(sync_time) = status.recent_sync_time {
                if let Ok(elapsed) = sync_time.elapsed() {
                    ui.horizontal(|ui| {
                        ui.label("🔄");
                        ui.label(format!("Last sync: {} ago", format_duration(elapsed)));
                    });
                }
            }
        } else {
            ui.label("Loading system status...");
        }
    }

    fn collect_system_status(&self, app_state: &crate::gui::state::AppState) -> SystemStatus {
        // Mock implementation - in real app this would collect actual status
        SystemStatus {
            storage_backends_online: if app_state.storage_manager.is_some() { 1 } else { 0 },
            total_storage_backends: 1,
            total_storage_used: "Unknown".to_string(),
            encryption_enabled: app_state.storage_configs.values()
                .any(|config| config.encryption_enabled),
            recent_sync_time: Some(std::time::SystemTime::now()),
        }
    }
}

pub struct ActivityFeedWidget {
    activities: Vec<ActivityItem>,
    last_update: std::time::Instant,
}

impl Default for ActivityFeedWidget {
    fn default() -> Self {
        Self {
            activities: Vec::new(),
            last_update: std::time::Instant::now(),
        }
    }
}

#[derive(Clone)]
struct ActivityItem {
    timestamp: std::time::SystemTime,
    icon: String,
    description: String,
    status: ActivityStatus,
}

#[derive(Clone)]
enum ActivityStatus {
    Success,
    Warning,
    Error,
    InProgress,
}

impl ActivityFeedWidget {
    pub fn render(&mut self, ui: &mut egui::Ui, app_state: &crate::gui::state::AppState) {
        ui.heading("Recent Activity");
        ui.separator();

        // Update activities periodically
        if self.last_update.elapsed().as_secs() > 10 {
            self.update_activities(app_state);
            self.last_update = std::time::Instant::now();
        }

        if self.activities.is_empty() {
            ui.label("No recent activity");
        } else {
            egui::ScrollArea::vertical()
                .max_height(150.0)
                .show(ui, |ui| {
                    for activity in &self.activities {
                        ui.horizontal(|ui| {
                            let color = match activity.status {
                                ActivityStatus::Success => egui::Color32::GREEN,
                                ActivityStatus::Warning => egui::Color32::YELLOW,
                                ActivityStatus::Error => egui::Color32::RED,
                                ActivityStatus::InProgress => egui::Color32::BLUE,
                            };

                            ui.label(&activity.icon);
                            ui.vertical(|ui| {
                                ui.small(&activity.description);
                                if let Ok(elapsed) = activity.timestamp.elapsed() {
                                    ui.small(format_duration(elapsed));
                                }
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.colored_label(color, "●");
                            });
                        });
                        ui.separator();
                    }
                });
        }
    }

    fn update_activities(&mut self, app_state: &crate::gui::state::AppState) {
        // Extract recent activities from logs
        if let Ok(logs) = app_state.logs.lock() {
            let recent_logs = logs.iter().rev().take(5);
            self.activities.clear();

            for (i, log_entry) in recent_logs.enumerate() {
                let timestamp = std::time::SystemTime::now() -
                    std::time::Duration::from_secs((i as u64 + 1) * 60); // Mock timestamps

                let (icon, status) = if log_entry.contains("error") || log_entry.contains("failed") {
                    ("❌", ActivityStatus::Error)
                } else if log_entry.contains("warning") {
                    ("⚠️", ActivityStatus::Warning)
                } else if log_entry.contains("progress") || log_entry.contains("running") {
                    ("🔄", ActivityStatus::InProgress)
                } else {
                    ("✅", ActivityStatus::Success)
                };

                self.activities.push(ActivityItem {
                    timestamp,
                    icon: icon.to_string(),
                    description: log_entry.clone(),
                    status,
                });
            }
        }
    }
}

#[derive(Default)]
pub struct QuickActionsWidget;

impl QuickActionsWidget {
    pub fn render(&mut self, ui: &mut egui::Ui, app_state: &mut crate::gui::state::AppState, notifications: &mut NotificationManager) {
        ui.heading("Quick Actions");
        ui.separator();

        ui.vertical(|ui| {
            // Add files action
            if ui.button("📁 Add Files").clicked() {
                if let Some(files) = rfd::FileDialog::new().pick_files() {
                    if !files.is_empty() {
                        app_state.selected_file = Some(files[0].clone());
                        notifications.success(
                            "Files Selected",
                            format!("Selected {} files for processing", files.len())
                        );
                    }
                }
            }

            ui.add_space(5.0);

            // Sync now action
            if ui.button("🔄 Sync Now").clicked() {
                // Trigger immediate sync
                app_state.log("Manual sync initiated");
                notifications.info("Sync Started", "Manual synchronization initiated");
            }

            ui.add_space(5.0);

            // Quick settings
            if ui.button("⚙️ Quick Setup").clicked() {
                // Could trigger setup wizard
                notifications.info("Quick Setup", "Feature coming soon!");
            }

            ui.add_space(5.0);

            // View logs
            if ui.button("📋 View Logs").clicked() {
                // Could switch to monitoring tab with logs focused
                notifications.info("View Logs", "Switch to Monitoring tab to view detailed logs");
            }
        });
    }
}

#[derive(Default)]
pub struct OperationsWidget;

impl OperationsWidget {
    pub fn render(&mut self, ui: &mut egui::Ui, app_state: &crate::gui::state::AppState) {
        ui.heading("Active Operations");
        ui.separator();

        let has_active_job = app_state.job_running;
        let has_watcher = app_state.watcher_running;

        if !has_active_job && !has_watcher {
            ui.label("No active operations");
            return;
        }

        // Show active job progress
        if has_active_job {
            ui.group(|ui| {
                ui.set_width(ui.available_width() - 20.0);

                ui.horizontal(|ui| {
                    ui.label("🔄");
                    ui.strong(&app_state.job_last_label);

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Pause").clicked() {
                            // Handle pause
                        }
                        if ui.small_button("Cancel").clicked() {
                            // Handle cancel
                        }
                    });
                });

                // Progress bar
                if let (Some(total), Some(done)) = (
                    &app_state.job_progress_total,
                    &app_state.job_progress_done,
                ) {
                    let total_val = total.load(std::sync::atomic::Ordering::Relaxed);
                    let done_val = done.load(std::sync::atomic::Ordering::Relaxed);

                    if total_val > 0 {
                        let progress = done_val as f32 / total_val as f32;
                        ui.add(egui::ProgressBar::new(progress)
                            .text(format!("{}/{} ({:.1}%)", done_val, total_val, progress * 100.0)));

                        // Estimate time remaining
                        if progress > 0.01 {
                            let estimated_total_time = std::time::Duration::from_secs(
                                (60.0 / progress) as u64 // Mock calculation
                            );
                            let remaining = estimated_total_time - std::time::Duration::from_secs(60);
                            ui.small(format!("Est. remaining: {}", format_duration(remaining)));
                        }
                    }
                }
            });

            ui.add_space(10.0);
        }

        // Show watcher status
        if has_watcher {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::GREEN, "👁");
                ui.label("File watcher active");
                if let Some(folder) = &app_state.selected_folder {
                    ui.small(format!("Watching: {}", folder.display()));
                }
            });
        }
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}