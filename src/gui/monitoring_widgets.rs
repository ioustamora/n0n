use eframe::egui::{self, *};
use std::collections::HashMap;
use std::sync::Arc;

use crate::monitoring::{
    MonitoringService, AlertSeverity, AlertStatus, HealthStatus, LogLevel,
    Alert, ComponentHealth, PerformanceMetrics, DashboardData, MetricValue
};

/// Widget for monitoring dashboard and system health
pub struct MonitoringDashboardWidget {
    pub monitoring_service: Option<Arc<MonitoringService>>,
    pub dashboard_data: Option<DashboardData>,
    pub selected_tab: MonitoringTab,
    pub refresh_interval_seconds: u32,
    pub last_refresh: Option<std::time::Instant>,
    pub auto_refresh: bool,
    pub alert_filters: AlertFilters,
    pub log_filters: LogFilters,
    pub show_advanced_metrics: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MonitoringTab {
    Overview,
    Alerts,
    Health,
    Metrics,
    Logs,
    Performance,
}

#[derive(Debug, Clone)]
pub struct AlertFilters {
    pub severity: Option<AlertSeverity>,
    pub status: Option<AlertStatus>,
    pub search_text: String,
}

#[derive(Debug, Clone)]
pub struct LogFilters {
    pub level: Option<LogLevel>,
    pub search_text: String,
    pub max_entries: usize,
}

impl Default for MonitoringDashboardWidget {
    fn default() -> Self {
        Self {
            monitoring_service: None,
            dashboard_data: None,
            selected_tab: MonitoringTab::Overview,
            refresh_interval_seconds: 30,
            last_refresh: None,
            auto_refresh: true,
            alert_filters: AlertFilters {
                severity: None,
                status: None,
                search_text: String::new(),
            },
            log_filters: LogFilters {
                level: None,
                search_text: String::new(),
                max_entries: 100,
            },
            show_advanced_metrics: false,
        }
    }
}

impl MonitoringDashboardWidget {
    pub fn ui(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        // Auto-refresh logic
        if self.auto_refresh {
            let should_refresh = self.last_refresh.map_or(true, |last| {
                last.elapsed().as_secs() >= self.refresh_interval_seconds as u64
            });

            if should_refresh {
                self.refresh_dashboard_data();
                self.last_refresh = Some(std::time::Instant::now());
            }
        }

        ui.heading("📊 Monitoring Dashboard");
        
        // Controls
        ui.horizontal(|ui| {
            if ui.button("🔄 Refresh").clicked() {
                self.refresh_dashboard_data();
            }
            
            ui.checkbox(&mut self.auto_refresh, "Auto-refresh");
            
            if self.auto_refresh {
                ui.label("every");
                ui.add(egui::DragValue::new(&mut self.refresh_interval_seconds).clamp_range(5..=300).suffix("s"));
            }
            
            ui.separator();
            
            // Status indicator
            if let Some(data) = &self.dashboard_data {
                let status_color = match data.system_health.overall_status {
                    HealthStatus::Healthy => Color32::GREEN,
                    HealthStatus::Degraded => Color32::YELLOW,
                    HealthStatus::Unhealthy => Color32::RED,
                    HealthStatus::Unknown => Color32::GRAY,
                };
                
                ui.colored_label(status_color, format!("● {:?}", data.system_health.overall_status));
                ui.label(format!("Uptime: {}s", data.uptime_seconds));
            }
        });

        ui.separator();

        // Tabs
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.selected_tab, MonitoringTab::Overview, "📊 Overview");
            ui.selectable_value(&mut self.selected_tab, MonitoringTab::Alerts, "🚨 Alerts");
            ui.selectable_value(&mut self.selected_tab, MonitoringTab::Health, "💗 Health");
            ui.selectable_value(&mut self.selected_tab, MonitoringTab::Metrics, "📈 Metrics");
            ui.selectable_value(&mut self.selected_tab, MonitoringTab::Logs, "📝 Logs");
            ui.selectable_value(&mut self.selected_tab, MonitoringTab::Performance, "⚡ Performance");
        });

        ui.separator();

        // Tab content
        match self.selected_tab {
            MonitoringTab::Overview => self.render_overview_tab(ui),
            MonitoringTab::Alerts => self.render_alerts_tab(ui),
            MonitoringTab::Health => self.render_health_tab(ui),
            MonitoringTab::Metrics => self.render_metrics_tab(ui),
            MonitoringTab::Logs => self.render_logs_tab(ui),
            MonitoringTab::Performance => self.render_performance_tab(ui),
        }

        // Request repaint for auto-refresh
        if self.auto_refresh {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
    }

    fn render_overview_tab(&mut self, ui: &mut Ui) {
        if let Some(data) = &self.dashboard_data {
            ui.columns(2, |columns| {
                // Left column - System Health
                columns[0].group(|ui| {
                    ui.heading("🏥 System Health");
                    ui.separator();
                    
                    ui.horizontal(|ui| {
                        let status_text = format!("{:?}", data.system_health.overall_status);
                        let status_color = match data.system_health.overall_status {
                            HealthStatus::Healthy => Color32::GREEN,
                            HealthStatus::Degraded => Color32::YELLOW,
                            HealthStatus::Unhealthy => Color32::RED,
                            HealthStatus::Unknown => Color32::GRAY,
                        };
                        ui.colored_label(status_color, format!("● {}", status_text));
                    });

                    ui.add_space(10.0);

                    // Health summary
                    ui.label(format!("📊 Components: {}", data.system_health.summary.total_components));
                    ui.label(format!("✅ Healthy: {}", data.system_health.summary.healthy_components));
                    ui.label(format!("⚠️ Degraded: {}", data.system_health.summary.degraded_components));
                    ui.label(format!("❌ Unhealthy: {}", data.system_health.summary.unhealthy_components));
                    ui.label(format!("❓ Unknown: {}", data.system_health.summary.unknown_components));
                    ui.label(format!("📈 Uptime: {:.1}%", data.system_health.summary.uptime_percentage));
                });

                // Right column - Active Alerts
                columns[1].group(|ui| {
                    ui.heading("🚨 Active Alerts");
                    ui.separator();
                    
                    if data.active_alerts.is_empty() {
                        ui.colored_label(Color32::GREEN, "✅ No active alerts");
                    } else {
                        let mut critical_count = 0;
                        let mut warning_count = 0;
                        let mut info_count = 0;

                        for alert in &data.active_alerts {
                            match alert.severity {
                                AlertSeverity::Emergency | AlertSeverity::Critical => critical_count += 1,
                                AlertSeverity::Warning => warning_count += 1,
                                AlertSeverity::Info => info_count += 1,
                            }
                        }

                        if critical_count > 0 {
                            ui.colored_label(Color32::RED, format!("🔥 Critical: {}", critical_count));
                        }
                        if warning_count > 0 {
                            ui.colored_label(Color32::YELLOW, format!("⚠️ Warning: {}", warning_count));
                        }
                        if info_count > 0 {
                            ui.colored_label(Color32::BLUE, format!("ℹ️ Info: {}", info_count));
                        }

                        ui.add_space(10.0);

                        // Recent alerts
                        ui.label("Recent Alerts:");
                        egui::ScrollArea::vertical()
                            .max_height(150.0)
                            .show(ui, |ui| {
                                for alert in data.active_alerts.iter().take(5) {
                                    self.render_alert_summary(ui, alert);
                                }
                            });
                    }
                });
            });

            ui.add_space(20.0);

            // Performance Overview
            ui.group(|ui| {
                ui.heading("⚡ Performance Overview");
                ui.separator();
                
                ui.columns(4, |columns| {
                    columns[0].vertical_centered(|ui| {
                        ui.label("💾 CPU");
                        ui.heading(format!("{:.1}%", data.performance_metrics.cpu_usage_percent));
                    });
                    
                    columns[1].vertical_centered(|ui| {
                        ui.label("🧠 Memory");
                        ui.heading(format!("{:.1}%", data.performance_metrics.memory_usage_percent));
                    });
                    
                    columns[2].vertical_centered(|ui| {
                        ui.label("🔗 Connections");
                        ui.heading(format!("{}", data.performance_metrics.active_connections));
                    });
                    
                    columns[3].vertical_centered(|ui| {
                        ui.label("🧵 Threads");
                        ui.heading(format!("{}", data.performance_metrics.thread_count));
                    });
                });
            });

            ui.add_space(20.0);

            // Key Metrics
            ui.group(|ui| {
                ui.heading("📊 Key Metrics");
                ui.separator();
                
                egui::ScrollArea::horizontal().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        for (name, value) in &data.metrics_summary {
                            ui.vertical(|ui| {
                                ui.label(name);
                                match value {
                                    MetricValue::Counter(v) => ui.heading(v.to_string()),
                                    MetricValue::Gauge(v) => ui.heading(format!("{:.2}", v)),
                                    MetricValue::Histogram { .. } => ui.heading("📊"),
                                    MetricValue::Summary { count, .. } => ui.heading(count.to_string()),
                                };
                            });
                            ui.separator();
                        }
                    });
                });
            });
        } else {
            ui.centered_and_justified(|ui| {
                ui.label("No monitoring data available. Start the monitoring service to see dashboard.");
            });
        }
    }

    fn render_alerts_tab(&mut self, ui: &mut Ui) {
        // Alert filters
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Filters:");
                
                egui::ComboBox::from_label("Severity")
                    .selected_text(
                        self.alert_filters.severity
                            .as_ref()
                            .map(|s| format!("{:?}", s))
                            .unwrap_or_else(|| "All".to_string())
                    )
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.alert_filters.severity, None, "All");
                        ui.selectable_value(&mut self.alert_filters.severity, Some(AlertSeverity::Emergency), "Emergency");
                        ui.selectable_value(&mut self.alert_filters.severity, Some(AlertSeverity::Critical), "Critical");
                        ui.selectable_value(&mut self.alert_filters.severity, Some(AlertSeverity::Warning), "Warning");
                        ui.selectable_value(&mut self.alert_filters.severity, Some(AlertSeverity::Info), "Info");
                    });
                
                egui::ComboBox::from_label("Status")
                    .selected_text(
                        self.alert_filters.status
                            .as_ref()
                            .map(|s| format!("{:?}", s))
                            .unwrap_or_else(|| "All".to_string())
                    )
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.alert_filters.status, None, "All");
                        ui.selectable_value(&mut self.alert_filters.status, Some(AlertStatus::Firing), "Firing");
                        ui.selectable_value(&mut self.alert_filters.status, Some(AlertStatus::Resolved), "Resolved");
                        ui.selectable_value(&mut self.alert_filters.status, Some(AlertStatus::Acknowledged), "Acknowledged");
                        ui.selectable_value(&mut self.alert_filters.status, Some(AlertStatus::Suppressed), "Suppressed");
                    });
                
                ui.text_edit_singleline(&mut self.alert_filters.search_text);
                ui.label("Search");
            });
        });

        ui.separator();

        // Alerts list
        if let Some(data) = &self.dashboard_data {
            egui::ScrollArea::vertical().show(ui, |ui| {
                for alert in &data.active_alerts {
                    if self.alert_matches_filters(alert) {
                        self.render_alert_detail(ui, alert);
                    }
                }
            });
        } else {
            ui.label("No alert data available");
        }
    }

    fn render_health_tab(&mut self, ui: &mut Ui) {
        if let Some(data) = &self.dashboard_data {
            for (component_id, health) in &data.system_health.components {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        let status_color = match health.status {
                            HealthStatus::Healthy => Color32::GREEN,
                            HealthStatus::Degraded => Color32::YELLOW,
                            HealthStatus::Unhealthy => Color32::RED,
                            HealthStatus::Unknown => Color32::GRAY,
                        };
                        
                        ui.colored_label(status_color, format!("● {:?}", health.status));
                        ui.heading(component_id);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(format!("{}ms", health.response_time_ms));
                        });
                    });
                    
                    ui.label(&health.message);
                    ui.label(format!("Last checked: {}", health.last_checked.format("%H:%M:%S")));
                    
                    if health.consecutive_failures > 0 {
                        ui.colored_label(Color32::RED, format!("Consecutive failures: {}", health.consecutive_failures));
                    }
                    
                    ui.horizontal(|ui| {
                        ui.label(format!("Success rate: {:.1}%", 
                            if health.total_checks > 0 {
                                (health.successful_checks as f64 / health.total_checks as f64) * 100.0
                            } else {
                                0.0
                            }
                        ));
                    });
                });
            }
        } else {
            ui.label("No health data available");
        }
    }

    fn render_metrics_tab(&mut self, ui: &mut Ui) {
        ui.checkbox(&mut self.show_advanced_metrics, "Show advanced metrics");
        ui.separator();

        if let Some(data) = &self.dashboard_data {
            egui::Grid::new("metrics_grid")
                .num_columns(3)
                .spacing([40.0, 8.0])
                .show(ui, |ui| {
                    ui.strong("Metric");
                    ui.strong("Value");
                    ui.strong("Type");
                    ui.end_row();

                    for (name, value) in &data.metrics_summary {
                        ui.label(name);
                        match value {
                            MetricValue::Counter(v) => {
                                ui.label(v.to_string());
                                ui.label("Counter");
                            }
                            MetricValue::Gauge(v) => {
                                ui.label(format!("{:.3}", v));
                                ui.label("Gauge");
                            }
                            MetricValue::Histogram { buckets, values } => {
                                ui.label(format!("{} buckets", buckets.len()));
                                ui.label("Histogram");
                            }
                            MetricValue::Summary { count, sum, .. } => {
                                ui.label(format!("count: {}, sum: {:.3}", count, sum));
                                ui.label("Summary");
                            }
                        }
                        ui.end_row();
                    }
                });
        } else {
            ui.label("No metrics data available");
        }
    }

    fn render_logs_tab(&mut self, ui: &mut Ui) {
        // Log filters
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Filters:");
                
                egui::ComboBox::from_label("Level")
                    .selected_text(
                        self.log_filters.level
                            .as_ref()
                            .map(|l| format!("{:?}", l))
                            .unwrap_or_else(|| "All".to_string())
                    )
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.log_filters.level, None, "All");
                        ui.selectable_value(&mut self.log_filters.level, Some(LogLevel::Fatal), "Fatal");
                        ui.selectable_value(&mut self.log_filters.level, Some(LogLevel::Error), "Error");
                        ui.selectable_value(&mut self.log_filters.level, Some(LogLevel::Warn), "Warn");
                        ui.selectable_value(&mut self.log_filters.level, Some(LogLevel::Info), "Info");
                        ui.selectable_value(&mut self.log_filters.level, Some(LogLevel::Debug), "Debug");
                        ui.selectable_value(&mut self.log_filters.level, Some(LogLevel::Trace), "Trace");
                    });
                
                ui.text_edit_singleline(&mut self.log_filters.search_text);
                ui.label("Search");
                
                ui.add(egui::DragValue::new(&mut self.log_filters.max_entries).clamp_range(10..=1000).prefix("Show ").suffix(" entries"));
            });
        });

        ui.separator();

        // Logs
        if let Some(data) = &self.dashboard_data {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for log_entry in data.recent_log_entries.iter().take(self.log_filters.max_entries) {
                        if self.log_matches_filters(log_entry) {
                            ui.horizontal(|ui| {
                                let level_color = match log_entry.level {
                                    LogLevel::Fatal => Color32::DARK_RED,
                                    LogLevel::Error => Color32::RED,
                                    LogLevel::Warn => Color32::YELLOW,
                                    LogLevel::Info => Color32::BLUE,
                                    LogLevel::Debug => Color32::GRAY,
                                    LogLevel::Trace => Color32::LIGHT_GRAY,
                                };
                                
                                ui.colored_label(level_color, format!("{:?}", log_entry.level));
                                ui.label(log_entry.timestamp.format("%H:%M:%S").to_string());
                                ui.label(&log_entry.message);
                            });
                        }
                    }
                });
        } else {
            ui.label("No log data available");
        }
    }

    fn render_performance_tab(&mut self, ui: &mut Ui) {
        if let Some(data) = &self.dashboard_data {
            ui.columns(2, |columns| {
                // System metrics
                columns[0].group(|ui| {
                    ui.heading("💻 System Metrics");
                    ui.separator();
                    
                    ui.label(format!("CPU Usage: {:.1}%", data.performance_metrics.cpu_usage_percent));
                    ui.add(ProgressBar::new(data.performance_metrics.cpu_usage_percent as f32 / 100.0));
                    
                    ui.add_space(5.0);
                    
                    ui.label(format!("Memory Usage: {:.1}%", data.performance_metrics.memory_usage_percent));
                    ui.add(ProgressBar::new(data.performance_metrics.memory_usage_percent as f32 / 100.0));
                    
                    ui.add_space(10.0);
                    
                    ui.label(format!("Memory: {} MB", data.performance_metrics.memory_usage_bytes / 1024 / 1024));
                    ui.label(format!("Active Connections: {}", data.performance_metrics.active_connections));
                    ui.label(format!("Thread Count: {}", data.performance_metrics.thread_count));
                    ui.label(format!("File Descriptors: {}", data.performance_metrics.file_descriptors));
                });
                
                // Network metrics
                columns[1].group(|ui| {
                    ui.heading("🌐 Network Metrics");
                    ui.separator();
                    
                    ui.label(format!("RX: {} KB/s", data.performance_metrics.network_rx_bytes_per_sec / 1024));
                    ui.label(format!("TX: {} KB/s", data.performance_metrics.network_tx_bytes_per_sec / 1024));
                    
                    ui.add_space(10.0);
                    
                    ui.heading("💽 Disk I/O");
                    ui.label(format!("Read: {} KB/s", data.performance_metrics.disk_read_bytes_per_sec / 1024));
                    ui.label(format!("Write: {} KB/s", data.performance_metrics.disk_write_bytes_per_sec / 1024));
                });
            });
        } else {
            ui.label("No performance data available");
        }
    }

    fn render_alert_summary(&self, ui: &mut Ui, alert: &Alert) {
        ui.horizontal(|ui| {
            let severity_color = match alert.severity {
                AlertSeverity::Emergency => Color32::DARK_RED,
                AlertSeverity::Critical => Color32::RED,
                AlertSeverity::Warning => Color32::YELLOW,
                AlertSeverity::Info => Color32::BLUE,
            };
            
            ui.colored_label(severity_color, format!("{:?}", alert.severity));
            ui.label(&alert.name);
        });
    }

    fn render_alert_detail(&self, ui: &mut Ui, alert: &Alert) {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                let severity_color = match alert.severity {
                    AlertSeverity::Emergency => Color32::DARK_RED,
                    AlertSeverity::Critical => Color32::RED,
                    AlertSeverity::Warning => Color32::YELLOW,
                    AlertSeverity::Info => Color32::BLUE,
                };
                
                ui.colored_label(severity_color, format!("{:?}", alert.severity));
                ui.heading(&alert.name);
                
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(alert.triggered_at.format("%H:%M:%S").to_string());
                    
                    let status_color = match alert.status {
                        AlertStatus::Firing => Color32::RED,
                        AlertStatus::Resolved => Color32::GREEN,
                        AlertStatus::Acknowledged => Color32::BLUE,
                        AlertStatus::Suppressed => Color32::GRAY,
                    };
                    ui.colored_label(status_color, format!("{:?}", alert.status));
                });
            });
            
            ui.label(&alert.description);
            
            if let Some(current_value) = alert.current_value {
                ui.horizontal(|ui| {
                    ui.label(format!("Current value: {:.2}", current_value));
                    ui.label(format!("Threshold: {:.2}", alert.threshold));
                });
            }
            
            if !alert.labels.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    for (key, value) in &alert.labels {
                        ui.small(format!("{}={}", key, value));
                    }
                });
            }
        });
    }

    fn alert_matches_filters(&self, alert: &Alert) -> bool {
        if let Some(severity_filter) = &self.alert_filters.severity {
            if &alert.severity != severity_filter {
                return false;
            }
        }
        
        if let Some(status_filter) = &self.alert_filters.status {
            if &alert.status != status_filter {
                return false;
            }
        }
        
        if !self.alert_filters.search_text.is_empty() {
            let search_text = self.alert_filters.search_text.to_lowercase();
            if !alert.name.to_lowercase().contains(&search_text) 
                && !alert.description.to_lowercase().contains(&search_text) {
                return false;
            }
        }
        
        true
    }

    fn log_matches_filters(&self, log_entry: &crate::monitoring::LogEntry) -> bool {
        if let Some(level_filter) = &self.log_filters.level {
            if &log_entry.level != level_filter {
                return false;
            }
        }
        
        if !self.log_filters.search_text.is_empty() {
            let search_text = self.log_filters.search_text.to_lowercase();
            if !log_entry.message.to_lowercase().contains(&search_text) {
                return false;
            }
        }
        
        true
    }

    fn refresh_dashboard_data(&mut self) {
        if let Some(_service) = &self.monitoring_service {
            // In a real implementation, this would call the monitoring service
            log::info!("Refreshing monitoring dashboard data...");
            
            // For now, this is a placeholder
            // self.dashboard_data = Some(service.get_dashboard_data().await.unwrap_or_default());
        }
    }
}