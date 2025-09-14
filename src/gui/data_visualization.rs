use eframe::egui;
use egui_plot::{Plot, PlotPoints, Line, Bar, BarChart, Legend};
use std::collections::{HashMap, VecDeque};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

/// Real-time data visualization components for monitoring
#[derive(Debug, Clone)]
pub struct DataVisualization {
    time_series_data: HashMap<String, TimeSeriesData>,
    metric_displays: HashMap<String, MetricDisplay>,
    charts: HashMap<String, ChartConfig>,
}

#[derive(Debug, Clone)]
pub struct TimeSeriesData {
    pub name: String,
    pub data_points: VecDeque<DataPoint>,
    pub max_points: usize,
    pub color: egui::Color32,
    pub unit: String,
}

#[derive(Debug, Clone)]
pub struct DataPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDisplay {
    pub name: String,
    pub current_value: f64,
    pub previous_value: f64,
    pub unit: String,
    pub format: DisplayFormat,
    pub status: MetricStatus,
    pub threshold_warning: Option<f64>,
    pub threshold_critical: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisplayFormat {
    Integer,
    Decimal(u8),
    Percentage,
    Bytes,
    Duration,
    Rate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricStatus {
    Healthy,
    Warning,
    Critical,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ChartConfig {
    pub chart_type: ChartType,
    pub title: String,
    pub x_label: String,
    pub y_label: String,
    pub show_legend: bool,
    pub auto_scale: bool,
    pub time_window_minutes: i64,
}

#[derive(Debug, Clone)]
pub enum ChartType {
    TimeSeries,
    Histogram,
    Gauge,
    HeatMap,
    BarChart,
}

/// System performance metrics
#[derive(Debug, Clone, Default)]
pub struct SystemMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_in: f64,
    pub network_out: f64,
    pub storage_ops_per_sec: f64,
    pub active_connections: u64,
    pub error_rate: f64,
    pub response_time_avg: f64,
    pub queue_depth: u64,
}

/// Storage analytics data
#[derive(Debug, Clone, Default)]
pub struct StorageAnalytics {
    pub total_files: u64,
    pub total_size_bytes: u64,
    pub files_per_backend: HashMap<String, u64>,
    pub size_per_backend: HashMap<String, u64>,
    pub operations_by_type: HashMap<String, u64>,
    pub error_counts: HashMap<String, u64>,
    pub performance_metrics: HashMap<String, f64>,
}

impl Default for DataVisualization {
    fn default() -> Self {
        Self::new()
    }
}

impl DataVisualization {
    pub fn new() -> Self {
        let mut viz = Self {
            time_series_data: HashMap::new(),
            metric_displays: HashMap::new(),
            charts: HashMap::new(),
        };

        viz.initialize_default_metrics();
        viz
    }

    fn initialize_default_metrics(&mut self) {
        // System metrics
        self.add_time_series("cpu_usage", "CPU Usage", 100, egui::Color32::BLUE, "%");
        self.add_time_series("memory_usage", "Memory Usage", 100, egui::Color32::GREEN, "%");
        self.add_time_series("disk_usage", "Disk Usage", 100, egui::Color32::from_rgb(255, 165, 0), "%");
        self.add_time_series("network_in", "Network In", 100, egui::Color32::from_rgb(128, 0, 128), "MB/s");
        self.add_time_series("network_out", "Network Out", 100, egui::Color32::RED, "MB/s");

        // Storage metrics
        self.add_time_series("storage_ops", "Storage Ops/sec", 100, egui::Color32::from_rgb(0, 255, 255), "ops/s");
        self.add_time_series("error_rate", "Error Rate", 100, egui::Color32::RED, "%");
        self.add_time_series("response_time", "Avg Response Time", 100, egui::Color32::YELLOW, "ms");

        // Configure metric displays
        self.add_metric_display("cpu_usage", "CPU Usage", DisplayFormat::Percentage, Some(80.0), Some(95.0));
        self.add_metric_display("memory_usage", "Memory Usage", DisplayFormat::Percentage, Some(85.0), Some(95.0));
        self.add_metric_display("disk_usage", "Disk Usage", DisplayFormat::Percentage, Some(80.0), Some(90.0));
        self.add_metric_display("active_connections", "Active Connections", DisplayFormat::Integer, Some(100.0), Some(200.0));
        self.add_metric_display("error_rate", "Error Rate", DisplayFormat::Percentage, Some(1.0), Some(5.0));

        // Configure charts
        self.add_chart("system_overview", ChartType::TimeSeries, "System Overview", "Time", "Usage %", true, true, 60);
        self.add_chart("storage_performance", ChartType::TimeSeries, "Storage Performance", "Time", "Operations/sec", true, true, 30);
        self.add_chart("error_distribution", ChartType::BarChart, "Error Distribution", "Error Type", "Count", false, true, 0);
    }

    pub fn add_time_series(&mut self, key: &str, name: &str, max_points: usize, color: egui::Color32, unit: &str) {
        self.time_series_data.insert(key.to_string(), TimeSeriesData {
            name: name.to_string(),
            data_points: VecDeque::with_capacity(max_points),
            max_points,
            color,
            unit: unit.to_string(),
        });
    }

    pub fn add_metric_display(&mut self, key: &str, name: &str, format: DisplayFormat, warning: Option<f64>, critical: Option<f64>) {
        self.metric_displays.insert(key.to_string(), MetricDisplay {
            name: name.to_string(),
            current_value: 0.0,
            previous_value: 0.0,
            unit: String::new(),
            format,
            status: MetricStatus::Unknown,
            threshold_warning: warning,
            threshold_critical: critical,
        });
    }

    pub fn add_chart(&mut self, key: &str, chart_type: ChartType, title: &str, x_label: &str, y_label: &str, legend: bool, auto_scale: bool, time_window: i64) {
        self.charts.insert(key.to_string(), ChartConfig {
            chart_type,
            title: title.to_string(),
            x_label: x_label.to_string(),
            y_label: y_label.to_string(),
            show_legend: legend,
            auto_scale,
            time_window_minutes: time_window,
        });
    }

    pub fn update_metric(&mut self, key: &str, value: f64) {
        // Update time series data
        if let Some(series) = self.time_series_data.get_mut(key) {
            let data_point = DataPoint {
                timestamp: Utc::now(),
                value,
            };

            series.data_points.push_back(data_point);
            if series.data_points.len() > series.max_points {
                series.data_points.pop_front();
            }
        }

        // Update metric display
        if let Some(metric) = self.metric_displays.get_mut(key) {
            metric.previous_value = metric.current_value;
            metric.current_value = value;
        }

        // Update status after metric update
        if let Some(metric) = self.metric_displays.get(key) {
            let status = self.calculate_metric_status(metric);
            if let Some(metric_mut) = self.metric_displays.get_mut(key) {
                metric_mut.status = status;
            }
        }
    }

    fn calculate_metric_status(&self, metric: &MetricDisplay) -> MetricStatus {
        if let Some(critical) = metric.threshold_critical {
            if metric.current_value >= critical {
                return MetricStatus::Critical;
            }
        }

        if let Some(warning) = metric.threshold_warning {
            if metric.current_value >= warning {
                return MetricStatus::Warning;
            }
        }

        MetricStatus::Healthy
    }

    /// Update from system metrics
    pub fn update_from_system_metrics(&mut self, metrics: &SystemMetrics) {
        self.update_metric("cpu_usage", metrics.cpu_usage);
        self.update_metric("memory_usage", metrics.memory_usage);
        self.update_metric("disk_usage", metrics.disk_usage);
        self.update_metric("network_in", metrics.network_in);
        self.update_metric("network_out", metrics.network_out);
        self.update_metric("storage_ops", metrics.storage_ops_per_sec);
        self.update_metric("error_rate", metrics.error_rate);
        self.update_metric("response_time", metrics.response_time_avg);

        // Update display-only metrics
        if let Some(metric) = self.metric_displays.get_mut("active_connections") {
            metric.previous_value = metric.current_value;
            metric.current_value = metrics.active_connections as f64;
        }

        // Update status after metric update
        if let Some(metric) = self.metric_displays.get("active_connections") {
            let status = self.calculate_metric_status(metric);
            if let Some(metric_mut) = self.metric_displays.get_mut("active_connections") {
                metric_mut.status = status;
            }
        }
    }

    /// Render system overview dashboard
    pub fn render_system_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("📊 System Overview");
        ui.add_space(10.0);

        // Key metrics cards
        ui.horizontal(|ui| {
            self.render_metric_card(ui, "cpu_usage");
            ui.add_space(10.0);
            self.render_metric_card(ui, "memory_usage");
            ui.add_space(10.0);
            self.render_metric_card(ui, "disk_usage");
            ui.add_space(10.0);
            self.render_metric_card(ui, "active_connections");
        });

        ui.add_space(20.0);

        // Time series charts
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() * 0.6);
                self.render_time_series_chart(ui, "System Resources", &["cpu_usage", "memory_usage", "disk_usage"]);
            });

            ui.add_space(10.0);

            ui.vertical(|ui| {
                ui.set_width(ui.available_width());
                self.render_time_series_chart(ui, "Network Activity", &["network_in", "network_out"]);
            });
        });
    }

    /// Render storage performance dashboard
    pub fn render_storage_dashboard(&mut self, ui: &mut egui::Ui, analytics: &StorageAnalytics) {
        ui.heading("💾 Storage Performance");
        ui.add_space(10.0);

        // Storage overview cards
        ui.horizontal(|ui| {
            self.render_storage_overview_card(ui, "Total Files", analytics.total_files as f64, DisplayFormat::Integer);
            ui.add_space(10.0);
            self.render_storage_overview_card(ui, "Total Size", analytics.total_size_bytes as f64, DisplayFormat::Bytes);
            ui.add_space(10.0);
            self.render_metric_card(ui, "storage_ops");
            ui.add_space(10.0);
            self.render_metric_card(ui, "error_rate");
        });

        ui.add_space(20.0);

        // Charts
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() * 0.5);
                self.render_storage_distribution_chart(ui, "Files by Backend", &analytics.files_per_backend);
            });

            ui.add_space(10.0);

            ui.vertical(|ui| {
                ui.set_width(ui.available_width());
                self.render_time_series_chart(ui, "Storage Operations", &["storage_ops", "error_rate"]);
            });
        });

        ui.add_space(10.0);

        // Operations breakdown
        if !analytics.operations_by_type.is_empty() {
            self.render_operations_chart(ui, "Operations by Type", &analytics.operations_by_type);
        }
    }

    fn render_metric_card(&mut self, ui: &mut egui::Ui, key: &str) {
        if let Some(metric) = self.metric_displays.get(key) {
            let card_color = match metric.status {
                MetricStatus::Healthy => egui::Color32::from_gray(240),
                MetricStatus::Warning => egui::Color32::from_rgb(255, 248, 220),
                MetricStatus::Critical => egui::Color32::from_rgb(255, 235, 235),
                MetricStatus::Unknown => egui::Color32::from_gray(245),
            };

            egui::Frame::none()
                .fill(card_color)
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(200)))
                .rounding(egui::Rounding::same(6.0))
                .inner_margin(egui::Margin::same(12.0))
                .show(ui, |ui| {
                    ui.set_min_width(120.0);
                    ui.set_min_height(80.0);

                    ui.vertical(|ui| {
                        ui.small(&metric.name);

                        ui.horizontal(|ui| {
                            // Status indicator
                            let status_color = match metric.status {
                                MetricStatus::Healthy => egui::Color32::GREEN,
                                MetricStatus::Warning => egui::Color32::from_rgb(255, 193, 7),
                                MetricStatus::Critical => egui::Color32::RED,
                                MetricStatus::Unknown => egui::Color32::GRAY,
                            };
                            ui.colored_label(status_color, "●");

                            // Current value
                            let formatted_value = self.format_metric_value(metric.current_value, &metric.format);
                            ui.strong(&formatted_value);
                        });

                        // Trend indicator
                        if metric.current_value != metric.previous_value {
                            let is_up = metric.current_value > metric.previous_value;
                            let trend_symbol = if is_up { "↗" } else { "↘" };
                            let trend_color = if is_up { egui::Color32::RED } else { egui::Color32::GREEN };

                            let change = ((metric.current_value - metric.previous_value) / metric.previous_value * 100.0).abs();
                            ui.horizontal(|ui| {
                                ui.colored_label(trend_color, trend_symbol);
                                ui.small(&format!("{:.1}%", change));
                            });
                        } else {
                            ui.small("→ No change");
                        }
                    });
                });
        }
    }

    fn render_storage_overview_card(&self, ui: &mut egui::Ui, name: &str, value: f64, format: DisplayFormat) {
        egui::Frame::none()
            .fill(egui::Color32::from_gray(240))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(200)))
            .rounding(egui::Rounding::same(6.0))
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.set_min_width(120.0);
                ui.set_min_height(80.0);

                ui.vertical_centered(|ui| {
                    ui.small(name);
                    let formatted_value = self.format_metric_value(value, &format);
                    ui.strong(&formatted_value);
                });
            });
    }

    fn render_time_series_chart(&mut self, ui: &mut egui::Ui, title: &str, series_keys: &[&str]) {
        ui.group(|ui| {
            ui.set_height(200.0);
            ui.strong(title);

            Plot::new(format!("plot_{}", title))
                .legend(Legend::default())
                .show(ui, |plot_ui| {
                    for &key in series_keys {
                        if let Some(series) = self.time_series_data.get(key) {
                            if !series.data_points.is_empty() {
                                let points: PlotPoints = series.data_points
                                    .iter()
                                    .enumerate()
                                    .map(|(i, point)| [i as f64, point.value])
                                    .collect();

                                plot_ui.line(
                                    Line::new(points)
                                        .name(&series.name)
                                        .color(series.color)
                                );
                            }
                        }
                    }
                });
        });
    }

    fn render_storage_distribution_chart(&self, ui: &mut egui::Ui, title: &str, data: &HashMap<String, u64>) {
        ui.group(|ui| {
            ui.set_height(200.0);
            ui.strong(title);

            if !data.is_empty() {
                Plot::new(format!("plot_{}", title))
                    .show(ui, |plot_ui| {
                        let bars: Vec<Bar> = data
                            .iter()
                            .enumerate()
                            .map(|(i, (name, &value))| {
                                Bar::new(i as f64, value as f64).name(name)
                            })
                            .collect();

                        plot_ui.bar_chart(BarChart::new(bars));
                    });
            } else {
                ui.label("No data available");
            }
        });
    }

    fn render_operations_chart(&self, ui: &mut egui::Ui, title: &str, data: &HashMap<String, u64>) {
        ui.group(|ui| {
            ui.set_height(150.0);
            ui.strong(title);

            ui.horizontal_wrapped(|ui| {
                for (operation, &count) in data {
                    ui.group(|ui| {
                        ui.vertical_centered(|ui| {
                            ui.small(operation);
                            ui.strong(&format!("{}", count));
                        });
                    });
                }
            });
        });
    }

    fn format_metric_value(&self, value: f64, format: &DisplayFormat) -> String {
        match format {
            DisplayFormat::Integer => format!("{:.0}", value),
            DisplayFormat::Decimal(places) => format!("{:.1$}", value, *places as usize),
            DisplayFormat::Percentage => format!("{:.1}%", value),
            DisplayFormat::Bytes => self.format_bytes(value),
            DisplayFormat::Duration => format!("{:.1}ms", value),
            DisplayFormat::Rate => format!("{:.1}/s", value),
        }
    }

    fn format_bytes(&self, bytes: f64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
        let mut size = bytes;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        format!("{:.1} {}", size, UNITS[unit_index])
    }

    /// Generate mock data for testing
    pub fn generate_mock_data(&mut self) {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Generate realistic system metrics
        let cpu = 20.0 + rng.gen::<f64>() * 60.0; // 20-80%
        let memory = 40.0 + rng.gen::<f64>() * 40.0; // 40-80%
        let disk = 30.0 + rng.gen::<f64>() * 50.0; // 30-80%
        let net_in = rng.gen::<f64>() * 10.0; // 0-10 MB/s
        let net_out = rng.gen::<f64>() * 5.0; // 0-5 MB/s
        let storage_ops = rng.gen::<f64>() * 100.0; // 0-100 ops/s
        let error_rate = rng.gen::<f64>() * 2.0; // 0-2%
        let response_time = 10.0 + rng.gen::<f64>() * 40.0; // 10-50ms

        self.update_metric("cpu_usage", cpu);
        self.update_metric("memory_usage", memory);
        self.update_metric("disk_usage", disk);
        self.update_metric("network_in", net_in);
        self.update_metric("network_out", net_out);
        self.update_metric("storage_ops", storage_ops);
        self.update_metric("error_rate", error_rate);
        self.update_metric("response_time", response_time);

        // Update active connections
        if let Some(metric) = self.metric_displays.get_mut("active_connections") {
            metric.previous_value = metric.current_value;
            metric.current_value = (50 + rng.gen::<u32>() % 100) as f64;
        }

        // Update status after metric update
        if let Some(metric) = self.metric_displays.get("active_connections") {
            let status = self.calculate_metric_status(metric);
            if let Some(metric_mut) = self.metric_displays.get_mut("active_connections") {
                metric_mut.status = status;
            }
        }
    }

    /// Real-time status indicator
    pub fn render_status_indicator(&self, ui: &mut egui::Ui, key: &str) {
        if let Some(metric) = self.metric_displays.get(key) {
            let (color, symbol) = match metric.status {
                MetricStatus::Healthy => (egui::Color32::GREEN, "✓"),
                MetricStatus::Warning => (egui::Color32::from_rgb(255, 193, 7), "⚠"),
                MetricStatus::Critical => (egui::Color32::RED, "✗"),
                MetricStatus::Unknown => (egui::Color32::GRAY, "?"),
            };

            ui.horizontal(|ui| {
                ui.colored_label(color, symbol);
                ui.label(&metric.name);
            });
        }
    }
}

