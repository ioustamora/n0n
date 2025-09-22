use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationLevel {
    Success,
    Info,
    Warning,
    Error,
}

impl NotificationLevel {
    pub fn color(&self) -> egui::Color32 {
        match self {
            Self::Success => egui::Color32::from_rgb(46, 160, 67),  // Green
            Self::Info => egui::Color32::from_rgb(54, 162, 235),    // Blue
            Self::Warning => egui::Color32::from_rgb(255, 193, 7),  // Amber
            Self::Error => egui::Color32::from_rgb(220, 53, 69),    // Red
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::Success => "✓",
            Self::Info => "ℹ",
            Self::Warning => "⚠",
            Self::Error => "✗",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationAction {
    pub label: String,
    pub action: String, // Action identifier for handling
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub level: NotificationLevel,
    pub title: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub dismissable: bool,
    pub actions: Vec<NotificationAction>,
    pub context: Option<String>, // Context for contextual notifications
}

impl Notification {
    pub fn new(level: NotificationLevel, title: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            level,
            title: title.into(),
            message: message.into(),
            timestamp: Utc::now(),
            dismissable: true,
            actions: Vec::new(),
            context: None,
        }
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    pub fn with_action(mut self, label: impl Into<String>, action: impl Into<String>) -> Self {
        self.actions.push(NotificationAction {
            label: label.into(),
            action: action.into(),
        });
        self
    }

    pub fn non_dismissable(mut self) -> Self {
        self.dismissable = false;
        self
    }

    pub fn success(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(NotificationLevel::Success, title, message)
    }

    pub fn info(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(NotificationLevel::Info, title, message)
    }

    pub fn warning(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(NotificationLevel::Warning, title, message)
    }

    pub fn error(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(NotificationLevel::Error, title, message)
    }
}

#[derive(Debug, Default)]
pub struct NotificationManager {
    notifications: VecDeque<Notification>,
    toast_notifications: VecDeque<Notification>,
    contextual_notifications: std::collections::HashMap<String, Notification>,
    max_notifications: usize,
    toast_duration_secs: u64,
}

impl NotificationManager {
    pub fn new() -> Self {
        Self {
            notifications: VecDeque::new(),
            toast_notifications: VecDeque::new(),
            contextual_notifications: std::collections::HashMap::new(),
            max_notifications: 100,
            toast_duration_secs: 5,
        }
    }

    pub fn add_notification(&mut self, notification: Notification) {
        if let Some(context) = &notification.context {
            // Contextual notification
            self.contextual_notifications.insert(context.clone(), notification);
        } else {
            // Global notification
            self.notifications.push_back(notification.clone());

            // Also add to toast if it's a recent notification
            if notification.dismissable {
                self.toast_notifications.push_back(notification);
            }
        }

        // Limit the number of stored notifications
        while self.notifications.len() > self.max_notifications {
            self.notifications.pop_front();
        }

        while self.toast_notifications.len() > 10 {
            self.toast_notifications.pop_front();
        }
    }

    pub fn get_contextual_notification(&self, context: &str) -> Option<&Notification> {
        self.contextual_notifications.get(context)
    }

    pub fn clear_contextual_notification(&mut self, context: &str) {
        self.contextual_notifications.remove(context);
    }

    pub fn dismiss_notification(&mut self, notification_id: &str) {
        self.notifications.retain(|n| n.id != notification_id);
        self.toast_notifications.retain(|n| n.id != notification_id);
    }

    pub fn clear_old_toasts(&mut self) {
        let now = Utc::now();
        self.toast_notifications.retain(|n| {
            let age = now.signed_duration_since(n.timestamp);
            age.num_seconds() < self.toast_duration_secs as i64
        });
    }

    pub fn render_contextual_status(&mut self, ui: &mut egui::Ui, context: &str) {
        if let Some(notification) = self.get_contextual_notification(context).cloned() {
            let mut should_dismiss = false;

            ui.horizontal(|ui| {
                ui.colored_label(notification.level.color(), notification.level.icon());
                ui.label(&notification.message);

                for action in &notification.actions {
                    if ui.small_button(&action.label).clicked() {
                        // Handle action (would need callback system in real implementation)
                        // For now, just clear the notification
                        should_dismiss = true;
                    }
                }

                if notification.dismissable && ui.small_button("✕").clicked() {
                    should_dismiss = true;
                }
            });

            if should_dismiss {
                self.clear_contextual_notification(context);
            }
        }
    }

    pub fn render_toast_notifications(&mut self, ctx: &egui::Context) {
        self.clear_old_toasts();

        if !self.toast_notifications.is_empty() {
            egui::Area::new(egui::Id::new("toast_notifications"))
                .fixed_pos(egui::pos2(10.0, 10.0))
                .show(ctx, |ui| {
                    ui.set_max_width(400.0);

                    let toast_notifications = self.toast_notifications.clone();
                    let mut notifications_to_dismiss = Vec::new();

                    for notification in &toast_notifications {
                        ui.group(|ui| {
                            ui.set_width(380.0);

                            ui.horizontal(|ui| {
                                ui.colored_label(notification.level.color(), notification.level.icon());
                                ui.vertical(|ui| {
                                    ui.strong(&notification.title);
                                    ui.label(&notification.message);

                                    if !notification.actions.is_empty() {
                                        ui.horizontal(|ui| {
                                            for action in &notification.actions {
                                                if ui.small_button(&action.label).clicked() {
                                                    // Handle action
                                                    notifications_to_dismiss.push(notification.id.clone());
                                                }
                                            }
                                        });
                                    }
                                });

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if notification.dismissable && ui.small_button("✕").clicked() {
                                        notifications_to_dismiss.push(notification.id.clone());
                                    }
                                });
                            });
                        });

                        ui.add_space(5.0);
                    }

                    // Dismiss notifications after the loop
                    for id in notifications_to_dismiss {
                        self.dismiss_notification(&id);
                    }
                });
        }
    }

    pub fn notification_count(&self) -> usize {
        self.notifications.len()
    }

    pub fn render_notification_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Notifications");

        if self.notifications.is_empty() {
            ui.label("No notifications");
        } else {
            egui::ScrollArea::vertical().show(ui, |ui| {
                let notifications = self.notifications.clone();
                let mut notifications_to_dismiss = Vec::new();

                for notification in &notifications {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(notification.level.color(), notification.level.icon());
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.strong(&notification.title);
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.small(&notification.timestamp.format("%H:%M:%S").to_string());
                                    });
                                });
                                ui.label(&notification.message);

                                if !notification.actions.is_empty() {
                                    ui.horizontal(|ui| {
                                        for action in &notification.actions {
                                            if ui.small_button(&action.label).clicked() {
                                                // Handle action
                                                notifications_to_dismiss.push(notification.id.clone());
                                            }
                                        }
                                    });
                                }
                            });

                            if notification.dismissable && ui.small_button("✕").clicked() {
                                notifications_to_dismiss.push(notification.id.clone());
                            }
                        });
                    });
                    ui.add_space(5.0);
                }

                // Dismiss notifications after the loop
                for id in notifications_to_dismiss {
                    self.dismiss_notification(&id);
                }
            });
        }
    }
}

// Helper functions for easy notification creation
impl NotificationManager {
    pub fn success(&mut self, title: impl Into<String>, message: impl Into<String>) {
        self.add_notification(Notification::success(title, message));
    }

    pub fn info(&mut self, title: impl Into<String>, message: impl Into<String>) {
        self.add_notification(Notification::info(title, message));
    }

    pub fn warning(&mut self, title: impl Into<String>, message: impl Into<String>) {
        self.add_notification(Notification::warning(title, message));
    }

    pub fn error(&mut self, title: impl Into<String>, message: impl Into<String>) {
        self.add_notification(Notification::error(title, message));
    }

    pub fn contextual_success(&mut self, context: impl Into<String>, title: impl Into<String>, message: impl Into<String>) {
        self.add_notification(Notification::success(title, message).with_context(context));
    }

    pub fn contextual_error(&mut self, context: impl Into<String>, title: impl Into<String>, message: impl Into<String>) {
        self.add_notification(Notification::error(title, message).with_context(context));
    }
}