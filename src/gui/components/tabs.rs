use egui::{Color32, Ui, Vec2, Rect, Pos2, Rounding, Stroke, Response};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Transition state for smooth tab switching
#[derive(Debug, Clone, PartialEq)]
pub enum TransitionState {
    Idle,
    Switching {
        from_tab: usize,
        to_tab: usize,
        progress: f32,
        start_time: Instant,
    },
    Loading {
        tab: usize,
        progress: f32
    },
}

impl Default for TransitionState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Configuration for tab appearance and behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabConfig {
    pub show_icons: bool,
    pub show_badges: bool,
    pub enable_animations: bool,
    pub tab_height: f32,
    pub tab_spacing: f32,
    pub transition_duration: Duration,
    pub keyboard_shortcuts: bool,
}

impl Default for TabConfig {
    fn default() -> Self {
        Self {
            show_icons: true,
            show_badges: true,
            enable_animations: true,
            tab_height: 36.0,
            tab_spacing: 4.0,
            transition_duration: Duration::from_millis(200),
            keyboard_shortcuts: true,
        }
    }
}

/// Individual tab data
#[derive(Debug, Clone)]
pub struct Tab<T: Clone> {
    pub id: T,
    pub label: String,
    pub icon: Option<String>,
    pub badge: Option<String>,
    pub badge_color: Option<Color32>,
    pub disabled: bool,
    pub loading: bool,
    pub has_unsaved_changes: bool,
    pub tooltip: Option<String>,
}

impl<T: Clone> Tab<T> {
    pub fn new(id: T, label: impl Into<String>) -> Self {
        Self {
            id,
            label: label.into(),
            icon: None,
            badge: None,
            badge_color: None,
            disabled: false,
            loading: false,
            has_unsaved_changes: false,
            tooltip: None,
        }
    }

    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    pub fn with_badge(mut self, badge: impl Into<String>, color: Option<Color32>) -> Self {
        self.badge = Some(badge.into());
        self.badge_color = color;
        self
    }

    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }

    pub fn disabled(mut self) -> Self {
        self.disabled = true;
        self
    }

    pub fn loading(mut self) -> Self {
        self.loading = true;
        self
    }

    pub fn with_unsaved_changes(mut self) -> Self {
        self.has_unsaved_changes = true;
        self
    }
}

/// Main tab system component
pub struct TabSystem<T: Clone + PartialEq> {
    tabs: Vec<Tab<T>>,
    active_tab_index: usize,
    config: TabConfig,
    transition_state: TransitionState,
    hover_tab: Option<usize>,
    focus_tab: Option<usize>,
    last_interaction_time: Instant,
}

impl<T: Clone + PartialEq> TabSystem<T> {
    pub fn new(tabs: Vec<Tab<T>>, config: TabConfig) -> Self {
        Self {
            tabs,
            active_tab_index: 0,
            config,
            transition_state: TransitionState::Idle,
            hover_tab: None,
            focus_tab: None,
            last_interaction_time: Instant::now(),
        }
    }

    pub fn with_active_tab(mut self, tab_id: &T) -> Self {
        if let Some(index) = self.tabs.iter().position(|tab| &tab.id == tab_id) {
            self.active_tab_index = index;
        }
        self
    }

    /// Get the currently active tab
    pub fn active_tab(&self) -> Option<&Tab<T>> {
        self.tabs.get(self.active_tab_index)
    }

    /// Get the currently active tab ID
    pub fn active_tab_id(&self) -> Option<&T> {
        self.active_tab().map(|tab| &tab.id)
    }

    /// Set the active tab by ID with transition
    pub fn set_active_tab(&mut self, tab_id: &T) -> bool {
        if let Some(new_index) = self.tabs.iter().position(|tab| &tab.id == tab_id) {
            if new_index != self.active_tab_index && !self.tabs[new_index].disabled {
                self.start_transition(new_index);
                return true;
            }
        }
        false
    }

    /// Start transition to new tab
    fn start_transition(&mut self, to_tab: usize) {
        if self.config.enable_animations {
            self.transition_state = TransitionState::Switching {
                from_tab: self.active_tab_index,
                to_tab,
                progress: 0.0,
                start_time: Instant::now(),
            };
        } else {
            self.active_tab_index = to_tab;
            self.transition_state = TransitionState::Idle;
        }
    }

    /// Update transition animations
    fn update_transitions(&mut self) {
        match &self.transition_state {
            TransitionState::Switching { from_tab, to_tab, start_time, .. } => {
                let elapsed = start_time.elapsed();
                let progress = (elapsed.as_millis() as f32 / self.config.transition_duration.as_millis() as f32).min(1.0);

                if progress >= 1.0 {
                    self.active_tab_index = *to_tab;
                    self.transition_state = TransitionState::Idle;
                } else {
                    self.transition_state = TransitionState::Switching {
                        from_tab: *from_tab,
                        to_tab: *to_tab,
                        progress,
                        start_time: *start_time,
                    };
                }
            }
            TransitionState::Loading { .. } => {
                // Handle loading state updates
            }
            TransitionState::Idle => {}
        }
    }

    /// Check if currently transitioning
    pub fn is_transitioning(&self) -> bool {
        !matches!(self.transition_state, TransitionState::Idle)
    }

    /// Render the tab bar
    pub fn render(&mut self, ui: &mut Ui) -> Option<T> {
        self.update_transitions();

        let mut clicked_tab = None;

        // Handle keyboard input
        if self.config.keyboard_shortcuts {
            self.handle_keyboard_input(ui);
        }

        ui.horizontal(|ui| {
            let available_width = ui.available_width();
            let tab_width = (available_width - (self.tabs.len() as f32 - 1.0) * self.config.tab_spacing) / self.tabs.len() as f32;

            for (index, tab) in self.tabs.iter().enumerate() {
                if index > 0 {
                    ui.add_space(self.config.tab_spacing);
                }

                let tab_rect = Rect::from_min_size(
                    ui.cursor().min,
                    Vec2::new(tab_width, self.config.tab_height),
                );

                let response = self.render_tab(ui, tab, index, tab_rect);

                if response.clicked() && !tab.disabled {
                    clicked_tab = Some(tab.id.clone());
                }

                // Update hover state
                if response.hovered() {
                    self.hover_tab = Some(index);
                } else if self.hover_tab == Some(index) && !response.hovered() {
                    self.hover_tab = None;
                }
            }
        });

        // Handle tab change
        if let Some(tab_id) = &clicked_tab {
            self.set_active_tab(tab_id);
        }

        clicked_tab
    }

    /// Render individual tab
    fn render_tab(&self, ui: &mut Ui, tab: &Tab<T>, index: usize, rect: Rect) -> Response {
        let is_active = index == self.active_tab_index;
        let is_hovered = self.hover_tab == Some(index);
        let is_focused = self.focus_tab == Some(index);

        // Calculate colors based on state
        let (bg_color, text_color, border_color) = self.get_tab_colors(is_active, is_hovered, tab.disabled);

        // Draw tab background
        let rounding = if is_active {
            Rounding::same(8.0)
        } else {
            Rounding::same(6.0)
        };

        ui.painter().rect_filled(rect, rounding, bg_color);

        // Draw border
        if is_active || is_focused {
            ui.painter().rect_stroke(rect, rounding, Stroke::new(2.0, border_color));
        }

        // Draw transition indicator
        if let TransitionState::Switching { to_tab, progress, .. } = &self.transition_state {
            if index == *to_tab {
                let indicator_height = 3.0;
                let indicator_width = rect.width() * progress;
                let indicator_rect = Rect::from_min_size(
                    Pos2::new(rect.left(), rect.bottom() - indicator_height),
                    Vec2::new(indicator_width, indicator_height),
                );
                ui.painter().rect_filled(indicator_rect, Rounding::ZERO, Color32::from_rgb(0, 122, 255));
            }
        }

        // Prepare text content
        let mut text_content = String::new();

        // Add icon
        if let Some(icon) = &tab.icon {
            if self.config.show_icons {
                text_content.push_str(icon);
                text_content.push(' ');
            }
        }

        // Add label
        text_content.push_str(&tab.label);

        // Add unsaved changes indicator
        if tab.has_unsaved_changes {
            text_content.push_str(" •");
        }

        // Add loading indicator
        if tab.loading {
            text_content.push_str(" ⟳");
        }

        // Draw text content
        let text_rect = rect.shrink(8.0);
        ui.painter().text(
            text_rect.center(),
            egui::Align2::CENTER_CENTER,
            text_content,
            egui::FontId::default(),
            text_color,
        );

        // Draw badge
        if let Some(badge) = &tab.badge {
            if self.config.show_badges {
                let badge_color = tab.badge_color.unwrap_or(Color32::from_rgb(255, 59, 48));
                let badge_pos = Pos2::new(rect.right() - 12.0, rect.top() + 6.0);
                let badge_rect = Rect::from_center_size(badge_pos, Vec2::new(16.0, 16.0));

                ui.painter().circle_filled(badge_pos, 8.0, badge_color);
                ui.painter().text(
                    badge_pos,
                    egui::Align2::CENTER_CENTER,
                    badge,
                    egui::FontId::proportional(10.0),
                    Color32::WHITE,
                );
            }
        }

        // Create response for interaction
        let mut response = ui.allocate_rect(rect, egui::Sense::click());

        // Add tooltip
        if let Some(tooltip) = &tab.tooltip {
            response = response.on_hover_text(tooltip);
        }

        response
    }

    /// Get appropriate colors for tab state
    fn get_tab_colors(&self, is_active: bool, is_hovered: bool, is_disabled: bool) -> (Color32, Color32, Color32) {
        if is_disabled {
            (
                Color32::from_gray(50),
                Color32::from_gray(120),
                Color32::from_gray(80),
            )
        } else if is_active {
            (
                Color32::from_rgb(0, 122, 255),
                Color32::WHITE,
                Color32::from_rgb(0, 122, 255),
            )
        } else if is_hovered {
            (
                Color32::from_gray(230),
                Color32::from_gray(60),
                Color32::from_gray(180),
            )
        } else {
            (
                Color32::from_gray(250),
                Color32::from_gray(80),
                Color32::from_gray(200),
            )
        }
    }

    /// Handle keyboard navigation
    fn handle_keyboard_input(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx();

        // Tab navigation with Ctrl+1-9
        for i in 1..=9 {
            let key = match i {
                1 => egui::Key::Num1,
                2 => egui::Key::Num2,
                3 => egui::Key::Num3,
                4 => egui::Key::Num4,
                5 => egui::Key::Num5,
                6 => egui::Key::Num6,
                7 => egui::Key::Num7,
                8 => egui::Key::Num8,
                9 => egui::Key::Num9,
                _ => continue,
            };

            if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, key)) {
                let tab_index = i - 1;
                if tab_index < self.tabs.len() && !self.tabs[tab_index].disabled {
                    self.start_transition(tab_index);
                }
            }
        }

        // Arrow key navigation
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowLeft)) {
            self.navigate_previous();
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowRight)) {
            self.navigate_next();
        }
    }

    /// Navigate to previous tab
    fn navigate_previous(&mut self) {
        if self.active_tab_index > 0 {
            let mut new_index = self.active_tab_index - 1;
            while new_index > 0 && self.tabs[new_index].disabled {
                new_index -= 1;
            }
            if !self.tabs[new_index].disabled {
                self.start_transition(new_index);
            }
        }
    }

    /// Navigate to next tab
    fn navigate_next(&mut self) {
        if self.active_tab_index < self.tabs.len() - 1 {
            let mut new_index = self.active_tab_index + 1;
            while new_index < self.tabs.len() - 1 && self.tabs[new_index].disabled {
                new_index += 1;
            }
            if new_index < self.tabs.len() && !self.tabs[new_index].disabled {
                self.start_transition(new_index);
            }
        }
    }

    /// Update tab state (loading, badges, etc.)
    pub fn update_tab(&mut self, tab_id: &T, update_fn: impl FnOnce(&mut Tab<T>)) {
        if let Some(index) = self.tabs.iter_mut().position(|tab| &tab.id == tab_id) {
            update_fn(&mut self.tabs[index]);
        }
    }

    /// Set loading state for a tab
    pub fn set_tab_loading(&mut self, tab_id: &T, loading: bool) {
        self.update_tab(tab_id, |tab| tab.loading = loading);
    }

    /// Set unsaved changes state for a tab
    pub fn set_tab_unsaved_changes(&mut self, tab_id: &T, has_changes: bool) {
        self.update_tab(tab_id, |tab| tab.has_unsaved_changes = has_changes);
    }

    /// Get transition progress (0.0 to 1.0)
    pub fn transition_progress(&self) -> f32 {
        match &self.transition_state {
            TransitionState::Switching { progress, .. } => *progress,
            _ => 1.0,
        }
    }
}

impl<T: Clone + PartialEq> Default for TabSystem<T> {
    fn default() -> Self {
        Self {
            tabs: Vec::new(),
            active_tab_index: 0,
            config: TabConfig::default(),
            transition_state: TransitionState::Idle,
            hover_tab: None,
            focus_tab: None,
            last_interaction_time: Instant::now(),
        }
    }
}