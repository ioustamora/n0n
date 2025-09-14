use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressiveDisclosure {
    pub show_advanced: bool,
    pub expert_mode: bool,
}

impl Default for ProgressiveDisclosure {
    fn default() -> Self {
        Self {
            show_advanced: false,
            expert_mode: false,
        }
    }
}

impl ProgressiveDisclosure {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_expert_mode(mut self, expert_mode: bool) -> Self {
        self.expert_mode = expert_mode;
        if expert_mode {
            self.show_advanced = true; // Expert mode shows all options by default
        }
        self
    }

    pub fn toggle_advanced(&mut self) {
        if !self.expert_mode {
            self.show_advanced = !self.show_advanced;
        }
    }

    pub fn should_show_advanced(&self) -> bool {
        self.show_advanced || self.expert_mode
    }

    /// Renders a section with progressive disclosure
    /// basic_ui: Always shown UI elements
    /// advanced_ui: UI elements shown only when advanced is enabled
    pub fn render_section<T>(
        &mut self,
        ui: &mut egui::Ui,
        basic_ui: impl FnOnce(&mut egui::Ui) -> T,
        advanced_ui: impl FnOnce(&mut egui::Ui) -> T,
    ) -> (T, Option<T>) {
        let basic_result = basic_ui(ui);

        if !self.expert_mode {
            ui.separator();
            ui.horizontal(|ui| {
                let button_text = if self.show_advanced {
                    "🔽 Hide Advanced Options"
                } else {
                    "🔧 Show Advanced Options"
                };

                if ui.button(button_text).clicked() {
                    self.toggle_advanced();
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.small("Tip: Enable Expert Mode in Settings to always show all options");
                });
            });
        }

        let advanced_result = if self.should_show_advanced() {
            ui.separator();
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                if !self.expert_mode {
                    ui.horizontal(|ui| {
                        ui.small("Advanced Options");
                        ui.separator();
                    });
                }
                Some(advanced_ui(ui))
            }).inner
        } else {
            None
        };

        (basic_result, advanced_result)
    }

    /// Renders a collapsible group with progressive disclosure
    pub fn render_collapsible_section<T, F1, F2>(
        &mut self,
        ui: &mut egui::Ui,
        title: &str,
        basic_ui: F1,
        advanced_ui: F2,
    ) -> (Option<T>, Option<T>)
    where
        F1: FnOnce(&mut egui::Ui) -> T,
        F2: FnOnce(&mut egui::Ui) -> T,
    {
        let response = ui.collapsing(title, |ui| {
            self.render_section(ui, basic_ui, advanced_ui)
        });

        if let Some((basic_result, advanced_result)) = response.body_returned {
            (Some(basic_result), advanced_result)
        } else {
            (None, None)
        }
    }

    /// Renders advanced options in a separate tab
    pub fn render_tabbed_section<T>(
        &mut self,
        ui: &mut egui::Ui,
        basic_tab_name: &str,
        advanced_tab_name: &str,
        selected_tab: &mut usize,
        basic_ui: impl FnOnce(&mut egui::Ui) -> T,
        advanced_ui: impl FnOnce(&mut egui::Ui) -> T,
    ) -> (Option<T>, Option<T>) {
        ui.horizontal(|ui| {
            ui.selectable_value(selected_tab, 0, basic_tab_name);
            if self.should_show_advanced() || self.expert_mode {
                ui.selectable_value(selected_tab, 1, advanced_tab_name);
            }
        });

        ui.separator();

        match *selected_tab {
            0 => (Some(basic_ui(ui)), None),
            1 if self.should_show_advanced() || self.expert_mode => (None, Some(advanced_ui(ui))),
            _ => {
                *selected_tab = 0; // Reset to basic tab if advanced is not available
                (Some(basic_ui(ui)), None)
            }
        }
    }

    /// Helper for rendering form fields with progressive disclosure
    pub fn render_form_field(
        &self,
        ui: &mut egui::Ui,
        label: &str,
        widget: impl FnOnce(&mut egui::Ui),
        is_advanced: bool,
    ) {
        if !is_advanced || self.should_show_advanced() {
            ui.horizontal(|ui| {
                ui.label(label);
                if is_advanced && !self.expert_mode {
                    ui.small("(Advanced)");
                }
            });
            widget(ui);
            ui.add_space(5.0);
        }
    }

    /// Render a help text that's only shown for advanced options
    pub fn render_advanced_help(&self, ui: &mut egui::Ui, help_text: &str) {
        if self.should_show_advanced() {
            ui.horizontal(|ui| {
                ui.small("ℹ");
                ui.small(help_text);
            });
            ui.add_space(3.0);
        }
    }

    /// Render a warning for advanced options
    pub fn render_advanced_warning(&self, ui: &mut egui::Ui, warning_text: &str) {
        if self.should_show_advanced() {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::from_rgb(255, 193, 7), "⚠");
                ui.small(warning_text);
            });
            ui.add_space(3.0);
        }
    }
}

/// A helper trait for widgets that support progressive disclosure
pub trait ProgressiveWidget {
    fn is_advanced(&self) -> bool;
    fn render(&mut self, ui: &mut egui::Ui, disclosure: &ProgressiveDisclosure);
}

/// A container for managing multiple progressive disclosure states
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProgressiveDisclosureManager {
    pub global_expert_mode: bool,
    pub section_states: std::collections::HashMap<String, bool>, // section_id -> show_advanced
}

impl ProgressiveDisclosureManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_expert_mode(&mut self, enabled: bool) {
        self.global_expert_mode = enabled;
    }

    pub fn get_disclosure(&self, section_id: &str) -> ProgressiveDisclosure {
        let show_advanced = self.section_states.get(section_id).copied().unwrap_or(false);
        ProgressiveDisclosure {
            show_advanced,
            expert_mode: self.global_expert_mode,
        }
    }

    pub fn set_section_advanced(&mut self, section_id: String, show_advanced: bool) {
        if !self.global_expert_mode {
            self.section_states.insert(section_id, show_advanced);
        }
    }

    pub fn toggle_section_advanced(&mut self, section_id: String) {
        if !self.global_expert_mode {
            let current = self.section_states.get(&section_id).copied().unwrap_or(false);
            self.section_states.insert(section_id, !current);
        }
    }

    /// Render a section with managed progressive disclosure
    pub fn render_managed_section<T>(
        &mut self,
        ui: &mut egui::Ui,
        section_id: &str,
        basic_ui: impl FnOnce(&mut egui::Ui) -> T,
        advanced_ui: impl FnOnce(&mut egui::Ui) -> T,
    ) -> (T, Option<T>) {
        let mut disclosure = self.get_disclosure(section_id);
        let (basic_result, advanced_result) = disclosure.render_section(ui, basic_ui, advanced_ui);

        // Update the state
        if !self.global_expert_mode {
            self.section_states.insert(section_id.to_string(), disclosure.show_advanced);
        }

        (basic_result, advanced_result)
    }
}