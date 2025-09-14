use egui::{Color32, TextStyle, Rounding, Stroke, emath::Rect};
use serde::{Deserialize, Serialize};

// Custom serialization for Color32
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableColor32 {
    r: u8,
    g: u8,
    b: u8,
    a: u8,
}

impl From<Color32> for SerializableColor32 {
    fn from(color: Color32) -> Self {
        let [r, g, b, a] = color.to_array();
        SerializableColor32 { r, g, b, a }
    }
}

impl From<SerializableColor32> for Color32 {
    fn from(color: SerializableColor32) -> Self {
        Color32::from_rgba_unmultiplied(color.r, color.g, color.b, color.a)
    }
}

/// Design tokens for consistent styling across the application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesignSystem {
    // Color palette
    pub colors: ColorPalette,
    // Typography
    pub typography: Typography,
    // Spacing
    pub spacing: Spacing,
    // Visual effects
    pub effects: Effects,
}

impl DesignSystem {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
pub struct ColorPalette {
    // Primary brand colors
    pub primary: Color32,
    pub primary_hover: Color32,
    pub primary_pressed: Color32,

    // Secondary colors
    pub secondary: Color32,
    pub secondary_hover: Color32,
    pub secondary_pressed: Color32,

    // Semantic colors
    pub success: Color32,
    pub warning: Color32,
    pub error: Color32,
    pub info: Color32,

    // Neutral colors
    pub background: Color32,
    pub surface: Color32,
    pub surface_hover: Color32,
    pub border: Color32,
    pub text_primary: Color32,
    pub text_secondary: Color32,
    pub text_disabled: Color32,
}

// Manual serialization implementation for ColorPalette
impl Serialize for ColorPalette {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ColorPalette", 16)?;
        state.serialize_field("primary", &SerializableColor32::from(self.primary))?;
        state.serialize_field("primary_hover", &SerializableColor32::from(self.primary_hover))?;
        state.serialize_field("primary_pressed", &SerializableColor32::from(self.primary_pressed))?;
        state.serialize_field("secondary", &SerializableColor32::from(self.secondary))?;
        state.serialize_field("secondary_hover", &SerializableColor32::from(self.secondary_hover))?;
        state.serialize_field("secondary_pressed", &SerializableColor32::from(self.secondary_pressed))?;
        state.serialize_field("success", &SerializableColor32::from(self.success))?;
        state.serialize_field("warning", &SerializableColor32::from(self.warning))?;
        state.serialize_field("error", &SerializableColor32::from(self.error))?;
        state.serialize_field("info", &SerializableColor32::from(self.info))?;
        state.serialize_field("background", &SerializableColor32::from(self.background))?;
        state.serialize_field("surface", &SerializableColor32::from(self.surface))?;
        state.serialize_field("surface_hover", &SerializableColor32::from(self.surface_hover))?;
        state.serialize_field("border", &SerializableColor32::from(self.border))?;
        state.serialize_field("text_primary", &SerializableColor32::from(self.text_primary))?;
        state.serialize_field("text_secondary", &SerializableColor32::from(self.text_secondary))?;
        state.serialize_field("text_disabled", &SerializableColor32::from(self.text_disabled))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ColorPalette {
    fn deserialize<D>(deserializer: D) -> Result<ColorPalette, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct ColorPaletteVisitor;

        impl<'de> Visitor<'de> for ColorPaletteVisitor {
            type Value = ColorPalette;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ColorPalette")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ColorPalette, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut palette = ColorPalette::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "primary" => palette.primary = map.next_value::<SerializableColor32>()?.into(),
                        "primary_hover" => palette.primary_hover = map.next_value::<SerializableColor32>()?.into(),
                        "primary_pressed" => palette.primary_pressed = map.next_value::<SerializableColor32>()?.into(),
                        "secondary" => palette.secondary = map.next_value::<SerializableColor32>()?.into(),
                        "secondary_hover" => palette.secondary_hover = map.next_value::<SerializableColor32>()?.into(),
                        "secondary_pressed" => palette.secondary_pressed = map.next_value::<SerializableColor32>()?.into(),
                        "success" => palette.success = map.next_value::<SerializableColor32>()?.into(),
                        "warning" => palette.warning = map.next_value::<SerializableColor32>()?.into(),
                        "error" => palette.error = map.next_value::<SerializableColor32>()?.into(),
                        "info" => palette.info = map.next_value::<SerializableColor32>()?.into(),
                        "background" => palette.background = map.next_value::<SerializableColor32>()?.into(),
                        "surface" => palette.surface = map.next_value::<SerializableColor32>()?.into(),
                        "surface_hover" => palette.surface_hover = map.next_value::<SerializableColor32>()?.into(),
                        "border" => palette.border = map.next_value::<SerializableColor32>()?.into(),
                        "text_primary" => palette.text_primary = map.next_value::<SerializableColor32>()?.into(),
                        "text_secondary" => palette.text_secondary = map.next_value::<SerializableColor32>()?.into(),
                        "text_disabled" => palette.text_disabled = map.next_value::<SerializableColor32>()?.into(),
                        _ => { let _: serde_json::Value = map.next_value()?; } // Skip unknown fields
                    }
                }

                Ok(palette)
            }
        }

        deserializer.deserialize_struct("ColorPalette", &[
            "primary", "primary_hover", "primary_pressed", "secondary", "secondary_hover", "secondary_pressed",
            "success", "warning", "error", "info", "background", "surface", "surface_hover", "border",
            "text_primary", "text_secondary", "text_disabled"
        ], ColorPaletteVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Typography {
    pub heading_1: f32,
    pub heading_2: f32,
    pub heading_3: f32,
    pub body: f32,
    pub small: f32,
    pub caption: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spacing {
    pub xs: f32,
    pub sm: f32,
    pub md: f32,
    pub lg: f32,
    pub xl: f32,
    pub xxl: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Effects {
    pub border_radius: f32,
    pub shadow_blur: f32,
    pub shadow_spread: f32,
    pub shadow_offset: (f32, f32),
    #[serde(skip)]
    pub shadow_elevation_1: epaint::Shadow,
    #[serde(skip)]
    pub shadow_elevation_2: epaint::Shadow,
}

impl Default for DesignSystem {
    fn default() -> Self {
        Self {
            colors: ColorPalette::default(),
            typography: Typography::default(),
            spacing: Spacing::default(),
            effects: Effects::default(),
        }
    }
}

impl Default for ColorPalette {
    fn default() -> Self {
        Self {
            primary: Color32::from_rgb(54, 162, 235),      // Professional blue
            primary_hover: Color32::from_rgb(43, 138, 212),
            primary_pressed: Color32::from_rgb(32, 114, 189),

            secondary: Color32::from_rgb(108, 117, 125),    // Neutral gray
            secondary_hover: Color32::from_rgb(88, 97, 105),
            secondary_pressed: Color32::from_rgb(68, 77, 85),

            success: Color32::from_rgb(40, 167, 69),        // Green
            warning: Color32::from_rgb(255, 193, 7),        // Amber
            error: Color32::from_rgb(220, 53, 69),          // Red
            info: Color32::from_rgb(23, 162, 184),          // Cyan

            background: Color32::from_rgb(248, 249, 250),   // Light gray
            surface: Color32::WHITE,
            surface_hover: Color32::from_rgb(245, 245, 245),
            border: Color32::from_rgb(222, 226, 230),
            text_primary: Color32::from_rgb(33, 37, 41),
            text_secondary: Color32::from_rgb(108, 117, 125),
            text_disabled: Color32::from_rgb(173, 181, 189),
        }
    }
}

impl Default for Typography {
    fn default() -> Self {
        Self {
            heading_1: 24.0,
            heading_2: 20.0,
            heading_3: 16.0,
            body: 14.0,
            small: 12.0,
            caption: 10.0,
        }
    }
}

impl Default for Spacing {
    fn default() -> Self {
        Self {
            xs: 4.0,
            sm: 8.0,
            md: 16.0,
            lg: 24.0,
            xl: 32.0,
            xxl: 48.0,
        }
    }
}

impl Default for Effects {
    fn default() -> Self {
        Self {
            border_radius: 6.0,
            shadow_blur: 8.0,
            shadow_spread: 0.0,
            shadow_offset: (0.0, 2.0),
            shadow_elevation_1: epaint::Shadow {
                offset: egui::Vec2::new(0.0, 2.0),
                blur: 8.0,
                spread: 0.0,
                color: Color32::from_black_alpha(30),
            },
            shadow_elevation_2: epaint::Shadow {
                offset: egui::Vec2::new(0.0, 4.0),
                blur: 16.0,
                spread: 0.0,
                color: Color32::from_black_alpha(40),
            },
        }
    }
}

/// Standardized UI components using the design system
pub struct ComponentLibrary;

impl ComponentLibrary {
    /// Primary button with consistent styling
    pub fn primary_button(text: String, design: &DesignSystem) -> egui::Button<'static> {
        egui::Button::new(text)
            .fill(design.colors.primary)
            .stroke(Stroke::NONE)
            .rounding(Rounding::same(design.effects.border_radius))
    }

    /// Secondary button with consistent styling
    pub fn secondary_button(text: String, design: &DesignSystem) -> egui::Button<'static> {
        egui::Button::new(text)
            .fill(design.colors.surface)
            .stroke(Stroke::new(1.0, design.colors.border))
            .rounding(Rounding::same(design.effects.border_radius))
    }

    /// Danger button for destructive actions
    pub fn danger_button(text: String, design: &DesignSystem) -> egui::Button<'static> {
        egui::Button::new(text)
            .fill(design.colors.error)
            .stroke(Stroke::NONE)
            .rounding(Rounding::same(design.effects.border_radius))
    }

    /// Success button for positive actions
    pub fn success_button(text: String, design: &DesignSystem) -> egui::Button<'static> {
        egui::Button::new(text)
            .fill(design.colors.success)
            .stroke(Stroke::NONE)
            .rounding(Rounding::same(design.effects.border_radius))
    }

    /// Card container with elevation
    pub fn card<R>(ui: &mut egui::Ui, design: &DesignSystem, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> egui::InnerResponse<R> {
        egui::Frame::none()
            .fill(design.colors.surface)
            .stroke(Stroke::new(1.0, design.colors.border))
            .rounding(Rounding::same(design.effects.border_radius))
            .shadow(design.effects.shadow_elevation_1)
            .inner_margin(design.spacing.md)
            .show(ui, add_contents)
    }

    /// Elevated card with more prominent shadow
    pub fn elevated_card<R>(ui: &mut egui::Ui, design: &DesignSystem, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> egui::InnerResponse<R> {
        egui::Frame::none()
            .fill(design.colors.surface)
            .stroke(Stroke::new(1.0, design.colors.border))
            .rounding(Rounding::same(design.effects.border_radius))
            .shadow(design.effects.shadow_elevation_2)
            .inner_margin(design.spacing.md)
            .show(ui, add_contents)
    }

    /// Status indicator with color coding
    pub fn status_indicator(ui: &mut egui::Ui, status: StatusType, text: &str, design: &DesignSystem) {
        let (color, icon) = match status {
            StatusType::Success => (design.colors.success, "✓"),
            StatusType::Warning => (design.colors.warning, "⚠"),
            StatusType::Error => (design.colors.error, "✗"),
            StatusType::Info => (design.colors.info, "ℹ"),
            StatusType::Active => (design.colors.primary, "●"),
        };

        ui.horizontal(|ui| {
            ui.colored_label(color, icon);
            ui.label(text);
        });
    }

    /// Progress bar with consistent styling
    pub fn progress_bar(ui: &mut egui::Ui, progress: f32, text: Option<&str>, design: &DesignSystem) {
        let progress_bar = egui::ProgressBar::new(progress)
            .fill(design.colors.primary)
            .rounding(Rounding::same(design.effects.border_radius / 2.0));

        let progress_bar = if let Some(text) = text {
            progress_bar.text(text)
        } else {
            progress_bar
        };

        ui.add(progress_bar);
    }

    /// Section header with consistent styling
    pub fn section_header(ui: &mut egui::Ui, title: &str, design: &DesignSystem) {
        ui.horizontal(|ui| {
            ui.add_space(design.spacing.sm);
            ui.heading(title);
        });
        ui.add_space(design.spacing.sm);
    }

    /// Form field group with label and input
    pub fn form_field<R>(
        ui: &mut egui::Ui,
        label: &str,
        help_text: Option<&str>,
        design: &DesignSystem,
        add_input: impl FnOnce(&mut egui::Ui) -> R,
    ) -> R {
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label(label);
                if let Some(help) = help_text {
                    ui.small(format!("({})", help));
                }
            });
            ui.add_space(design.spacing.xs);
            let result = add_input(ui);
            ui.add_space(design.spacing.sm);
            result
        }).inner
    }

    /// Alert box with different severity levels
    pub fn alert(ui: &mut egui::Ui, alert_type: AlertType, title: &str, message: &str, design: &DesignSystem) {
        let (bg_color, border_color, text_color, icon) = match alert_type {
            AlertType::Success => (
                Color32::from_rgba_unmultiplied(212, 237, 218, 255),
                design.colors.success,
                Color32::from_rgb(21, 87, 36),
                "✓"
            ),
            AlertType::Warning => (
                Color32::from_rgba_unmultiplied(255, 243, 205, 255),
                design.colors.warning,
                Color32::from_rgb(102, 77, 3),
                "⚠"
            ),
            AlertType::Error => (
                Color32::from_rgba_unmultiplied(248, 215, 218, 255),
                design.colors.error,
                Color32::from_rgb(88, 21, 28),
                "✗"
            ),
            AlertType::Info => (
                Color32::from_rgba_unmultiplied(209, 236, 241, 255),
                design.colors.info,
                Color32::from_rgb(12, 84, 96),
                "ℹ"
            ),
        };

        egui::Frame::none()
            .fill(bg_color)
            .stroke(Stroke::new(1.0, border_color))
            .rounding(Rounding::same(design.effects.border_radius))
            .inner_margin(design.spacing.md)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(border_color, icon);
                    ui.vertical(|ui| {
                        ui.colored_label(text_color, egui::RichText::new(title).strong());
                        if !message.is_empty() {
                            ui.colored_label(text_color, message);
                        }
                    });
                });
            });
    }

    /// Tab selector with consistent styling
    pub fn tab_selector<T: PartialEq + Clone>(
        ui: &mut egui::Ui,
        tabs: &[T],
        current_tab: &mut T,
        tab_name: impl Fn(&T) -> String,
        design: &DesignSystem,
    ) {
        ui.horizontal(|ui| {
            for tab in tabs {
                let is_selected = current_tab == tab;
                let button_color = if is_selected {
                    design.colors.primary
                } else {
                    design.colors.surface
                };
                let text_color = if is_selected {
                    Color32::WHITE
                } else {
                    design.colors.text_primary
                };

                let button = egui::Button::new(egui::RichText::new(tab_name(tab)).color(text_color))
                    .fill(button_color)
                    .stroke(Stroke::new(1.0, design.colors.border))
                    .rounding(Rounding::same(design.effects.border_radius));

                if ui.add(button).clicked() {
                    *current_tab = tab.clone();
                }
                ui.add_space(design.spacing.xs);
            }
        });
    }
}

#[derive(Debug, Clone, Copy)]
pub enum StatusType {
    Success,
    Warning,
    Error,
    Info,
    Active,
}

#[derive(Debug, Clone, Copy)]
pub enum AlertType {
    Success,
    Warning,
    Error,
    Info,
}

/// Helper trait for applying design system to egui components
pub trait DesignSystemExt {
    fn with_design_system(self, design: &DesignSystem) -> Self;
}

impl DesignSystemExt for egui::Button<'_> {
    fn with_design_system(self, design: &DesignSystem) -> Self {
        self.rounding(Rounding::same(design.effects.border_radius))
    }
}

impl DesignSystemExt for egui::Frame {
    fn with_design_system(self, design: &DesignSystem) -> Self {
        self.rounding(Rounding::same(design.effects.border_radius))
            .shadow(design.effects.shadow_elevation_1)
    }
}

/// Theme variants for light/dark mode support
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeVariant {
    Light,
    Dark,
}

impl DesignSystem {
    pub fn light_theme() -> Self {
        Self::default() // Default is already light theme
    }

    pub fn dark_theme() -> Self {
        let mut design = Self::default();
        design.colors = ColorPalette {
            primary: Color32::from_rgb(74, 182, 255),
            primary_hover: Color32::from_rgb(54, 162, 235),
            primary_pressed: Color32::from_rgb(34, 142, 215),

            secondary: Color32::from_rgb(108, 117, 125),
            secondary_hover: Color32::from_rgb(128, 137, 145),
            secondary_pressed: Color32::from_rgb(148, 157, 165),

            success: Color32::from_rgb(60, 187, 89),
            warning: Color32::from_rgb(255, 213, 47),
            error: Color32::from_rgb(240, 73, 89),
            info: Color32::from_rgb(43, 182, 204),

            background: Color32::from_rgb(33, 37, 41),
            surface: Color32::from_rgb(52, 58, 64),
            surface_hover: Color32::from_rgb(72, 78, 84),
            border: Color32::from_rgb(73, 80, 87),
            text_primary: Color32::from_rgb(248, 249, 250),
            text_secondary: Color32::from_rgb(173, 181, 189),
            text_disabled: Color32::from_rgb(108, 117, 125),
        };
        design
    }

    pub fn apply_to_egui_style(&self, style: &mut egui::Style) {
        // Apply color scheme to egui's built-in styles
        style.visuals.widgets.noninteractive.bg_fill = self.colors.surface;
        style.visuals.widgets.noninteractive.weak_bg_fill = self.colors.background;
        style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, self.colors.border);
        style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, self.colors.text_primary);

        style.visuals.widgets.inactive.bg_fill = self.colors.surface;
        style.visuals.widgets.inactive.weak_bg_fill = self.colors.surface_hover;
        style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, self.colors.border);
        style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, self.colors.text_primary);

        style.visuals.widgets.hovered.bg_fill = self.colors.surface_hover;
        style.visuals.widgets.hovered.weak_bg_fill = self.colors.surface_hover;
        style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, self.colors.primary);
        style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, self.colors.text_primary);

        style.visuals.widgets.active.bg_fill = self.colors.primary;
        style.visuals.widgets.active.weak_bg_fill = self.colors.primary;
        style.visuals.widgets.active.bg_stroke = Stroke::new(1.0, self.colors.primary);
        style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);

        // Apply spacing
        style.spacing.item_spacing = egui::Vec2::splat(self.spacing.sm);
        style.spacing.button_padding = egui::Vec2::new(self.spacing.md, self.spacing.sm);
        style.spacing.menu_margin = egui::Vec2::splat(self.spacing.md).into();

        // Apply rounding
        style.visuals.widgets.noninteractive.rounding = Rounding::same(self.effects.border_radius);
        style.visuals.widgets.inactive.rounding = Rounding::same(self.effects.border_radius);
        style.visuals.widgets.hovered.rounding = Rounding::same(self.effects.border_radius);
        style.visuals.widgets.active.rounding = Rounding::same(self.effects.border_radius);
    }
}