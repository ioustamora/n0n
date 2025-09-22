pub mod state;
pub mod state_manager;
pub mod widgets;
pub mod storage_widgets;
pub mod migration_widgets;
pub mod config_widgets;
pub mod backup_widgets;
pub mod crypto_widgets;
pub mod monitoring_widgets;
pub mod access_control_widgets;
pub mod drag_drop;
pub mod navigation;
pub mod notifications;
pub mod progressive_disclosure;
pub mod dashboard;
pub mod design_system;
pub mod wizard;
pub mod storage_wizard;
pub mod data_visualization;
pub mod role_based_ui;
pub mod intelligent_config;
pub mod adaptive_ui;
pub mod components;

pub use state::AppState;

// Re-export enhanced state management

// Re-export new UI components

use eframe::egui;
use std::path::PathBuf;

pub fn run_app() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "n0n - Secure File Sharing",
        options,
        Box::new(|_cc| {
            Box::new(AppState::new())
        }),
    )
}

#[cfg(not(target_os = "windows"))]
pub fn open_folder_in_os(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    std::process::Command::new("xdg-open")
        .arg(path)
        .spawn()?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn open_folder_in_os(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    std::process::Command::new("explorer")
        .arg(path)
        .spawn()?;
    Ok(())
}

/// Check if a path is hidden (starts with .)
pub fn is_hidden_path(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.starts_with('.'))
        .unwrap_or(false)
}