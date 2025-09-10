pub mod state;
pub mod widgets;
pub mod storage_widgets;
pub mod migration_widgets;
pub mod config_widgets;
pub mod backup_widgets;
pub mod crypto_widgets;
pub mod monitoring_widgets;
pub mod access_control_widgets;

pub use state::AppState;

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