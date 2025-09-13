use std::path::{Path, PathBuf};
use eframe::egui;
use std::sync::{Arc, Mutex};

/// Drag and drop handler for file operations
pub struct DragDropHandler {
    /// Files that were just dropped
    pub dropped_files: Arc<Mutex<Vec<PathBuf>>>,
    /// Whether we're currently hovering with files
    pub hover_active: bool,
    /// Supported file types filter
    pub allowed_extensions: Vec<String>,
    /// Maximum number of files that can be dropped at once
    pub max_files: Option<usize>,
}

impl Default for DragDropHandler {
    fn default() -> Self {
        Self {
            dropped_files: Arc::new(Mutex::new(Vec::new())),
            hover_active: false,
            allowed_extensions: Vec::new(), // Empty means all files allowed
            max_files: None, // None means unlimited
        }
    }
}

impl DragDropHandler {
    /// Create a new drag drop handler with configuration
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set allowed file extensions (e.g., ["txt", "pdf", "jpg"])
    pub fn with_allowed_extensions(mut self, extensions: Vec<String>) -> Self {
        self.allowed_extensions = extensions;
        self
    }
    
    /// Set maximum number of files that can be dropped at once
    pub fn with_max_files(mut self, max: usize) -> Self {
        self.max_files = Some(max);
        self
    }
    
    /// Check if a file has an allowed extension
    fn is_file_allowed(&self, path: &Path) -> bool {
        if self.allowed_extensions.is_empty() {
            return true; // All files allowed
        }
        
        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                return self.allowed_extensions.iter()
                    .any(|allowed| allowed.to_lowercase() == ext_str.to_lowercase());
            }
        }
        false
    }
    
    /// Process egui drag and drop events
    pub fn handle_drag_drop(&mut self, ctx: &egui::Context, response: &egui::Response) -> Vec<PathBuf> {
        // Handle drag and drop
        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            let dropped_files = ctx.input(|i| i.raw.dropped_files.clone());
            
            let mut valid_files = Vec::new();
            for file in dropped_files {
                if let Some(path) = &file.path {
                    if self.is_file_allowed(path) {
                        valid_files.push(path.clone());
                        
                        // Check max files limit
                        if let Some(max) = self.max_files {
                            if valid_files.len() >= max {
                                break;
                            }
                        }
                    }
                }
            }
            
            // Store the dropped files
            if let Ok(mut files) = self.dropped_files.lock() {
                files.clear();
                files.extend(valid_files.clone());
            }
            
            return valid_files;
        }
        
        // Update hover state
        self.hover_active = response.hovered() && ctx.input(|i| !i.raw.hovered_files.is_empty());
        
        Vec::new()
    }
    
    /// Get and clear the dropped files
    pub fn take_dropped_files(&self) -> Vec<PathBuf> {
        if let Ok(mut files) = self.dropped_files.lock() {
            let result = files.clone();
            files.clear();
            result
        } else {
            Vec::new()
        }
    }
    
    /// Render a drop zone UI component
    pub fn render_drop_zone(
        &mut self,
        ui: &mut egui::Ui,
        size: egui::Vec2,
        label: &str,
    ) -> (egui::Response, Vec<PathBuf>) {
        let (rect, response) = ui.allocate_exact_size(size, egui::Sense::hover());
        
        // Handle drag and drop
        let dropped_files = self.handle_drag_drop(ui.ctx(), &response);
        
        // Visual styling
        let stroke = if self.hover_active {
            egui::Stroke::new(2.0, egui::Color32::from_rgb(0, 150, 255)) // Blue when hovering
        } else {
            egui::Stroke::new(1.0, egui::Color32::GRAY) // Gray normally
        };
        
        let fill = if self.hover_active {
            egui::Color32::from_rgba_unmultiplied(0, 150, 255, 20) // Light blue background
        } else {
            egui::Color32::from_rgba_unmultiplied(128, 128, 128, 10) // Light gray background
        };
        
        // Draw the drop zone
        ui.painter().rect(rect, 10.0, fill, stroke);
        
        // Draw the label
        let text_color = if self.hover_active {
            egui::Color32::from_rgb(0, 100, 200)
        } else {
            egui::Color32::GRAY
        };
        
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(14.0),
            text_color,
        );
        
        // Add instruction text
        let instruction = if self.allowed_extensions.is_empty() {
            "Drop files here".to_string()
        } else {
            format!("Drop {} files here", self.allowed_extensions.join(", "))
        };
        
        let instruction_pos = rect.center() + egui::Vec2::new(0.0, 20.0);
        ui.painter().text(
            instruction_pos,
            egui::Align2::CENTER_CENTER,
            &instruction,
            egui::FontId::proportional(10.0),
            egui::Color32::GRAY,
        );
        
        (response, dropped_files)
    }
    
    /// Render file list preview for dropped files
    pub fn render_file_preview(&self, ui: &mut egui::Ui) {
        if let Ok(files) = self.dropped_files.lock() {
            if !files.is_empty() {
                ui.collapsing("Dropped Files", |ui| {
                    for (i, file) in files.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(format!("{}.", i + 1));
                            
                            // Show file name with full path as tooltip
                            let file_name = file.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("Unknown file");
                            
                            let label = ui.label(file_name);
                            label.on_hover_text(file.display().to_string());
                            
                            // Show file size if available
                            if let Ok(metadata) = std::fs::metadata(file) {
                                let size = metadata.len();
                                let size_str = format_file_size(size);
                                ui.label(format!("({})", size_str));
                            }
                        });
                    }
                });
            }
        }
    }
    
    /// Get current hover state
    pub fn is_hovering(&self) -> bool {
        self.hover_active
    }
    
    /// Clear all dropped files
    pub fn clear(&self) {
        if let Ok(mut files) = self.dropped_files.lock() {
            files.clear();
        }
    }
}

/// Format file size in human readable format
fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Enhanced file dialog with drag and drop support
pub struct EnhancedFileDialog {
    drag_drop: DragDropHandler,
    native_dialog_open: bool,
}

impl Default for EnhancedFileDialog {
    fn default() -> Self {
        Self {
            drag_drop: DragDropHandler::new(),
            native_dialog_open: false,
        }
    }
}

impl EnhancedFileDialog {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Render the enhanced file dialog with both native dialog and drag-drop
    pub fn render(
        &mut self,
        ui: &mut egui::Ui,
        current_selection: &mut Option<PathBuf>,
    ) -> bool {
        let mut selection_changed = false;
        
        ui.vertical(|ui| {
            ui.heading("File Selection");
            
            // Current selection display
            if let Some(selected) = current_selection {
                let file_name = selected.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Unknown file");
                
                let should_clear = ui.horizontal(|ui| {
                    ui.label("Selected:");
                    ui.monospace(file_name);
                    ui.button("Clear").clicked()
                }).inner;
                
                if should_clear {
                    *current_selection = None;
                    selection_changed = true;
                }
                
                ui.separator();
            }
            
            // Native file dialog button
            if ui.button("Browse Files...").clicked() && !self.native_dialog_open {
                self.native_dialog_open = true;
                
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    *current_selection = Some(path);
                    selection_changed = true;
                }
                
                self.native_dialog_open = false;
            }
            
            ui.separator();
            ui.label("Or drag and drop files below:");
            
            // Drag and drop zone
            let drop_size = egui::Vec2::new(300.0, 100.0);
            let (_, dropped_files) = self.drag_drop.render_drop_zone(
                ui,
                drop_size,
                "Drop files here"
            );
            
            // Handle dropped files
            if let Some(first_file) = dropped_files.first() {
                *current_selection = Some(first_file.clone());
                selection_changed = true;
            }
            
            // Preview dropped files
            self.drag_drop.render_file_preview(ui);
        });
        
        selection_changed
    }
}

/// Multi-file selection with drag and drop support
pub struct MultiFileSelector {
    drag_drop: DragDropHandler,
    selected_files: Vec<PathBuf>,
}

impl Default for MultiFileSelector {
    fn default() -> Self {
        Self {
            drag_drop: DragDropHandler::new(),
            selected_files: Vec::new(),
        }
    }
}

impl MultiFileSelector {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set allowed file extensions
    pub fn with_allowed_extensions(mut self, extensions: Vec<String>) -> Self {
        self.drag_drop = self.drag_drop.with_allowed_extensions(extensions);
        self
    }
    
    /// Render the multi-file selector
    pub fn render(&mut self, ui: &mut egui::Ui) -> bool {
        let mut selection_changed = false;
        
        ui.vertical(|ui| {
            ui.heading("Multi-File Selection");
            
            // Current selection list
            if !self.selected_files.is_empty() {
                ui.collapsing("Selected Files", |ui| {
                    let mut to_remove = None;
                    
                    for (i, file) in self.selected_files.iter().enumerate() {
                        ui.horizontal(|ui| {
                            if ui.button("❌").clicked() {
                                to_remove = Some(i);
                            }
                            
                            let file_name = file.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("Unknown file");
                            
                            let label = ui.label(file_name);
                            label.on_hover_text(file.display().to_string());
                        });
                    }
                    
                    if let Some(index) = to_remove {
                        self.selected_files.remove(index);
                        selection_changed = true;
                    }
                });
                
                ui.horizontal(|ui| {
                    if ui.button("Clear All").clicked() {
                        self.selected_files.clear();
                        selection_changed = true;
                    }
                    
                    ui.label(format!("{} files selected", self.selected_files.len()));
                });
                
                ui.separator();
            }
            
            // Add files button
            if ui.button("Add Files...").clicked() {
                if let Some(files) = rfd::FileDialog::new().pick_files() {
                    for file in files {
                        if !self.selected_files.contains(&file) {
                            self.selected_files.push(file);
                            selection_changed = true;
                        }
                    }
                }
            }
            
            ui.separator();
            ui.label("Or drag and drop multiple files:");
            
            // Drag and drop zone
            let drop_size = egui::Vec2::new(400.0, 120.0);
            let (_, dropped_files) = self.drag_drop.render_drop_zone(
                ui,
                drop_size,
                "Drop multiple files here"
            );
            
            // Handle dropped files
            for file in dropped_files {
                if !self.selected_files.contains(&file) {
                    self.selected_files.push(file);
                    selection_changed = true;
                }
            }
        });
        
        selection_changed
    }
    
    /// Get the currently selected files
    pub fn get_selected_files(&self) -> &[PathBuf] {
        &self.selected_files
    }
    
    /// Clear all selected files
    pub fn clear(&mut self) {
        self.selected_files.clear();
    }
    
    /// Add a file to the selection
    pub fn add_file(&mut self, path: PathBuf) -> bool {
        if !self.selected_files.contains(&path) {
            self.selected_files.push(path);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_drag_drop_handler_creation() {
        let handler = DragDropHandler::new()
            .with_allowed_extensions(vec!["txt".to_string(), "pdf".to_string()])
            .with_max_files(5);
        
        assert_eq!(handler.allowed_extensions, vec!["txt", "pdf"]);
        assert_eq!(handler.max_files, Some(5));
    }
    
    #[test]
    fn test_file_allowed() {
        let handler = DragDropHandler::new()
            .with_allowed_extensions(vec!["txt".to_string(), "pdf".to_string()]);
        
        assert!(handler.is_file_allowed(Path::new("test.txt")));
        assert!(handler.is_file_allowed(Path::new("test.PDF"))); // Case insensitive
        assert!(!handler.is_file_allowed(Path::new("test.jpg")));
        assert!(!handler.is_file_allowed(Path::new("test"))); // No extension
    }
    
    #[test]
    fn test_file_allowed_empty_extensions() {
        let handler = DragDropHandler::new(); // No allowed extensions = all allowed
        
        assert!(handler.is_file_allowed(Path::new("test.txt")));
        assert!(handler.is_file_allowed(Path::new("test.jpg")));
        assert!(handler.is_file_allowed(Path::new("test")));
    }
    
    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(512), "512 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_file_size(1024 * 1024 * 1024), "1.0 GB");
    }
    
    #[test]
    fn test_multi_file_selector() {
        let mut selector = MultiFileSelector::new();
        
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        
        // Add file
        assert!(selector.add_file(path.clone()));
        assert_eq!(selector.get_selected_files().len(), 1);
        
        // Add same file again - should not duplicate
        assert!(!selector.add_file(path.clone()));
        assert_eq!(selector.get_selected_files().len(), 1);
        
        // Clear files
        selector.clear();
        assert_eq!(selector.get_selected_files().len(), 0);
    }
}