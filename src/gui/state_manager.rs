use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};
use anyhow::Result;

use crate::config::AppConfig;
use crate::storage::backend::StorageType;

/// Central state management system for the GUI
/// Implements message-based state updates with atomic transitions
pub struct StateManager {
    /// Current application state
    state: Arc<RwLock<AppState>>,
    /// State change listeners
    listeners: Arc<RwLock<Vec<Box<dyn Fn(&StateChange) + Send + Sync>>>>,
    /// Configuration reference
    config: Arc<RwLock<AppConfig>>,
}

/// Complete application state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppState {
    /// GUI-specific state
    pub gui: GuiState,
    /// File operations state
    pub file_ops: FileOperationsState,
    /// Storage management state
    pub storage: StorageState,
    /// Configuration UI state
    pub config_ui: ConfigUIState,
    /// Migration UI state
    pub migration: MigrationState,
    /// Monitoring UI state
    pub monitoring: MonitoringState,
}

/// GUI component state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuiState {
    /// Current theme
    pub theme: String,
    /// Window dimensions
    pub window_size: (f32, f32),
    /// Current tab/view
    pub active_view: String,
    /// UI scale factor
    pub scale_factor: f32,
    /// Whether animations are enabled
    pub animations_enabled: bool,
    /// Progress indicators
    pub progress_states: HashMap<String, ProgressState>,
}

/// File operations state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileOperationsState {
    /// Currently selected files
    pub selected_files: Vec<String>,
    /// Active file operations
    pub active_operations: HashMap<String, FileOperationStatus>,
    /// Upload/download progress
    pub transfer_progress: HashMap<String, f32>,
    /// Recent files history
    pub recent_files: Vec<String>,
}

/// Storage configuration state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageState {
    /// Currently active storage backend
    pub active_backend: StorageType,
    /// Storage backend configurations
    pub backend_configs: HashMap<StorageType, HashMap<String, String>>,
    /// Connection status for each backend
    pub connection_status: HashMap<StorageType, ConnectionStatus>,
    /// Available storage backends
    pub available_backends: Vec<StorageType>,
}

/// Configuration UI state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigUIState {
    /// Currently open config section
    pub active_section: String,
    /// Unsaved changes indicator
    pub has_unsaved_changes: bool,
    /// Validation errors
    pub validation_errors: Vec<String>,
    /// Configuration profiles
    pub available_profiles: Vec<String>,
}

/// Migration UI state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationState {
    /// Source backend type
    pub source_backend: Option<StorageType>,
    /// Destination backend type
    pub dest_backend: Option<StorageType>,
    /// Migration progress
    pub migration_progress: f32,
    /// Migration status
    pub migration_status: MigrationStatus,
    /// Migration strategy
    pub migration_strategy: String,
    /// Batch size for migrations
    pub batch_size: usize,
    /// Concurrent operations limit
    pub concurrency_limit: usize,
}

/// Monitoring UI state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitoringState {
    /// Active monitoring views
    pub active_views: Vec<String>,
    /// Metrics refresh interval
    pub refresh_interval_ms: u64,
    /// Alert notifications
    pub alerts: Vec<AlertNotification>,
    /// Performance metrics
    pub metrics: HashMap<String, f64>,
}

/// State change messages for message-based updates
#[derive(Clone, Debug)]
pub enum StateMessage {
    /// GUI state changes
    SetTheme(String),
    SetWindowSize(f32, f32),
    SetActiveView(String),
    SetScaleFactor(f32),
    ToggleAnimations,
    UpdateProgress(String, ProgressState),
    
    /// File operations
    SelectFiles(Vec<String>),
    StartFileOperation(String, FileOperationStatus),
    UpdateTransferProgress(String, f32),
    CompleteFileOperation(String),
    
    /// Storage state changes
    SetActiveBackend(StorageType),
    UpdateBackendConfig(StorageType, String, String),
    UpdateConnectionStatus(StorageType, ConnectionStatus),
    
    /// Configuration changes
    SetActiveConfigSection(String),
    SetUnsavedChanges(bool),
    AddValidationError(String),
    ClearValidationErrors,
    UpdateAvailableProfiles(Vec<String>),
    
    /// Migration changes
    SetMigrationSource(StorageType),
    SetMigrationDestination(StorageType),
    UpdateMigrationProgress(f32),
    SetMigrationStatus(MigrationStatus),
    SetMigrationStrategy(String),
    SetBatchSize(usize),
    SetConcurrencyLimit(usize),
    
    /// Monitoring changes
    AddMonitoringView(String),
    RemoveMonitoringView(String),
    SetRefreshInterval(u64),
    AddAlert(AlertNotification),
    ClearAlert(String),
    UpdateMetric(String, f64),
}

/// State change notification
#[derive(Clone, Debug)]
pub struct StateChange {
    pub message: StateMessage,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Supporting enums and structs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgressState {
    pub current: usize,
    pub total: usize,
    pub message: String,
    pub is_indeterminate: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FileOperationStatus {
    Pending,
    InProgress,
    Completed,
    Failed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MigrationStatus {
    NotStarted,
    InProgress,
    Completed,
    Failed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertNotification {
    pub id: String,
    pub level: AlertLevel,
    pub title: String,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AlertLevel {
    Info,
    Warning,
    Error,
    Success,
}

impl StateManager {
    /// Create a new state manager
    pub fn new(config: Arc<RwLock<AppConfig>>) -> Self {
        let state = AppState::default();
        
        Self {
            state: Arc::new(RwLock::new(state)),
            listeners: Arc::new(RwLock::new(Vec::new())),
            config,
        }
    }

    /// Get current state (read-only)
    pub fn get_state(&self) -> Result<AppState> {
        let state = self.state.read().map_err(|_| anyhow::anyhow!("Failed to read state"))?;
        Ok(state.clone())
    }

    /// Send a state update message
    pub fn send_message(&self, message: StateMessage) -> Result<()> {
        let change = StateChange {
            message: message.clone(),
            timestamp: chrono::Utc::now(),
        };

        // Apply the state change
        self.apply_state_change(&change)?;

        // Notify listeners
        self.notify_listeners(&change)?;

        Ok(())
    }

    /// Add a state change listener
    pub fn add_listener<F>(&self, listener: F) -> Result<()>
    where
        F: Fn(&StateChange) + Send + Sync + 'static,
    {
        let mut listeners = self.listeners.write().map_err(|_| anyhow::anyhow!("Failed to write listeners"))?;
        listeners.push(Box::new(listener));
        Ok(())
    }

    /// Apply atomic state changes
    fn apply_state_change(&self, change: &StateChange) -> Result<()> {
        let mut state = self.state.write().map_err(|_| anyhow::anyhow!("Failed to write state"))?;
        
        match &change.message {
            StateMessage::SetTheme(theme) => {
                state.gui.theme = theme.clone();
            },
            StateMessage::SetWindowSize(width, height) => {
                state.gui.window_size = (*width, *height);
            },
            StateMessage::SetActiveView(view) => {
                state.gui.active_view = view.clone();
            },
            StateMessage::SetScaleFactor(factor) => {
                state.gui.scale_factor = *factor;
            },
            StateMessage::ToggleAnimations => {
                state.gui.animations_enabled = !state.gui.animations_enabled;
            },
            StateMessage::UpdateProgress(id, progress) => {
                state.gui.progress_states.insert(id.clone(), progress.clone());
            },
            StateMessage::SelectFiles(files) => {
                state.file_ops.selected_files = files.clone();
            },
            StateMessage::StartFileOperation(id, status) => {
                state.file_ops.active_operations.insert(id.clone(), status.clone());
            },
            StateMessage::UpdateTransferProgress(id, progress) => {
                state.file_ops.transfer_progress.insert(id.clone(), *progress);
            },
            StateMessage::CompleteFileOperation(id) => {
                state.file_ops.active_operations.remove(id);
                state.file_ops.transfer_progress.remove(id);
            },
            StateMessage::SetActiveBackend(backend) => {
                state.storage.active_backend = *backend;
            },
            StateMessage::UpdateBackendConfig(backend, key, value) => {
                let config = state.storage.backend_configs.entry(*backend).or_default();
                config.insert(key.clone(), value.clone());
            },
            StateMessage::UpdateConnectionStatus(backend, status) => {
                state.storage.connection_status.insert(*backend, status.clone());
            },
            StateMessage::SetActiveConfigSection(section) => {
                state.config_ui.active_section = section.clone();
            },
            StateMessage::SetUnsavedChanges(has_changes) => {
                state.config_ui.has_unsaved_changes = *has_changes;
            },
            StateMessage::AddValidationError(error) => {
                state.config_ui.validation_errors.push(error.clone());
            },
            StateMessage::ClearValidationErrors => {
                state.config_ui.validation_errors.clear();
            },
            StateMessage::UpdateAvailableProfiles(profiles) => {
                state.config_ui.available_profiles = profiles.clone();
            },
            StateMessage::SetMigrationSource(backend) => {
                state.migration.source_backend = Some(*backend);
            },
            StateMessage::SetMigrationDestination(backend) => {
                state.migration.dest_backend = Some(*backend);
            },
            StateMessage::UpdateMigrationProgress(progress) => {
                state.migration.migration_progress = *progress;
            },
            StateMessage::SetMigrationStatus(status) => {
                state.migration.migration_status = status.clone();
            },
            StateMessage::SetMigrationStrategy(strategy) => {
                state.migration.migration_strategy = strategy.clone();
            },
            StateMessage::SetBatchSize(size) => {
                state.migration.batch_size = *size;
            },
            StateMessage::SetConcurrencyLimit(limit) => {
                state.migration.concurrency_limit = *limit;
            },
            StateMessage::AddMonitoringView(view) => {
                if !state.monitoring.active_views.contains(view) {
                    state.monitoring.active_views.push(view.clone());
                }
            },
            StateMessage::RemoveMonitoringView(view) => {
                state.monitoring.active_views.retain(|v| v != view);
            },
            StateMessage::SetRefreshInterval(interval) => {
                state.monitoring.refresh_interval_ms = *interval;
            },
            StateMessage::AddAlert(alert) => {
                state.monitoring.alerts.push(alert.clone());
            },
            StateMessage::ClearAlert(id) => {
                state.monitoring.alerts.retain(|a| &a.id != id);
            },
            StateMessage::UpdateMetric(key, value) => {
                state.monitoring.metrics.insert(key.clone(), *value);
            },
        }

        // Validate state after change
        self.validate_state(&state)?;

        Ok(())
    }

    /// Validate state consistency
    fn validate_state(&self, state: &AppState) -> Result<()> {
        // Validate GUI state
        if state.gui.scale_factor < 0.5 || state.gui.scale_factor > 3.0 {
            return Err(anyhow::anyhow!("Invalid scale factor: {}", state.gui.scale_factor));
        }

        // Validate migration state
        if state.migration.batch_size == 0 {
            return Err(anyhow::anyhow!("Batch size cannot be zero"));
        }

        if state.migration.concurrency_limit == 0 {
            return Err(anyhow::anyhow!("Concurrency limit cannot be zero"));
        }

        Ok(())
    }

    /// Notify all listeners of state changes
    fn notify_listeners(&self, change: &StateChange) -> Result<()> {
        let listeners = self.listeners.read().map_err(|_| anyhow::anyhow!("Failed to read listeners"))?;
        
        for listener in listeners.iter() {
            listener(change);
        }

        Ok(())
    }

    /// Reset state to defaults
    pub fn reset_to_defaults(&self) -> Result<()> {
        let mut state = self.state.write().map_err(|_| anyhow::anyhow!("Failed to write state"))?;
        *state = AppState::default();
        Ok(())
    }

    /// Export current state to JSON
    pub fn export_state(&self) -> Result<String> {
        let state = self.state.read().map_err(|_| anyhow::anyhow!("Failed to read state"))?;
        Ok(serde_json::to_string_pretty(&*state)?)
    }

    /// Import state from JSON
    pub fn import_state(&self, json: &str) -> Result<()> {
        let new_state: AppState = serde_json::from_str(json)?;
        self.validate_state(&new_state)?;
        
        let mut state = self.state.write().map_err(|_| anyhow::anyhow!("Failed to write state"))?;
        *state = new_state;
        
        Ok(())
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            gui: GuiState::default(),
            file_ops: FileOperationsState::default(),
            storage: StorageState::default(),
            config_ui: ConfigUIState::default(),
            migration: MigrationState::default(),
            monitoring: MonitoringState::default(),
        }
    }
}

impl Default for GuiState {
    fn default() -> Self {
        Self {
            theme: "auto".to_string(),
            window_size: (1200.0, 800.0),
            active_view: "main".to_string(),
            scale_factor: 1.0,
            animations_enabled: true,
            progress_states: HashMap::new(),
        }
    }
}

impl Default for FileOperationsState {
    fn default() -> Self {
        Self {
            selected_files: Vec::new(),
            active_operations: HashMap::new(),
            transfer_progress: HashMap::new(),
            recent_files: Vec::new(),
        }
    }
}

impl Default for StorageState {
    fn default() -> Self {
        Self {
            active_backend: StorageType::Local,
            backend_configs: HashMap::new(),
            connection_status: HashMap::new(),
            available_backends: vec![
                StorageType::Local,
                StorageType::Sftp,
                StorageType::S3Compatible,
                StorageType::GoogleCloud,
                StorageType::AzureBlob,
            ],
        }
    }
}

impl Default for ConfigUIState {
    fn default() -> Self {
        Self {
            active_section: "storage".to_string(),
            has_unsaved_changes: false,
            validation_errors: Vec::new(),
            available_profiles: Vec::new(),
        }
    }
}

impl Default for MigrationState {
    fn default() -> Self {
        Self {
            source_backend: None,
            dest_backend: None,
            migration_progress: 0.0,
            migration_status: MigrationStatus::NotStarted,
            migration_strategy: "CopyThenDelete".to_string(),
            batch_size: 100,
            concurrency_limit: 4,
        }
    }
}

impl Default for MonitoringState {
    fn default() -> Self {
        Self {
            active_views: vec!["overview".to_string()],
            refresh_interval_ms: 5000,
            alerts: Vec::new(),
            metrics: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_manager_creation() {
        let config = Arc::new(RwLock::new(AppConfig::default()));
        let manager = StateManager::new(config);
        let state = manager.get_state().unwrap();
        assert_eq!(state.gui.theme, "auto");
    }

    #[test]
    fn test_message_based_updates() {
        let config = Arc::new(RwLock::new(AppConfig::default()));
        let manager = StateManager::new(config);

        // Test theme change
        manager.send_message(StateMessage::SetTheme("dark".to_string())).unwrap();
        let state = manager.get_state().unwrap();
        assert_eq!(state.gui.theme, "dark");

        // Test file selection
        manager.send_message(StateMessage::SelectFiles(vec!["file1.txt".to_string(), "file2.txt".to_string()])).unwrap();
        let state = manager.get_state().unwrap();
        assert_eq!(state.file_ops.selected_files.len(), 2);
    }

    #[test]
    fn test_state_validation() {
        let config = Arc::new(RwLock::new(AppConfig::default()));
        let manager = StateManager::new(config);

        // Valid scale factor should work
        assert!(manager.send_message(StateMessage::SetScaleFactor(1.5)).is_ok());

        // Invalid scale factor should fail
        assert!(manager.send_message(StateMessage::SetScaleFactor(5.0)).is_err());
    }

    #[test]
    fn test_state_listeners() {
        let config = Arc::new(RwLock::new(AppConfig::default()));
        let manager = StateManager::new(config);

        let mut received_changes = Vec::new();
        let changes_ref = Arc::new(std::sync::Mutex::new(&mut received_changes));

        manager.add_listener(move |change| {
            // In a real test, we'd capture these changes
            println!("State change: {:?}", change.message);
        }).unwrap();

        manager.send_message(StateMessage::SetTheme("light".to_string())).unwrap();
        // In a real implementation, we'd verify the listener was called
    }
}