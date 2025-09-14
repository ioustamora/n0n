use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MainTab {
    Dashboard,
    Storage,
    Security,
    Backup,
    Monitoring,
    Settings,
}

impl MainTab {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Dashboard => "🏠 Dashboard",
            Self::Storage => "💾 Storage",
            Self::Security => "🔒 Security",
            Self::Backup => "🗄️ Backup",
            Self::Monitoring => "📊 Monitoring",
            Self::Settings => "⚙️ Settings",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Dashboard => "System overview and quick actions",
            Self::Storage => "Storage backends and file operations",
            Self::Security => "Encryption, access control, and keys",
            Self::Backup => "Backup scheduling and disaster recovery",
            Self::Monitoring => "Analytics, health, and performance",
            Self::Settings => "Application preferences and profiles",
        }
    }

    pub fn all() -> &'static [MainTab] {
        &[
            Self::Dashboard,
            Self::Storage,
            Self::Security,
            Self::Backup,
            Self::Monitoring,
            Self::Settings,
        ]
    }
}

impl Default for MainTab {
    fn default() -> Self {
        Self::Dashboard
    }
}