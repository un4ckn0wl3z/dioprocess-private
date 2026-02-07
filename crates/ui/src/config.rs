//! Application configuration with SQLite storage
//!
//! Stores user preferences like theme selection in a separate database
//! from the callback events.

use parking_lot::Mutex;
use rusqlite::{params, Connection, Result as SqlResult};
use std::path::PathBuf;
use std::sync::Arc;

/// Available application themes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    /// Aura Glow - Dark theme with white/glowing text (default)
    #[default]
    AuraGlow,
    /// Cyber - Original cyan/purple theme
    Cyber,
}

impl Theme {
    /// Convert from database integer value
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => Theme::AuraGlow,
            1 => Theme::Cyber,
            _ => Theme::AuraGlow,
        }
    }

    /// Convert to database integer value
    pub fn to_i32(self) -> i32 {
        match self {
            Theme::AuraGlow => 0,
            Theme::Cyber => 1,
        }
    }

    /// Get display name for UI
    pub fn display_name(&self) -> &'static str {
        match self {
            Theme::AuraGlow => "Aura Glow",
            Theme::Cyber => "Cyber",
        }
    }

    /// Get all available themes
    pub fn all() -> &'static [Theme] {
        &[Theme::AuraGlow, Theme::Cyber]
    }
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub theme: Theme,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            theme: Theme::AuraGlow,
        }
    }
}

/// Configuration storage manager
pub struct ConfigStorage {
    conn: Arc<Mutex<Connection>>,
}

impl ConfigStorage {
    /// Create or open config storage at the specified path
    pub fn open(db_path: PathBuf) -> SqlResult<Self> {
        let conn = Connection::open(&db_path)?;

        // Enable WAL mode for better performance
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;",
        )?;

        // Create config table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open storage in the default location (AppData/Local/DioProcess)
    pub fn open_default() -> SqlResult<Self> {
        let db_path = get_config_db_path();
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Self::open(db_path)
    }

    /// Load application configuration
    pub fn load_config(&self) -> AppConfig {
        let conn = self.conn.lock();

        let theme = conn
            .query_row(
                "SELECT value FROM config WHERE key = 'theme'",
                [],
                |row| row.get::<_, i32>(0),
            )
            .map(Theme::from_i32)
            .unwrap_or_default();

        AppConfig { theme }
    }

    /// Save theme preference
    pub fn save_theme(&self, theme: Theme) -> SqlResult<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('theme', ?)",
            params![theme.to_i32()],
        )?;
        Ok(())
    }
}

/// Get the config database path (separate from events.db)
pub fn get_config_db_path() -> PathBuf {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(local_app_data)
        .join("DioProcess")
        .join("config.db")
}

/// Global config storage instance
static CONFIG_STORAGE: std::sync::OnceLock<ConfigStorage> = std::sync::OnceLock::new();

/// Get the global config storage instance
pub fn get_config_storage() -> &'static ConfigStorage {
    CONFIG_STORAGE.get_or_init(|| {
        ConfigStorage::open_default().expect("Failed to open config database")
    })
}

/// Load theme from config (convenience function)
pub fn load_theme() -> Theme {
    get_config_storage().load_config().theme
}

/// Save theme to config (convenience function)
pub fn save_theme(theme: Theme) {
    let _ = get_config_storage().save_theme(theme);
}
