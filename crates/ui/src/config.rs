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

        // Create secrets table for sensitive data like PAT
        conn.execute(
            "CREATE TABLE IF NOT EXISTS secrets (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
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

    /// Save PAT token (base64 encoded)
    pub fn save_pat(&self, pat: &str) -> SqlResult<()> {
        let encoded = base64_encode(pat);
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO secrets (key, value) VALUES ('pat', ?)",
            params![encoded],
        )?;
        Ok(())
    }

    /// Load PAT token
    pub fn load_pat(&self) -> Option<String> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT value FROM secrets WHERE key = 'pat'",
            [],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|encoded| base64_decode(&encoded).ok())
    }

    /// Check if PAT is configured
    pub fn has_pat(&self) -> bool {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT 1 FROM secrets WHERE key = 'pat'",
            [],
            |_| Ok(()),
        )
        .is_ok()
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

/// Save PAT to config (convenience function)
pub fn save_pat(pat: &str) {
    let _ = get_config_storage().save_pat(pat);
}

/// Load PAT from config (convenience function)
pub fn load_pat() -> Option<String> {
    get_config_storage().load_pat()
}

/// Check if PAT is configured (convenience function)
pub fn has_pat() -> bool {
    get_config_storage().has_pat()
}

/// Simple base64 encode function
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;

        let n = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        result.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[(n >> 6 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Simple base64 decode function
fn base64_decode(input: &str) -> Result<String, String> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }

    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    for chunk in input.chunks(4) {
        if chunk.len() < 4 {
            return Err("Invalid base64 length".to_string());
        }

        let a = decode_char(chunk[0]).ok_or("Invalid base64 character")?;
        let b = decode_char(chunk[1]).ok_or("Invalid base64 character")?;
        let c = decode_char(chunk[2]).ok_or("Invalid base64 character")?;
        let d = decode_char(chunk[3]).ok_or("Invalid base64 character")?;

        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }

    String::from_utf8(output).map_err(|e| format!("Invalid UTF-8: {}", e))
}
