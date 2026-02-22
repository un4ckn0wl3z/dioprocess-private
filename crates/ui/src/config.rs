//! Application configuration with SQLite storage
//!
//! Stores user preferences like theme selection in a separate database
//! from the callback events.

use parking_lot::Mutex;
use rusqlite::{params, Connection, Result as SqlResult};
use std::path::PathBuf;
use std::sync::Arc;

use crate::state::{DphScript, DprScript, EptHookInputMode};

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

        // Create hidden_files table for file hiding persistence
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hidden_files (
                path TEXT PRIMARY KEY
            )",
            [],
        )?;

        // Create hidden_processes table for DKOM process hiding persistence
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hidden_processes (
                pid INTEGER PRIMARY KEY
            )",
            [],
        )?;

        // Create hidden_ports table for NSI port hiding persistence
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hidden_ports (
                port INTEGER PRIMARY KEY
            )",
            [],
        )?;

        // Create dph_scripts table for .dph script persistence
        conn.execute(
            "CREATE TABLE IF NOT EXISTS dph_scripts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                target_expr TEXT NOT NULL,
                mode INTEGER NOT NULL,
                stolen_bytes INTEGER NOT NULL DEFAULT 6,
                code TEXT NOT NULL
            )",
            [],
        )?;

        // Create dpr_scripts table for .dpr script persistence
        conn.execute(
            "CREATE TABLE IF NOT EXISTS dpr_scripts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                target_expr TEXT NOT NULL,
                register TEXT NOT NULL,
                reg_index INTEGER NOT NULL,
                value_expr TEXT NOT NULL,
                new_value INTEGER NOT NULL
            )",
            [],
        )?;

        // Create respawn_targets table for process respawn monitor persistence
        conn.execute(
            "CREATE TABLE IF NOT EXISTS respawn_targets (
                process_name TEXT PRIMARY KEY,
                kill_method INTEGER NOT NULL,
                scan_interval INTEGER NOT NULL DEFAULT 2
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

    /// Delete PAT token
    pub fn delete_pat(&self) -> SqlResult<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM secrets WHERE key = 'pat'", [])?;
        Ok(())
    }

    /// Add a hidden file path
    pub fn add_hidden_path(&self, path: &str) -> SqlResult<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO hidden_files (path) VALUES (?)",
            params![path],
        )?;
        Ok(())
    }

    /// Remove a hidden file path
    pub fn remove_hidden_path(&self, path: &str) -> SqlResult<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM hidden_files WHERE path = ?", params![path])?;
        Ok(())
    }

    /// Load all hidden file paths
    pub fn load_hidden_paths(&self) -> Vec<String> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare("SELECT path FROM hidden_files ORDER BY path") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let result: Vec<String> = match stmt.query_map([], |row| row.get::<_, String>(0)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        result
    }

    /// Add a hidden process PID (DKOM persistence)
    pub fn add_hidden_process(&self, pid: u32) -> SqlResult<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO hidden_processes (pid) VALUES (?)",
            params![pid as i64],
        )?;
        Ok(())
    }

    /// Remove a hidden process PID
    pub fn remove_hidden_process(&self, pid: u32) -> SqlResult<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM hidden_processes WHERE pid = ?",
            params![pid as i64],
        )?;
        Ok(())
    }

    /// Load all hidden process PIDs
    pub fn load_hidden_processes(&self) -> Vec<u32> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare("SELECT pid FROM hidden_processes ORDER BY pid") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let result: Vec<u32> = match stmt.query_map([], |row| row.get::<_, i64>(0).map(|v| v as u32)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        result
    }

    /// Clear all hidden process PIDs
    pub fn clear_hidden_processes(&self) -> SqlResult<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM hidden_processes", [])?;
        Ok(())
    }

    /// Add a hidden port (NSI port hiding persistence)
    pub fn add_hidden_port(&self, port: u16) -> SqlResult<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO hidden_ports (port) VALUES (?)",
            params![port as i64],
        )?;
        Ok(())
    }

    /// Remove a hidden port
    pub fn remove_hidden_port(&self, port: u16) -> SqlResult<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM hidden_ports WHERE port = ?",
            params![port as i64],
        )?;
        Ok(())
    }

    /// Load all hidden ports
    pub fn load_hidden_ports(&self) -> Vec<u16> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare("SELECT port FROM hidden_ports ORDER BY port") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let result: Vec<u16> = match stmt.query_map([], |row| row.get::<_, i64>(0).map(|v| v as u16)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        result
    }

    /// Save all DPH scripts (full replace)
    pub fn save_dph_scripts(&self, scripts: &[DphScript]) {
        let conn = self.conn.lock();
        let _ = conn.execute("DELETE FROM dph_scripts", []);
        for s in scripts {
            let mode_i: i32 = match s.mode {
                EptHookInputMode::Hex => 0,
                EptHookInputMode::Assembly => 1,
                EptHookInputMode::Detour => 2,
            };
            let _ = conn.execute(
                "INSERT INTO dph_scripts (name, file_path, target_expr, mode, stolen_bytes, code) VALUES (?, ?, ?, ?, ?, ?)",
                params![s.name, s.file_path, s.target_expr, mode_i, s.stolen_bytes as i64, s.code],
            );
        }
    }

    /// Load all DPH scripts (status reset to Pending)
    pub fn load_dph_scripts(&self) -> Vec<DphScript> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare("SELECT name, file_path, target_expr, mode, stolen_bytes, code FROM dph_scripts ORDER BY id") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let result: Vec<DphScript> = match stmt.query_map([], |row| {
            let mode_i: i32 = row.get(3)?;
            let mode = match mode_i {
                1 => EptHookInputMode::Assembly,
                2 => EptHookInputMode::Detour,
                _ => EptHookInputMode::Hex,
            };
            Ok(DphScript {
                name: row.get(0)?,
                file_path: row.get(1)?,
                target_expr: row.get(2)?,
                resolved_addr: None,
                mode,
                stolen_bytes: row.get::<_, i64>(4)? as u32,
                code: row.get(5)?,
                hook_index: None,
                status: "Pending".to_string(),
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        result
    }

    /// Save all DPR scripts (full replace)
    pub fn save_dpr_scripts(&self, scripts: &[DprScript]) {
        let conn = self.conn.lock();
        let _ = conn.execute("DELETE FROM dpr_scripts", []);
        for s in scripts {
            let _ = conn.execute(
                "INSERT INTO dpr_scripts (name, file_path, target_expr, register, reg_index, value_expr, new_value) VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![s.name, s.file_path, s.target_expr, s.register, s.reg_index as i64, s.value_expr, s.new_value as i64],
            );
        }
    }

    /// Load all DPR scripts (status reset to Pending)
    pub fn load_dpr_scripts(&self) -> Vec<DprScript> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare("SELECT name, file_path, target_expr, register, reg_index, value_expr, new_value FROM dpr_scripts ORDER BY id") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let result: Vec<DprScript> = match stmt.query_map([], |row| {
            Ok(DprScript {
                name: row.get(0)?,
                file_path: row.get(1)?,
                target_expr: row.get(2)?,
                resolved_addr: None,
                register: row.get(3)?,
                reg_index: row.get::<_, i64>(4)? as u32,
                value_expr: row.get(5)?,
                new_value: row.get::<_, i64>(6)? as u64,
                entry_index: None,
                status: "Pending".to_string(),
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        result
    }

    /// Save respawn monitor targets (full replace)
    pub fn save_respawn_targets(&self, targets: &[crate::state::RespawnTarget]) {
        let conn = self.conn.lock();
        let _ = conn.execute("DELETE FROM respawn_targets", []);
        for t in targets {
            let _ = conn.execute(
                "INSERT INTO respawn_targets (process_name, kill_method, scan_interval) VALUES (?, ?, ?)",
                params![t.process_name, t.kill_method as i64, t.scan_interval as i64],
            );
        }
    }

    /// Load respawn monitor targets
    pub fn load_respawn_targets(&self) -> Vec<crate::state::RespawnTarget> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare("SELECT process_name, kill_method, scan_interval FROM respawn_targets ORDER BY process_name") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let result: Vec<crate::state::RespawnTarget> = match stmt.query_map([], |row| {
            Ok(crate::state::RespawnTarget {
                process_name: row.get(0)?,
                kill_method: row.get::<_, i64>(1)? as u32,
                scan_interval: row.get::<_, i64>(2)? as u32,
                kill_count: 0,
                last_killed_pid: None,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        result
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

/// Delete PAT from config (convenience function)
pub fn delete_pat() {
    let _ = get_config_storage().delete_pat();
}

/// Save DPH scripts to config (convenience function)
pub fn save_dph_scripts(scripts: &[DphScript]) {
    get_config_storage().save_dph_scripts(scripts);
}

/// Load DPH scripts from config (convenience function)
pub fn load_dph_scripts() -> Vec<DphScript> {
    get_config_storage().load_dph_scripts()
}

/// Save DPR scripts to config (convenience function)
pub fn save_dpr_scripts(scripts: &[DprScript]) {
    get_config_storage().save_dpr_scripts(scripts);
}

/// Load DPR scripts from config (convenience function)
pub fn load_dpr_scripts() -> Vec<DprScript> {
    get_config_storage().load_dpr_scripts()
}

/// Save respawn monitor targets (convenience function)
pub fn save_respawn_targets(targets: &[crate::state::RespawnTarget]) {
    get_config_storage().save_respawn_targets(targets);
}

/// Load respawn monitor targets (convenience function)
pub fn load_respawn_targets() -> Vec<crate::state::RespawnTarget> {
    get_config_storage().load_respawn_targets()
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
