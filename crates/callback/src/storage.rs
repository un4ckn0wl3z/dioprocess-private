//! SQLite storage for kernel callback events
//!
//! Provides persistent storage with batched writes and efficient queries.

use crate::types::{CallbackEvent, EventCategory, EventType, RegistryOperation};
use parking_lot::Mutex;
use rusqlite::{params, Connection, Result as SqlResult};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default batch size before flushing to database
const DEFAULT_BATCH_SIZE: usize = 500;
/// Default flush interval in milliseconds
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 100;
/// Default retention period in hours (24 hours)
const DEFAULT_RETENTION_HOURS: u64 = 24;

/// Event storage manager with batched writes
pub struct EventStorage {
    conn: Arc<Mutex<Connection>>,
    write_buffer: Arc<Mutex<Vec<CallbackEvent>>>,
    last_flush: Arc<Mutex<Instant>>,
    batch_size: usize,
    flush_interval: Duration,
}

impl EventStorage {
    /// Create or open event storage at the specified path
    pub fn open(db_path: PathBuf) -> SqlResult<Self> {
        let conn = Connection::open(&db_path)?;

        // Enable WAL mode for concurrent reads during writes
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=10000;
             PRAGMA temp_store=MEMORY;",
        )?;

        // Create events table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type INTEGER NOT NULL,
                process_id INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                parent_process_id INTEGER,
                creating_process_id INTEGER,
                command_line TEXT,
                thread_id INTEGER,
                exit_code INTEGER,
                image_base INTEGER,
                image_size INTEGER,
                image_name TEXT,
                is_system_image INTEGER,
                is_kernel_image INTEGER,
                source_process_id INTEGER,
                source_thread_id INTEGER,
                target_process_id INTEGER,
                target_thread_id INTEGER,
                desired_access INTEGER,
                granted_access INTEGER,
                source_image_name TEXT,
                key_name TEXT,
                value_name TEXT,
                registry_operation INTEGER,
                created_at INTEGER DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )?;

        // Create indexes for common queries
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
             CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
             CREATE INDEX IF NOT EXISTS idx_events_pid ON events(process_id);
             CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);",
        )?;

        // Create process name cache table (PID → name mapping)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS process_names (
                pid INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                updated_at INTEGER DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            write_buffer: Arc::new(Mutex::new(Vec::with_capacity(DEFAULT_BATCH_SIZE))),
            last_flush: Arc::new(Mutex::new(Instant::now())),
            batch_size: DEFAULT_BATCH_SIZE,
            flush_interval: Duration::from_millis(DEFAULT_FLUSH_INTERVAL_MS),
        })
    }

    /// Open storage in the default location (AppData/Local/DioProcess)
    pub fn open_default() -> SqlResult<Self> {
        let db_path = get_default_db_path();
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Self::open(db_path)
    }

    /// Add events to the write buffer, flushing if needed
    pub fn add_events(&self, events: Vec<CallbackEvent>) {
        if events.is_empty() {
            return;
        }

        let mut buffer = self.write_buffer.lock();
        buffer.extend(events);

        let should_flush = buffer.len() >= self.batch_size
            || self.last_flush.lock().elapsed() >= self.flush_interval;

        if should_flush {
            let events_to_write: Vec<_> = buffer.drain(..).collect();
            drop(buffer);
            self.flush_events(events_to_write);
        }
    }

    /// Force flush any buffered events
    pub fn flush(&self) {
        let events: Vec<_> = self.write_buffer.lock().drain(..).collect();
        if !events.is_empty() {
            self.flush_events(events);
        }
    }

    fn flush_events(&self, mut events: Vec<CallbackEvent>) {
        let conn = self.conn.lock();

        // Step 1: Cache process names from ProcessCreate events
        Self::cache_process_names(&conn, &events);

        // Step 2: Resolve <PID X> placeholders from cache
        Self::resolve_process_names(&conn, &mut events);

        // Step 3: Insert events
        if let Err(e) = Self::insert_events_batch(&conn, &events) {
            eprintln!("Failed to flush events: {}", e);
        }
        *self.last_flush.lock() = Instant::now();
    }

    /// Cache process names from ProcessCreate events
    fn cache_process_names(conn: &Connection, events: &[CallbackEvent]) {
        let mut stmt = match conn.prepare_cached(
            "INSERT OR REPLACE INTO process_names (pid, name, updated_at) VALUES (?, ?, strftime('%s', 'now'))"
        ) {
            Ok(s) => s,
            Err(_) => return,
        };

        for event in events {
            // Only cache from ProcessCreate events with valid names
            if event.event_type == EventType::ProcessCreate
                && !event.process_name.starts_with("<PID")
            {
                let _ = stmt.execute(params![event.process_id, &event.process_name]);
            }
        }
    }

    /// Resolve <PID X> placeholders using cached process names
    fn resolve_process_names(conn: &Connection, events: &mut [CallbackEvent]) {
        for event in events.iter_mut() {
            if event.process_name.starts_with("<PID") {
                if let Ok(name) = conn.query_row(
                    "SELECT name FROM process_names WHERE pid = ?",
                    params![event.process_id],
                    |row| row.get::<_, String>(0),
                ) {
                    event.process_name = name;
                }
            }
        }
    }

    fn insert_events_batch(conn: &Connection, events: &[CallbackEvent]) -> SqlResult<()> {
        let mut stmt = conn.prepare_cached(
            "INSERT INTO events (
                timestamp, event_type, process_id, process_name,
                parent_process_id, creating_process_id, command_line,
                thread_id, exit_code, image_base, image_size, image_name,
                is_system_image, is_kernel_image, source_process_id, source_thread_id,
                target_process_id, target_thread_id, desired_access, granted_access,
                source_image_name, key_name, value_name, registry_operation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )?;

        for event in events {
            stmt.execute(params![
                event.timestamp as i64,
                event.event_type as u32,
                event.process_id,
                &event.process_name,
                event.parent_process_id,
                event.creating_process_id,
                &event.command_line,
                event.thread_id,
                event.exit_code,
                event.image_base.map(|v| v as i64),
                event.image_size.map(|v| v as i64),
                &event.image_name,
                event.is_system_image.map(|b| b as i32),
                event.is_kernel_image.map(|b| b as i32),
                event.source_process_id,
                event.source_thread_id,
                event.target_process_id,
                event.target_thread_id,
                event.desired_access,
                event.granted_access,
                &event.source_image_name,
                &event.key_name,
                &event.value_name,
                event.registry_operation.map(|op| op as u32),
            ])?;
        }

        Ok(())
    }

    /// Query events with filtering and pagination
    pub fn query_events(&self, filter: &EventFilter, limit: usize, offset: usize) -> Vec<CallbackEvent> {
        self.flush(); // Ensure buffered events are written

        let conn = self.conn.lock();
        let (where_clause, params) = filter.to_sql();

        let sql = format!(
            "SELECT timestamp, event_type, process_id, process_name,
                    parent_process_id, creating_process_id, command_line,
                    thread_id, exit_code, image_base, image_size, image_name,
                    is_system_image, is_kernel_image, source_process_id, source_thread_id,
                    target_process_id, target_thread_id, desired_access, granted_access,
                    source_image_name, key_name, value_name, registry_operation
             FROM events
             {}
             ORDER BY timestamp DESC
             LIMIT ? OFFSET ?",
            if where_clause.is_empty() {
                String::new()
            } else {
                format!("WHERE {}", where_clause)
            }
        );

        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        // Build parameter list
        let mut all_params: Vec<Box<dyn rusqlite::ToSql>> = params;
        all_params.push(Box::new(limit as i64));
        all_params.push(Box::new(offset as i64));

        let param_refs: Vec<&dyn rusqlite::ToSql> = all_params.iter().map(|p| p.as_ref()).collect();

        let rows = match stmt.query_map(param_refs.as_slice(), |row| {
            Ok(CallbackEvent {
                timestamp: row.get::<_, i64>(0)? as u64,
                event_type: EventType::from_u32(row.get::<_, u32>(1)?).unwrap_or(EventType::ProcessCreate),
                process_id: row.get(2)?,
                process_name: row.get(3)?,
                parent_process_id: row.get(4)?,
                creating_process_id: row.get(5)?,
                command_line: row.get(6)?,
                thread_id: row.get(7)?,
                exit_code: row.get(8)?,
                image_base: row.get::<_, Option<i64>>(9)?.map(|v| v as u64),
                image_size: row.get::<_, Option<i64>>(10)?.map(|v| v as u64),
                image_name: row.get(11)?,
                is_system_image: row.get::<_, Option<i32>>(12)?.map(|v| v != 0),
                is_kernel_image: row.get::<_, Option<i32>>(13)?.map(|v| v != 0),
                source_process_id: row.get(14)?,
                source_thread_id: row.get(15)?,
                target_process_id: row.get(16)?,
                target_thread_id: row.get(17)?,
                desired_access: row.get(18)?,
                granted_access: row.get(19)?,
                source_image_name: row.get(20)?,
                key_name: row.get(21)?,
                value_name: row.get(22)?,
                registry_operation: row.get::<_, Option<u32>>(23)?.and_then(|v| match v {
                    0 => Some(RegistryOperation::CreateKey),
                    1 => Some(RegistryOperation::OpenKey),
                    2 => Some(RegistryOperation::SetValue),
                    3 => Some(RegistryOperation::DeleteKey),
                    4 => Some(RegistryOperation::DeleteValue),
                    5 => Some(RegistryOperation::RenameKey),
                    6 => Some(RegistryOperation::QueryValue),
                    _ => None,
                }),
            })
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Get total event count (optionally filtered)
    pub fn count_events(&self, filter: &EventFilter) -> usize {
        self.flush();

        let conn = self.conn.lock();
        let (where_clause, params) = filter.to_sql();

        let sql = format!(
            "SELECT COUNT(*) FROM events {}",
            if where_clause.is_empty() {
                String::new()
            } else {
                format!("WHERE {}", where_clause)
            }
        );

        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

        conn.query_row(&sql, param_refs.as_slice(), |row| row.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }

    /// Delete events older than the retention period
    pub fn cleanup_old_events(&self, retention_hours: u64) {
        let conn = self.conn.lock();
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (retention_hours * 3600);

        let _ = conn.execute(
            "DELETE FROM events WHERE created_at < ?",
            params![cutoff as i64],
        );

        // Also cleanup old process name cache entries
        let _ = conn.execute(
            "DELETE FROM process_names WHERE updated_at < ?",
            params![cutoff as i64],
        );
    }

    /// Clear all events
    pub fn clear_all(&self) {
        self.write_buffer.lock().clear();
        let conn = self.conn.lock();
        let _ = conn.execute("DELETE FROM events", []);
        let _ = conn.execute("VACUUM", []);
    }

    /// Get database file size in bytes
    pub fn db_size(&self) -> u64 {
        let db_path = get_default_db_path();
        std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0)
    }
}

impl Drop for EventStorage {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Filter for querying events
#[derive(Default, Clone)]
pub struct EventFilter {
    pub event_type: Option<EventType>,
    pub category: Option<EventCategory>,
    pub process_id: Option<u32>,
    pub search: Option<String>,
}

impl EventFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_type(mut self, event_type: EventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    pub fn with_category(mut self, category: EventCategory) -> Self {
        self.category = Some(category);
        self
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.process_id = Some(pid);
        self
    }

    pub fn with_search(mut self, search: String) -> Self {
        if !search.is_empty() {
            self.search = Some(search);
        }
        self
    }

    fn to_sql(&self) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(event_type) = self.event_type {
            conditions.push("event_type = ?".to_string());
            params.push(Box::new(event_type as u32));
        }

        if let Some(category) = self.category {
            let types: Vec<u32> = match category {
                EventCategory::Process => vec![0, 1], // ProcessCreate, ProcessExit
                EventCategory::Thread => vec![2, 3],  // ThreadCreate, ThreadExit
                EventCategory::Image => vec![4],      // ImageLoad
                EventCategory::Handle => vec![5, 6, 7, 8], // Handle operations
                EventCategory::Registry => vec![9, 10, 11, 12, 13, 14, 15], // Registry operations
            };
            let placeholders: Vec<_> = types.iter().map(|_| "?").collect();
            conditions.push(format!("event_type IN ({})", placeholders.join(", ")));
            for t in types {
                params.push(Box::new(t));
            }
        }

        if let Some(pid) = self.process_id {
            conditions.push("process_id = ?".to_string());
            params.push(Box::new(pid));
        }

        if let Some(ref search) = self.search {
            let pattern = format!("%{}%", search);
            conditions.push(
                "(process_name LIKE ? OR command_line LIKE ? OR image_name LIKE ? OR key_name LIKE ? OR value_name LIKE ? OR CAST(process_id AS TEXT) LIKE ?)".to_string()
            );
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern));
        }

        (conditions.join(" AND "), params)
    }
}

/// Get the default database path
pub fn get_default_db_path() -> PathBuf {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(local_app_data)
        .join("DioProcess")
        .join("events.db")
}

/// Run cleanup of old events (call periodically)
pub fn run_retention_cleanup(storage: &EventStorage) {
    storage.cleanup_old_events(DEFAULT_RETENTION_HOURS);
}
