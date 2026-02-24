//! SQLite storage for saved packets (.dpp format)
//!
//! Provides persistent storage for edited/saved packets that can be reused.

use crate::packet_capture::{CapturedPacket, PacketDirection, PacketProtocol};
use parking_lot::Mutex;
use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

/// Saved packet entry with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedPacket {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub protocol: PacketProtocol,
    pub direction: PacketDirection,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub payload: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// .dpp file format (DioProcess Packet)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DppFile {
    pub version: u32,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub protocol: String,
    pub direction: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub payload_hex: String,
}

impl DppFile {
    pub const VERSION: u32 = 1;

    pub fn from_packet(packet: &CapturedPacket, name: &str, description: &str, tags: &[String]) -> Self {
        Self {
            version: Self::VERSION,
            name: name.to_string(),
            description: description.to_string(),
            tags: tags.to_vec(),
            protocol: format!("{:?}", packet.protocol),
            direction: format!("{:?}", packet.direction),
            local_addr: packet.local_addr.to_string(),
            local_port: packet.local_port,
            remote_addr: packet.remote_addr.to_string(),
            remote_port: packet.remote_port,
            payload_hex: packet.payload.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
        }
    }

    pub fn to_captured_packet(&self) -> CapturedPacket {
        let protocol = match self.protocol.to_uppercase().as_str() {
            "TCP" => PacketProtocol::Tcp,
            _ => PacketProtocol::Udp,
        };
        let direction = match self.direction.to_uppercase().as_str() {
            "INBOUND" => PacketDirection::Inbound,
            _ => PacketDirection::Outbound,
        };
        let payload: Vec<u8> = self.payload_hex
            .split_whitespace()
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        CapturedPacket {
            id: 0,
            timestamp: 0,
            pid: 0,
            direction,
            protocol,
            local_addr: self.local_addr.parse().unwrap_or([127, 0, 0, 1].into()),
            local_port: self.local_port,
            remote_addr: self.remote_addr.parse().unwrap_or([127, 0, 0, 1].into()),
            remote_port: self.remote_port,
            payload,
        }
    }

    pub fn save_to_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    pub fn load_from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Packet storage manager
pub struct PacketStorage {
    conn: Arc<Mutex<Connection>>,
}

impl PacketStorage {
    /// Create or open packet storage at the specified path
    pub fn open(db_path: PathBuf) -> SqlResult<Self> {
        let conn = Connection::open(&db_path)?;

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=5000;",
        )?;

        // Create saved_packets table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS saved_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                tags TEXT DEFAULT '',
                protocol INTEGER NOT NULL,
                direction INTEGER NOT NULL,
                local_addr TEXT NOT NULL,
                local_port INTEGER NOT NULL,
                remote_addr TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                payload BLOB NOT NULL,
                created_at INTEGER DEFAULT (strftime('%s', 'now')),
                updated_at INTEGER DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )?;

        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_packets_name ON saved_packets(name);
             CREATE INDEX IF NOT EXISTS idx_packets_tags ON saved_packets(tags);
             CREATE INDEX IF NOT EXISTS idx_packets_created ON saved_packets(created_at DESC);",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open storage in the default location
    pub fn open_default() -> SqlResult<Self> {
        let db_path = get_packet_db_path();
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Self::open(db_path)
    }

    /// Save a packet to the database
    pub fn save_packet(
        &self,
        name: &str,
        description: &str,
        tags: &[String],
        packet: &CapturedPacket,
    ) -> SqlResult<i64> {
        let conn = self.conn.lock();
        let tags_str = tags.join(",");

        conn.execute(
            "INSERT INTO saved_packets (name, description, tags, protocol, direction, 
             local_addr, local_port, remote_addr, remote_port, payload)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                name,
                description,
                tags_str,
                packet.protocol as u8,
                packet.direction as u8,
                packet.local_addr.to_string(),
                packet.local_port,
                packet.remote_addr.to_string(),
                packet.remote_port,
                &packet.payload,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Update an existing saved packet
    pub fn update_packet(
        &self,
        id: i64,
        name: &str,
        description: &str,
        tags: &[String],
        packet: &CapturedPacket,
    ) -> SqlResult<()> {
        let conn = self.conn.lock();
        let tags_str = tags.join(",");

        conn.execute(
            "UPDATE saved_packets SET 
             name = ?, description = ?, tags = ?, protocol = ?, direction = ?,
             local_addr = ?, local_port = ?, remote_addr = ?, remote_port = ?, payload = ?,
             updated_at = strftime('%s', 'now')
             WHERE id = ?",
            params![
                name,
                description,
                tags_str,
                packet.protocol as u8,
                packet.direction as u8,
                packet.local_addr.to_string(),
                packet.local_port,
                packet.remote_addr.to_string(),
                packet.remote_port,
                &packet.payload,
                id,
            ],
        )?;

        Ok(())
    }

    /// Delete a saved packet
    pub fn delete_packet(&self, id: i64) -> SqlResult<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM saved_packets WHERE id = ?", params![id])?;
        Ok(())
    }

    /// Get all saved packets
    pub fn get_all_packets(&self) -> Vec<SavedPacket> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare(
            "SELECT id, name, description, tags, protocol, direction,
                    local_addr, local_port, remote_addr, remote_port, payload,
                    created_at, updated_at
             FROM saved_packets ORDER BY updated_at DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map([], |row| {
            let tags_str: String = row.get(3)?;
            let tags: Vec<String> = if tags_str.is_empty() {
                Vec::new()
            } else {
                tags_str.split(',').map(|s| s.to_string()).collect()
            };

            Ok(SavedPacket {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                tags,
                protocol: PacketProtocol::from(row.get::<_, u8>(4)?),
                direction: PacketDirection::from(row.get::<_, u8>(5)?),
                local_addr: row.get(6)?,
                local_port: row.get(7)?,
                remote_addr: row.get(8)?,
                remote_port: row.get(9)?,
                payload: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Search packets by name or tags
    pub fn search_packets(&self, query: &str) -> Vec<SavedPacket> {
        let conn = self.conn.lock();
        let pattern = format!("%{}%", query);

        let mut stmt = match conn.prepare(
            "SELECT id, name, description, tags, protocol, direction,
                    local_addr, local_port, remote_addr, remote_port, payload,
                    created_at, updated_at
             FROM saved_packets 
             WHERE name LIKE ? OR description LIKE ? OR tags LIKE ?
             ORDER BY updated_at DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map(params![&pattern, &pattern, &pattern], |row| {
            let tags_str: String = row.get(3)?;
            let tags: Vec<String> = if tags_str.is_empty() {
                Vec::new()
            } else {
                tags_str.split(',').map(|s| s.to_string()).collect()
            };

            Ok(SavedPacket {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                tags,
                protocol: PacketProtocol::from(row.get::<_, u8>(4)?),
                direction: PacketDirection::from(row.get::<_, u8>(5)?),
                local_addr: row.get(6)?,
                local_port: row.get(7)?,
                remote_addr: row.get(8)?,
                remote_port: row.get(9)?,
                payload: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Get a single packet by ID
    pub fn get_packet(&self, id: i64) -> Option<SavedPacket> {
        let conn = self.conn.lock();
        
        conn.query_row(
            "SELECT id, name, description, tags, protocol, direction,
                    local_addr, local_port, remote_addr, remote_port, payload,
                    created_at, updated_at
             FROM saved_packets WHERE id = ?",
            params![id],
            |row| {
                let tags_str: String = row.get(3)?;
                let tags: Vec<String> = if tags_str.is_empty() {
                    Vec::new()
                } else {
                    tags_str.split(',').map(|s| s.to_string()).collect()
                };

                Ok(SavedPacket {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    tags,
                    protocol: PacketProtocol::from(row.get::<_, u8>(4)?),
                    direction: PacketDirection::from(row.get::<_, u8>(5)?),
                    local_addr: row.get(6)?,
                    local_port: row.get(7)?,
                    remote_addr: row.get(8)?,
                    remote_port: row.get(9)?,
                    payload: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            },
        ).ok()
    }

    /// Import a .dpp file into the database
    pub fn import_dpp(&self, path: &std::path::Path) -> std::io::Result<i64> {
        let dpp = DppFile::load_from_file(path)?;
        let packet = dpp.to_captured_packet();
        
        self.save_packet(&dpp.name, &dpp.description, &dpp.tags, &packet)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }

    /// Export a saved packet to .dpp file
    pub fn export_dpp(&self, id: i64, path: &std::path::Path) -> std::io::Result<()> {
        let saved = self.get_packet(id)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Packet not found"))?;
        
        let packet = saved.to_captured_packet();
        let dpp = DppFile::from_packet(&packet, &saved.name, &saved.description, &saved.tags);
        dpp.save_to_file(path)
    }

    /// Get packet count
    pub fn count(&self) -> usize {
        let conn = self.conn.lock();
        conn.query_row("SELECT COUNT(*) FROM saved_packets", [], |row| row.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }
}

impl SavedPacket {
    /// Convert to CapturedPacket for injection
    pub fn to_captured_packet(&self) -> CapturedPacket {
        CapturedPacket {
            id: self.id as u64,
            timestamp: 0,
            pid: 0,
            direction: self.direction,
            protocol: self.protocol,
            local_addr: self.local_addr.parse().unwrap_or([127, 0, 0, 1].into()),
            local_port: self.local_port,
            remote_addr: self.remote_addr.parse().unwrap_or([127, 0, 0, 1].into()),
            remote_port: self.remote_port,
            payload: self.payload.clone(),
        }
    }
}

/// Get the default packet database path
pub fn get_packet_db_path() -> PathBuf {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(local_app_data)
        .join("DioProcess")
        .join("packets.db")
}

/// Global packet storage instance
static PACKET_STORAGE: once_cell::sync::Lazy<Option<PacketStorage>> =
    once_cell::sync::Lazy::new(|| PacketStorage::open_default().ok());

/// Get the global packet storage
pub fn get_packet_storage() -> Option<&'static PacketStorage> {
    PACKET_STORAGE.as_ref()
}
