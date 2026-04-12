use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use rusqlite::Connection;

const SCHEMA: &str = include_str!("../../sql/schema.sql");

/// Overall application settings (empty for now, ready for future use).
#[derive(Debug, Clone, Default)]
pub struct AppConfig {}

/// Saved limit settings for a single process, keyed by process name.
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    pub dl_enabled: bool,
    pub dl_value: f64,
    pub dl_unit: String,
    pub dl_blocked: bool,
    pub ul_enabled: bool,
    pub ul_value: f64,
    pub ul_unit: String,
    pub ul_blocked: bool,
}

/// Map of process name -> saved settings.
pub type ProcessesConfig = HashMap<String, ProcessConfig>;

/// Returns the config directory, creating it if needed.
/// Uses `%APPDATA%/DecLimiter/` on Windows, `~/.config/DecLimiter/` elsewhere.
fn config_dir() -> PathBuf {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("DecLimiter");
    if !dir.exists() {
        fs::create_dir_all(&dir).ok();
    }
    dir
}

fn db_path() -> PathBuf {
    config_dir().join("declimiter.db")
}

fn open_db() -> rusqlite::Result<Connection> {
    let conn = Connection::open(db_path())?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

pub fn load_app_config() -> AppConfig {
    if let Ok(_conn) = open_db() {
        // AppConfig is currently empty; opening the DB ensures the schema exists.
    }
    AppConfig::default()
}

pub fn save_app_config(_config: &AppConfig) {
    // AppConfig is currently empty; nothing to persist.
    let _ = open_db();
}

pub fn load_processes_config() -> ProcessesConfig {
    let conn = match open_db() {
        Ok(c) => c,
        Err(_) => return ProcessesConfig::new(),
    };

    let mut stmt = match conn.prepare(
        "SELECT process_name, dl_enabled, dl_value, dl_unit, dl_blocked,
                ul_enabled, ul_value, ul_unit, ul_blocked
         FROM process_config"
    ) {
        Ok(s) => s,
        Err(_) => return ProcessesConfig::new(),
    };

    let rows = match stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ProcessConfig {
                dl_enabled: row.get::<_, bool>(1)?,
                dl_value: row.get::<_, f64>(2)?,
                dl_unit: row.get::<_, String>(3)?,
                dl_blocked: row.get::<_, bool>(4)?,
                ul_enabled: row.get::<_, bool>(5)?,
                ul_value: row.get::<_, f64>(6)?,
                ul_unit: row.get::<_, String>(7)?,
                ul_blocked: row.get::<_, bool>(8)?,
            },
        ))
    }) {
        Ok(r) => r,
        Err(_) => return ProcessesConfig::new(),
    };

    let mut map = ProcessesConfig::new();
    for row in rows.flatten() {
        map.insert(row.0, row.1);
    }
    map
}

pub fn save_processes_config(config: &ProcessesConfig) {
    let conn = match open_db() {
        Ok(c) => c,
        Err(_) => return,
    };

    // Wrap in a transaction for atomicity
    let tx = match conn.unchecked_transaction() {
        Ok(t) => t,
        Err(_) => return,
    };

    tx.execute("DELETE FROM process_config", []).ok();

    let mut stmt = match tx.prepare(
        "INSERT INTO process_config
            (process_name, dl_enabled, dl_value, dl_unit, dl_blocked,
             ul_enabled, ul_value, ul_unit, ul_blocked)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
    ) {
        Ok(s) => s,
        Err(_) => return,
    };

    for (name, pc) in config {
        stmt.execute(rusqlite::params![
            name,
            pc.dl_enabled,
            pc.dl_value,
            &pc.dl_unit,
            pc.dl_blocked,
            pc.ul_enabled,
            pc.ul_value,
            &pc.ul_unit,
            pc.ul_blocked,
        ]).ok();
    }

    drop(stmt);
    tx.commit().ok();
}
