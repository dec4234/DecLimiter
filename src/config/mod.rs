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
    match open_db() {
        Ok(conn) => load_processes_config_from(&conn),
        Err(_) => ProcessesConfig::new(),
    }
}

/// Reads the per-process settings from an open database that has the schema.
fn load_processes_config_from(conn: &Connection) -> ProcessesConfig {
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
    if let Ok(conn) = open_db() {
        save_processes_config_to(&conn, config);
    }
}

/// Replaces all per-process settings in an open database that has the schema.
fn save_processes_config_to(conn: &Connection, config: &ProcessesConfig) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory database with the schema, so the tests never touch the
    /// real settings file.
    fn memory_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn
    }

    fn sample(dl_value: f64, ul_blocked: bool) -> ProcessConfig {
        ProcessConfig {
            dl_enabled: true,
            dl_value,
            dl_unit: "MBps".to_string(),
            dl_blocked: false,
            ul_enabled: false,
            ul_value: 12.5,
            ul_unit: "Bps".to_string(),
            ul_blocked,
        }
    }

    fn assert_same(a: &ProcessConfig, b: &ProcessConfig) {
        assert_eq!(a.dl_enabled, b.dl_enabled);
        assert_eq!(a.dl_value, b.dl_value);
        assert_eq!(a.dl_unit, b.dl_unit);
        assert_eq!(a.dl_blocked, b.dl_blocked);
        assert_eq!(a.ul_enabled, b.ul_enabled);
        assert_eq!(a.ul_value, b.ul_value);
        assert_eq!(a.ul_unit, b.ul_unit);
        assert_eq!(a.ul_blocked, b.ul_blocked);
    }

    #[test]
    fn schema_can_run_more_than_once() {
        let conn = memory_db();
        conn.execute_batch(SCHEMA).expect("the schema must use IF NOT EXISTS");
    }

    #[test]
    fn empty_database_gives_empty_config() {
        assert!(load_processes_config_from(&memory_db()).is_empty());
    }

    #[test]
    fn saved_config_loads_back_the_same() {
        let conn = memory_db();
        let mut config = ProcessesConfig::new();
        config.insert("chrome.exe".to_string(), sample(2.5, false));
        config.insert("steam.exe".to_string(), sample(0.0, true));

        save_processes_config_to(&conn, &config);
        let loaded = load_processes_config_from(&conn);

        assert_eq!(loaded.len(), 2);
        assert_same(&loaded["chrome.exe"], &config["chrome.exe"]);
        assert_same(&loaded["steam.exe"], &config["steam.exe"]);
    }

    #[test]
    fn save_replaces_all_earlier_rows() {
        let conn = memory_db();
        let mut first = ProcessesConfig::new();
        first.insert("old.exe".to_string(), sample(1.0, false));
        first.insert("kept.exe".to_string(), sample(1.0, false));
        save_processes_config_to(&conn, &first);

        let mut second = ProcessesConfig::new();
        second.insert("kept.exe".to_string(), sample(9.0, true));
        save_processes_config_to(&conn, &second);

        let loaded = load_processes_config_from(&conn);
        assert_eq!(loaded.len(), 1, "old.exe must be gone");
        assert_same(&loaded["kept.exe"], &second["kept.exe"]);

        save_processes_config_to(&conn, &ProcessesConfig::new());
        assert!(load_processes_config_from(&conn).is_empty());
    }

    #[test]
    fn names_with_quotes_and_unicode_are_kept() {
        let conn = memory_db();
        let mut config = ProcessesConfig::new();
        let name = "it's \"odd\" ünïcødé 程序.exe";
        config.insert(name.to_string(), sample(3.0, false));

        save_processes_config_to(&conn, &config);
        assert!(load_processes_config_from(&conn).contains_key(name));
    }

    #[test]
    fn schema_defaults_fill_missing_columns() {
        let conn = memory_db();
        conn.execute("INSERT INTO process_config (process_name) VALUES ('bare.exe')", []).unwrap();

        let loaded = load_processes_config_from(&conn);
        let bare = &loaded["bare.exe"];
        assert!(!bare.dl_enabled && !bare.dl_blocked && !bare.ul_enabled && !bare.ul_blocked);
        assert_eq!(bare.dl_value, 0.0);
        assert_eq!(bare.ul_value, 0.0);
        assert_eq!(bare.dl_unit, "KBps");
        assert_eq!(bare.ul_unit, "KBps");
    }

    #[test]
    fn a_bad_row_is_skipped_and_the_rest_load() {
        let conn = memory_db();
        conn.execute("INSERT INTO process_config (process_name, dl_value) VALUES ('bad.exe', 'not a number')", []).unwrap();
        conn.execute("INSERT INTO process_config (process_name, dl_value) VALUES ('good.exe', 4.0)", []).unwrap();

        let loaded = load_processes_config_from(&conn);
        assert!(!loaded.contains_key("bad.exe"));
        assert_eq!(loaded["good.exe"].dl_value, 4.0);
    }

    #[test]
    fn missing_table_gives_empty_config_and_save_does_not_panic() {
        // A database without the schema.
        let conn = Connection::open_in_memory().unwrap();
        assert!(load_processes_config_from(&conn).is_empty());

        let mut config = ProcessesConfig::new();
        config.insert("x.exe".to_string(), sample(1.0, false));
        save_processes_config_to(&conn, &config);
    }
}
