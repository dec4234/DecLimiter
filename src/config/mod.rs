use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Overall application settings (empty for now, ready for future use).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {}

/// Saved limit settings for a single process, keyed by process name.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

fn processes_path() -> PathBuf {
    config_dir().join("processes.json")
}

pub fn load_app_config() -> AppConfig {
    let path = config_path();
    match fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => {
            // Create default config file
            let config = AppConfig::default();
            save_app_config(&config);
            config
        }
    }
}

pub fn save_app_config(config: &AppConfig) {
    let path = config_path();
    if let Ok(json) = serde_json::to_string_pretty(config) {
        fs::write(path, json).ok();
    }
}

pub fn load_processes_config() -> ProcessesConfig {
    let path = processes_path();
    match fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => {
            let config = ProcessesConfig::new();
            save_processes_config(&config);
            config
        }
    }
}

pub fn save_processes_config(config: &ProcessesConfig) {
    let path = processes_path();
    if let Ok(json) = serde_json::to_string_pretty(config) {
        fs::write(path, json).ok();
    }
}
