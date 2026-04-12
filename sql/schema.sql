-- DecLimiter SQLite Schema
-- Database located at: %APPDATA%/DecLimiter/declimiter.db (Windows)
--                       ~/.config/DecLimiter/declimiter.db  (Linux/macOS)

-- Key-value store for application-wide settings.
CREATE TABLE IF NOT EXISTS app_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Per-process bandwidth limit settings, keyed by process name.
CREATE TABLE IF NOT EXISTS process_config (
    process_name TEXT    PRIMARY KEY,
    dl_enabled   INTEGER NOT NULL DEFAULT 0,
    dl_value     REAL    NOT NULL DEFAULT 0.0,
    dl_unit      TEXT    NOT NULL DEFAULT 'KBps',
    dl_blocked   INTEGER NOT NULL DEFAULT 0,
    ul_enabled   INTEGER NOT NULL DEFAULT 0,
    ul_value     REAL    NOT NULL DEFAULT 0.0,
    ul_unit      TEXT    NOT NULL DEFAULT 'KBps',
    ul_blocked   INTEGER NOT NULL DEFAULT 0
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_process_config_dl_enabled
    ON process_config (dl_enabled);

CREATE INDEX IF NOT EXISTS idx_process_config_ul_enabled
    ON process_config (ul_enabled);

CREATE INDEX IF NOT EXISTS idx_process_config_dl_blocked
    ON process_config (dl_blocked);

CREATE INDEX IF NOT EXISTS idx_process_config_ul_blocked
    ON process_config (ul_blocked);
