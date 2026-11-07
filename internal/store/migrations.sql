CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    ip            TEXT NOT NULL,
    api_port      INTEGER NOT NULL DEFAULT 8729,
    api_tls       INTEGER NOT NULL DEFAULT 1,
    api_user      TEXT NOT NULL,
    api_pass_enc  TEXT NOT NULL DEFAULT '',
    ssh_user      TEXT NOT NULL DEFAULT 'admin',
    api_cert_pin  TEXT NOT NULL DEFAULT '',
    ssh_host_pin  TEXT NOT NULL DEFAULT '',
    model         TEXT NOT NULL DEFAULT '',
    serial        TEXT NOT NULL DEFAULT '',
    ros_version   TEXT NOT NULL DEFAULT '',
    last_seen     TIMESTAMP,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    api_ssl_cert    TEXT NOT NULL DEFAULT '',
    api_cert_expiry TIMESTAMP,
    fw_latest       TEXT NOT NULL DEFAULT '',
    fw_channel      TEXT NOT NULL DEFAULT '',
    fw_status       TEXT NOT NULL DEFAULT '',
    UNIQUE(ip, api_port)
);

CREATE TABLE IF NOT EXISTS metrics (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts        TIMESTAMP NOT NULL,
    cpu       INTEGER NOT NULL DEFAULT 0,
    free_mem  INTEGER NOT NULL DEFAULT 0,
    total_mem INTEGER NOT NULL DEFAULT 0,
    uptime    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_metrics_dev_ts ON metrics(device_id, ts);

CREATE TABLE IF NOT EXISTS configs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    taken_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    kind      TEXT NOT NULL DEFAULT 'export',
    sha256    TEXT NOT NULL,
    content   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_configs_dev ON configs(device_id, taken_at);

-- One row per (device, rule). state is 'active' or 'resolved'.
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule       TEXT NOT NULL,
    state      TEXT NOT NULL DEFAULT 'active',
    severity   TEXT NOT NULL DEFAULT 'warn',
    detail     TEXT NOT NULL DEFAULT '',
    since      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(device_id, rule)
);
CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state);

-- Single-row CA store (id=1): the certificate authority ROSMan issues with.
CREATE TABLE IF NOT EXISTS ca (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    cn         TEXT NOT NULL,
    cert_pem   TEXT NOT NULL,
    key_enc    TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor  TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
