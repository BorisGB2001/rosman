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

-- Locations / sites.
CREATE TABLE IF NOT EXISTS sites (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Free-form device grouping tags.
CREATE TABLE IF NOT EXISTS device_tags (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tag       TEXT NOT NULL,
    UNIQUE(device_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_device_tags_tag ON device_tags(tag);

-- Per-interface byte counters sampled at each poll (rates computed on read).
CREATE TABLE IF NOT EXISTS iface_traffic (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    iface     TEXT NOT NULL,
    ts        TIMESTAMP NOT NULL,
    rx_bytes  INTEGER NOT NULL DEFAULT 0,
    tx_bytes  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_iface_dev_if_ts ON iface_traffic(device_id, iface, ts);

-- Connected clients (DHCP leases + ARP), replaced per poll.
CREATE TABLE IF NOT EXISTS device_clients (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    mac       TEXT NOT NULL DEFAULT '',
    ip        TEXT NOT NULL DEFAULT '',
    hostname  TEXT NOT NULL DEFAULT '',
    iface     TEXT NOT NULL DEFAULT '',
    source    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_clients_dev ON device_clients(device_id);
CREATE INDEX IF NOT EXISTS idx_clients_mac ON device_clients(mac);

-- Physical/interface port list for the faceplate, replaced per poll.
CREATE TABLE IF NOT EXISTS device_ports (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    pos       INTEGER NOT NULL DEFAULT 0,
    name      TEXT NOT NULL DEFAULT '',
    type      TEXT NOT NULL DEFAULT '',
    running   INTEGER NOT NULL DEFAULT 0,
    disabled  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ports_dev ON device_ports(device_id, pos);

-- Discovered neighbours (MNDP/LLDP/CDP), replaced per poll.
CREATE TABLE IF NOT EXISTS device_neighbors (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    iface     TEXT NOT NULL DEFAULT '',
    identity  TEXT NOT NULL DEFAULT '',
    ip        TEXT NOT NULL DEFAULT '',
    mac       TEXT NOT NULL DEFAULT '',
    platform  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_neighbors_dev ON device_neighbors(device_id);

-- Named RouterOS config snippets applied with change-guard.
CREATE TABLE IF NOT EXISTS config_templates (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Single-row CA store (id=1): the certificate authority ROSMan issues with.
CREATE TABLE IF NOT EXISTS ca (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    cn         TEXT NOT NULL,
    cert_pem   TEXT NOT NULL,
    key_enc    TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Firmware upgrade jobs and their per-device items.
CREATE TABLE IF NOT EXISTS fw_jobs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor      TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'running'
);
CREATE TABLE IF NOT EXISTS fw_job_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      INTEGER NOT NULL REFERENCES fw_jobs(id) ON DELETE CASCADE,
    device_id   INTEGER NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    target      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'queued',
    detail      TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_fw_items_job ON fw_job_items(job_id);

-- Simple key/value application settings.
CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor  TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

-- Personal API tokens (bearer) for the JSON API. Only the SHA-256 hash is stored.
CREATE TABLE IF NOT EXISTS api_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used  TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);

-- Maintenance windows suppress alert notifications for a device (or the whole
-- fleet when device_id IS NULL) between starts_at and ends_at.
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER,
    starts_at  TIMESTAMP NOT NULL,
    ends_at    TIMESTAMP NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_maint_dev ON maintenance_windows(device_id);

-- Outgoing webhooks: POST a JSON payload to subscribed URLs on events.
CREATE TABLE IF NOT EXISTS webhooks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL,
    events      TEXT NOT NULL DEFAULT 'all',
    secret_enc  TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_status TEXT NOT NULL DEFAULT '',
    last_at     TIMESTAMP,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Scheduled (cron-like) jobs run by the scheduler.
CREATE TABLE IF NOT EXISTS cron_jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL,              -- poll|backup|fwcheck|gitexport|template
    target       TEXT NOT NULL DEFAULT 'all',-- all|site:ID|tag:NAME|device:ID
    template_id  INTEGER,
    guard        INTEGER NOT NULL DEFAULT 120,
    kind         TEXT NOT NULL DEFAULT 'interval', -- interval|daily
    interval_min INTEGER NOT NULL DEFAULT 60,
    at_hour      INTEGER NOT NULL DEFAULT 3,
    at_min       INTEGER NOT NULL DEFAULT 0,
    weekday      INTEGER NOT NULL DEFAULT -1, -- -1 any day, 0..6 Sun..Sat
    enabled      INTEGER NOT NULL DEFAULT 1,
    last_run     TIMESTAMP,
    last_status  TEXT NOT NULL DEFAULT '',
    next_run     TIMESTAMP,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Per-device configured IP addresses and interface MACs (replaced each poll).
CREATE TABLE IF NOT EXISTS device_addrs (
    device_id INTEGER NOT NULL,
    address   TEXT NOT NULL,
    iface     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_device_addrs ON device_addrs(device_id);
CREATE TABLE IF NOT EXISTS device_macs (
    device_id INTEGER NOT NULL,
    iface     TEXT NOT NULL DEFAULT '',
    mac       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_macs ON device_macs(device_id);

-- Per-device LTE summary (one modem typical), updated on poll.
CREATE TABLE IF NOT EXISTS device_lte (
    device_id  INTEGER PRIMARY KEY,
    present    INTEGER NOT NULL DEFAULT 0,
    info       TEXT NOT NULL DEFAULT '',
    rsrp       TEXT NOT NULL DEFAULT '',
    fw_upgrade INTEGER NOT NULL DEFAULT 0
);

-- Per-device active VPN tunnel summary, updated on poll.
CREATE TABLE IF NOT EXISTS device_vpn (
    device_id INTEGER PRIMARY KEY,
    count     INTEGER NOT NULL DEFAULT 0,
    info      TEXT NOT NULL DEFAULT ''
);

-- Bridge forwarding database (FDB): learned MAC -> physical member port, per
-- device. Ground truth for which port a MAC/host sits behind.
CREATE TABLE IF NOT EXISTS bridge_hosts (
    device_id INTEGER NOT NULL,
    mac       TEXT NOT NULL,
    iface     TEXT NOT NULL DEFAULT '',
    bridge    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_bridge_hosts_dev ON bridge_hosts(device_id);
CREATE INDEX IF NOT EXISTS idx_bridge_hosts_mac ON bridge_hosts(mac);

-- Per-device uploaded images (rack photos, better product shots) for the gallery.
CREATE TABLE IF NOT EXISTS device_images (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    INTEGER NOT NULL,
    caption      TEXT NOT NULL DEFAULT '',
    content_type TEXT NOT NULL DEFAULT '',
    data         BLOB,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_device_images ON device_images(device_id);

-- Saved topology node positions (manual drag layout).
CREATE TABLE IF NOT EXISTS topo_pos (
    device_id INTEGER PRIMARY KEY,
    x         REAL NOT NULL,
    y         REAL NOT NULL
);

-- Config compliance rules checked against each device's latest /export.
CREATE TABLE IF NOT EXISTS compliance_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT 'warn',  -- warn | crit
    kind       TEXT NOT NULL DEFAULT 'require',-- require | forbid | require_re | forbid_re
    pattern    TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
