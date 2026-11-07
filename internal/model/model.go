// Package model holds the plain data types shared across rosman.
package model

import "time"

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         Role
	CreatedAt    time.Time
}

// Device is a managed RouterOS unit.
type Device struct {
	ID          int64
	Name        string
	IP          string
	APIPort     int
	APITLS      bool
	APIUser     string
	APIPassEnc  string // AES-GCM encrypted
	SSHUser     string
	APICertPin  string // sha256 hex of the device's API TLS leaf cert (TOFU)
	SSHHostPin  string // sha256 base64 of the device's SSH host key (TOFU)
	Model       string
	Serial      string
	ROSVersion  string
	LastSeen    *time.Time
	CreatedAt   time.Time
	APISSLCert    string     // name of the cert bound to api-ssl
	APICertExpiry *time.Time // its invalid-after
	FwLatest      string     // latest RouterOS version known to the device
	FwChannel     string     // update channel (stable/testing/...)
	FwStatus      string     // device's update status string
	SiteID        *int64     // location
	SiteName      string     // joined for display
	Tags          []string   // grouping tags (filled on demand)
}

// Site is a location grouping devices.
type Site struct {
	ID    int64
	Name  string
	Count int // devices in it
}

// Health is one health sample.
type Health struct {
	DeviceID  int64
	TS        time.Time
	CPU       int    // percent
	FreeMem   int64  // bytes
	TotalMem  int64  // bytes
	Uptime    string // RouterOS uptime string
}

// Alert is one monitoring finding (one row per device+rule).
type Alert struct {
	ID        int64
	DeviceID  int64
	Device    string // joined device name, for listings
	Rule      string
	State     string // "active" | "resolved"
	Severity  string // "warn" | "crit"
	Detail    string
	Since     time.Time
	UpdatedAt time.Time
}

// Audit is one entry in the audit log.
type Audit struct {
	ID     int64
	TS     time.Time
	Actor  string
	Action string
	Detail string
}

// IfaceSample is one per-interface byte-counter reading.
type IfaceSample struct {
	Iface   string
	TS      time.Time
	RxBytes int64
	TxBytes int64
	Running bool
}

// Neighbor is a discovered adjacent device (MNDP/LLDP/CDP).
type Neighbor struct {
	DeviceID int64
	Iface    string
	Identity string
	IP       string
	MAC      string
	Platform string
}

// Template is a named RouterOS config snippet.
type Template struct {
	ID        int64
	Name      string
	Body      string
	CreatedAt time.Time
}

// Config is one stored configuration snapshot.
type Config struct {
	ID       int64
	DeviceID int64
	TakenAt  time.Time
	Kind     string // "export" | "binary"
	SHA256   string
	Content  string
}
