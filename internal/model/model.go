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
	ID            int64
	Username      string
	PasswordHash  string
	Role          Role
	CreatedAt     time.Time
	TOTPSecretEnc string
	TOTPEnabled   bool
}

// CronJob is a scheduled task run by the scheduler.
type CronJob struct {
	ID          int64
	Name        string
	Action      string // poll|backup|fwcheck|gitexport|template
	Target      string // all|site:ID|tag:NAME|device:ID
	TemplateID  *int64
	Guard       int
	Kind        string // interval|daily
	IntervalMin int
	AtHour      int
	AtMin       int
	Weekday     int // -1 any day, 0..6
	Enabled     bool
	LastRun     *time.Time
	LastStatus  string
	NextRun     *time.Time
	CreatedAt   time.Time
}

// Webhook is an outgoing integration endpoint fired on events.
type Webhook struct {
	ID         int64
	URL        string
	Events     string // comma-separated event types, or "all"
	SecretEnc  string
	Enabled    bool
	LastStatus string
	LastAt     *time.Time
	CreatedAt  time.Time
}

// MaintenanceWindow suppresses alert notifications for a device (or the whole
// fleet when DeviceID is nil) during [StartsAt, EndsAt].
type MaintenanceWindow struct {
	ID        int64
	DeviceID  *int64
	StartsAt  time.Time
	EndsAt    time.Time
	Note      string
	CreatedBy string
	CreatedAt time.Time
}

// APIToken is a personal bearer token for the JSON API (hash stored, not value).
type APIToken struct {
	ID        int64
	UserID    int64
	Name      string
	CreatedAt time.Time
	LastUsed  *time.Time
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
	SNMPEnabled   bool
	SNMPCommEnc   string // encrypted community
	SNMPPort      int
	DeviceType      string     // router | switch | mix | "" (unknown)
	LastFail        *time.Time // last poll failure
	PollIntervalSec int        // per-device poll interval in seconds (0 = global default)
}

// FwJob is a firmware upgrade run.
type FwJob struct {
	ID        int64
	CreatedAt time.Time
	Actor     string
	Note      string
	Status    string
}

// FwItem is one device's progress within a firmware upgrade job.
type FwItem struct {
	ID         int64
	JobID      int64
	DeviceID   int64
	DeviceName string
	Target     string
	Status     string
	Detail     string
	UpdatedAt  time.Time
}

// Site is a location grouping devices.
type Site struct {
	ID    int64
	Name  string
	Count int // devices in it
	Lat   *float64
	Lon   *float64
}

// Health is one health sample.
type Health struct {
	DeviceID  int64
	TS        time.Time
	CPU       int     // percent
	FreeMem   int64   // bytes
	TotalMem  int64   // bytes
	Uptime    string  // RouterOS uptime string
	Temp      float64 // °C (0 when unknown)
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

// Client is a connected device seen via DHCP lease or ARP.
type Client struct {
	DeviceID   int64
	DeviceName string
	MAC        string
	IP         string
	Hostname   string
	Iface      string
	Source     string
}

// Port is a physical/interface port for the device faceplate.
type Port struct {
	Name     string
	Type     string
	Running  bool
	Disabled bool
}

// NetAddr is one IP address configured on the device.
type NetAddr struct {
	Address string
	Iface   string
}

// NetMac is one interface MAC on the device.
type NetMac struct {
	Iface string
	Mac   string
}

// LTEInfo is a per-device LTE summary for the device list.
type LTEInfo struct {
	Present    bool
	Info       string // e.g. "lte · -95 dBm · MegaFon"
	RSRP       string // raw RSRP for colour-coding, e.g. "-95"
	FwUpgrade  bool   // modem firmware upgrade available
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
