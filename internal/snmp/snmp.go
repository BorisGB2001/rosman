// Package snmp polls RouterOS devices over SNMP v2c for load/health, as an
// alternative/addition to the API. OIDs come from standard MIB-2, HOST-RESOURCES
// and the MikroTik enterprise MIB (numeric OIDs — facts, not vendor assets).
package snmp

import (
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Result is one SNMP health reading.
type Result struct {
	SysName  string
	Uptime   string
	CPU      int
	MemUsed  int64
	MemTotal int64
	Temp     float64
}

const (
	oidSysName  = "1.3.6.1.2.1.1.5.0"
	oidUptime   = "1.3.6.1.2.1.1.3.0"
	oidTemp     = "1.3.6.1.4.1.14988.1.1.3.10.0" // mtxrHlTemperature
	oidProcLoad = "1.3.6.1.2.1.25.3.3.1.2"       // hrProcessorLoad
	oidStDescr  = "1.3.6.1.2.1.25.2.3.1.3"       // hrStorageDescr
	oidStUnits  = "1.3.6.1.2.1.25.2.3.1.4"       // hrStorageAllocationUnits
	oidStSize   = "1.3.6.1.2.1.25.2.3.1.5"       // hrStorageSize
	oidStUsed   = "1.3.6.1.2.1.25.2.3.1.6"       // hrStorageUsed
)

// Poll collects an SNMP reading from the device.
func Poll(ip, community string, port int, timeout time.Duration) (Result, error) {
	if port == 0 {
		port = 161
	}
	g := &gosnmp.GoSNMP{
		Target: ip, Port: uint16(port), Community: community,
		Version: gosnmp.Version2c, Timeout: timeout, Retries: 1, MaxOids: 60,
	}
	if err := g.Connect(); err != nil {
		return Result{}, err
	}
	defer g.Conn.Close()

	var r Result
	pkt, err := g.Get([]string{oidSysName, oidUptime, oidTemp})
	if err != nil {
		return r, err
	}
	for _, v := range pkt.Variables {
		switch {
		case strings.HasSuffix(v.Name, oidSysName[1:]) || v.Name == "."+oidSysName:
			r.SysName = toStr(v)
		case v.Name == "."+oidUptime:
			r.Uptime = ticks(v)
		case v.Name == "."+oidTemp:
			t := toFloat(v)
			if t > 200 {
				t /= 10
			}
			r.Temp = t
		}
	}

	if vals, err := g.WalkAll(oidProcLoad); err == nil && len(vals) > 0 {
		sum := 0
		for _, v := range vals {
			sum += int(toFloat(v))
		}
		r.CPU = sum / len(vals)
	}

	if descrs, err := g.WalkAll(oidStDescr); err == nil {
		for _, d := range descrs {
			name := strings.ToLower(toStr(d))
			if !strings.Contains(name, "memory") && !strings.Contains(name, "ram") {
				continue
			}
			idx := lastElem(d.Name)
			if idx == "" {
				continue
			}
			p, err := g.Get([]string{oidStUnits + "." + idx, oidStSize + "." + idx, oidStUsed + "." + idx})
			if err != nil || len(p.Variables) < 3 {
				continue
			}
			units := toFloat(p.Variables[0])
			r.MemTotal = int64(toFloat(p.Variables[1]) * units)
			r.MemUsed = int64(toFloat(p.Variables[2]) * units)
			break
		}
	}
	return r, nil
}

func toStr(v gosnmp.SnmpPDU) string {
	if b, ok := v.Value.([]byte); ok {
		return string(b)
	}
	return fmt.Sprintf("%v", v.Value)
}

func toFloat(v gosnmp.SnmpPDU) float64 {
	switch n := v.Value.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case uint:
		return float64(n)
	case uint32:
		return float64(n)
	case uint64:
		return float64(n)
	case float64:
		return n
	default:
		return float64(gosnmp.ToBigInt(v.Value).Int64())
	}
}

func ticks(v gosnmp.SnmpPDU) string {
	hundredths := int64(toFloat(v))
	d := time.Duration(hundredths) * 10 * time.Millisecond
	return d.Round(time.Second).String()
}

func lastElem(oid string) string {
	i := strings.LastIndexByte(oid, '.')
	if i < 0 {
		return ""
	}
	return oid[i+1:]
}
