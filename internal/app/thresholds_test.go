package app

import (
	"testing"

	"rosman/internal/config"
	"rosman/internal/model"
	"rosman/internal/notify"
	"rosman/internal/ros"
	"rosman/internal/store"
)

func active(t *testing.T, st *store.Store, id int64, rule string) bool {
	t.Helper()
	s, _ := st.AlertState(id, rule)
	return s == "active"
}

func TestEvalThresholds(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateDevice(model.Device{Name: "dev1", IP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: st, Notify: notify.New("", "", ""), Cfg: config.Config{}}
	d, _ := st.Device(id)

	// No threshold set: nothing should fire even at 99% CPU.
	a.evalThresholds(d, ros.Health{CPU: 99})
	if active(t, st, id, "cpu_high") {
		t.Fatal("cpu alert raised with no threshold configured")
	}

	// Threshold exceeded -> alert raised.
	_ = st.SetSetting("alert_cpu", "80")
	a.evalThresholds(d, ros.Health{CPU: 90})
	if !active(t, st, id, "cpu_high") {
		t.Fatal("cpu alert not raised above threshold")
	}

	// Metric drops below -> alert cleared.
	a.evalThresholds(d, ros.Health{CPU: 50})
	if active(t, st, id, "cpu_high") {
		t.Fatal("cpu alert not cleared below threshold")
	}

	// Temperature and memory thresholds.
	_ = st.SetSetting("alert_temp", "60")
	_ = st.SetSetting("alert_mem", "90")
	a.evalThresholds(d, ros.Health{Temp: 70, TotalMem: 100, FreeMem: 5})
	if !active(t, st, id, "temp_high") {
		t.Fatal("temp alert not raised")
	}
	if !active(t, st, id, "mem_high") {
		t.Fatal("mem alert not raised (used 95%)")
	}

	// Disabling a threshold (0) clears its alert.
	_ = st.SetSetting("alert_temp", "0")
	a.evalThresholds(d, ros.Health{Temp: 70, TotalMem: 100, FreeMem: 5})
	if active(t, st, id, "temp_high") {
		t.Fatal("temp alert not cleared after disabling threshold")
	}
}

// A device's own temperature threshold wins over the global one.
func TestDeviceTempThreshold(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateDevice(model.Device{Name: "dev1", IP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: st, Notify: notify.New("", "", ""), Cfg: config.Config{}}
	_ = st.SetSetting("alert_temp", "80")
	_ = st.SetDeviceAlertPrefs(id, 55, "-100123,@ops")
	d, _ := st.Device(id)
	if d.TempAlertC != 55 || d.TGChats != "-100123,@ops" {
		t.Fatalf("prefs not stored: %d %q", d.TempAlertC, d.TGChats)
	}
	a.evalThresholds(d, ros.Health{Temp: 60})
	if !active(t, st, id, "temp_high") {
		t.Fatal("device threshold 55°C not applied at 60°C (global is 80)")
	}
	// Back to the global threshold: 60°C is under 80°C, the alert clears.
	_ = st.SetDeviceAlertPrefs(id, 0, "")
	d, _ = st.Device(id)
	a.evalThresholds(d, ros.Health{Temp: 60})
	if active(t, st, id, "temp_high") {
		t.Fatal("alert not cleared after returning to the global threshold")
	}
}
