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
