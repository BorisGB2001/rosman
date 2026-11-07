package totp

import (
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	s := NewSecret()
	c := Now(s)
	if len(c) != 6 {
		t.Fatalf("code len %d", len(c))
	}
	if !Validate(s, c) {
		t.Fatalf("fresh code should validate")
	}
	if Validate(s, "12345") {
		t.Fatalf("short code validated")
	}
	if Validate(s, "abcdef") {
		t.Fatalf("non-numeric validated")
	}
}

func TestDriftWindow(t *testing.T) {
	s := NewSecret()
	// A code from one step earlier must still validate (±1 window).
	prev, err := codeAt(s, time.Now().Add(-period*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !Validate(s, prev) {
		t.Fatalf("previous-step code should validate within drift window")
	}
	// Two steps away must NOT validate.
	far, _ := codeAt(s, time.Now().Add(-3*period*time.Second))
	if far != Now(s) && Validate(s, far) {
		t.Fatalf("far code should not validate")
	}
}

func TestURI(t *testing.T) {
	u := URI("ROSMan", "admin", "ABC234")
	if u == "" || u[:16] != "otpauth://totp/R" {
		t.Fatalf("bad uri: %s", u)
	}
}
