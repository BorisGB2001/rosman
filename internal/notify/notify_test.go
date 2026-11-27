package notify

import (
	"reflect"
	"testing"
)

func TestParseChats(t *testing.T) {
	got, bad := ParseChats(" -1001234567890, 42;@ops_team\n42 ")
	if bad != "" || !reflect.DeepEqual(got, []string{"-1001234567890", "42", "@ops_team"}) {
		t.Fatalf("got %v bad %q", got, bad)
	}
	if _, bad := ParseChats("123, abc"); bad != "abc" {
		t.Fatalf("invalid token not reported: %q", bad)
	}
	if got, bad := ParseChats(""); bad != "" || len(got) != 0 {
		t.Fatalf("empty input: %v %q", got, bad)
	}
}
