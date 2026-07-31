package constant

import "testing"

func TestProxyDisplayNameGlobalProtect(t *testing.T) {
	if got := ProxyDisplayName(TypeGlobalProtect); got != "GlobalProtect" {
		t.Fatalf("unexpected display name: %q", got)
	}
}
