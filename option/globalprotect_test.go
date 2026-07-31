package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"
)

func TestGlobalProtectEndpointOptionsJSON(t *testing.T) {
	var options GlobalProtectEndpointOptions
	if err := json.Unmarshal([]byte(`{"server":"vpn.example.com","server_port":1235,"username":"alice","password":"secret","reported_os":"mac-intel","bind_interface":"en7"}`), &options); err != nil {
		t.Fatal(err)
	}
	if options.Server != "vpn.example.com" {
		t.Fatalf("unexpected server: %q", options.Server)
	}
	if options.ServerPort != 1235 {
		t.Fatalf("unexpected server port: %d", options.ServerPort)
	}
	if options.Username != "alice" {
		t.Fatalf("unexpected username: %q", options.Username)
	}
	if options.Password != "secret" {
		t.Fatalf("unexpected password: %q", options.Password)
	}
	if options.ReportedOS != "mac-intel" {
		t.Fatalf("unexpected reported os: %q", options.ReportedOS)
	}
	if options.DialerOptions.BindInterface != "en7" {
		t.Fatalf("unexpected bind interface: %q", options.DialerOptions.BindInterface)
	}
}
