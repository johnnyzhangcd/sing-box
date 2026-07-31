//go:build with_globalprotect

package globalprotect

import "testing"

func TestBuildServerURL(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		serverPort uint16
		want       string
	}{
		{
			name:   "host and port",
			server: "vpn.example.com:1235",
			want:   "https://vpn.example.com:1235",
		},
		{
			name:   "host only uses no explicit port",
			server: "vpn.example.com",
			want:   "https://vpn.example.com",
		},
		{
			name:       "host only with port",
			server:     "vpn.example.com",
			serverPort: 443,
			want:       "https://vpn.example.com:443",
		},
		{
			name:   "ipv6 host and port",
			server: "[2001:db8::1]:1235",
			want:   "https://[2001:db8::1]:1235",
		},
		{
			name:   "scheme passthrough",
			server: "https://vpn.example.com:443/path",
			want:   "https://vpn.example.com:443/path",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildServerURL(tc.server, tc.serverPort)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("unexpected url: %q", got)
			}
		})
	}
}

func TestBuildTunnelConfig(t *testing.T) {
	t.Run("ipv4 and ipv6", func(t *testing.T) {
		config, err := buildTunnelConfig(openconnectIPInfo{
			Addr:     "10.77.0.10",
			Netmask:  "255.255.255.0",
			Addr6:    "2001:db8::10",
			Netmask6: "2001:db8::/64",
			MTU:      1420,
		})
		if err != nil {
			t.Fatal(err)
		}
		if config.MTU != 1420 {
			t.Fatalf("unexpected mtu: %d", config.MTU)
		}
		if len(config.Prefixes) != 2 {
			t.Fatalf("unexpected prefix count: %d", len(config.Prefixes))
		}
		if got := config.Prefixes[0].String(); got != "10.77.0.10/24" {
			t.Fatalf("unexpected ipv4 prefix: %s", got)
		}
		if got := config.Prefixes[1].String(); got != "2001:db8::10/64" {
			t.Fatalf("unexpected ipv6 prefix: %s", got)
		}
	})

	t.Run("default mtu", func(t *testing.T) {
		config, err := buildTunnelConfig(openconnectIPInfo{
			Addr6:    "2001:db8::10",
			Netmask6: "2001:db8::10/128",
		})
		if err != nil {
			t.Fatal(err)
		}
		if config.MTU != 1400 {
			t.Fatalf("unexpected default mtu: %d", config.MTU)
		}
		if len(config.Prefixes) != 1 || config.Prefixes[0].String() != "2001:db8::10/128" {
			t.Fatalf("unexpected prefixes: %#v", config.Prefixes)
		}
	})
}
