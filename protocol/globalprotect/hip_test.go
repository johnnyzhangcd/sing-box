//go:build with_globalprotect

package globalprotect

import (
	"net/netip"
	"net/url"
	"testing"
)

func TestBuildHIPCheckBodyMatchesOpenConnect(t *testing.T) {
	cookie := "authcookie=secret&portal=p&user=u&domain=d&computer=host&preferred-ip=10.0.0.1"
	body := buildHIPCheckBody(cookie, []netip.Prefix{
		netip.MustParsePrefix("10.10.0.34/32"),
		netip.MustParsePrefix("2001:db8::34/128"),
	})
	values, err := url.ParseQuery(body)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"client-role":  "global-protect-full",
		"authcookie":   "secret",
		"portal":       "p",
		"user":         "u",
		"domain":       "d",
		"computer":     "host",
		"preferred-ip": "10.0.0.1",
		"client-ip":    "10.10.0.34",
		"client-ipv6":  "2001:db8::34",
		"md5":          "42d3ecfacd319e15179c75737a1fce6f",
	}
	for key, expected := range want {
		if actual := values.Get(key); actual != expected {
			t.Fatalf("%s: expected %q, got %q", key, expected, actual)
		}
	}
}

func TestParseHIPCheckXML(t *testing.T) {
	needed, err := parseHIPCheckXML([]byte(`<response status="success"><hip-report-needed>yes</hip-report-needed></response>`))
	if err != nil {
		t.Fatal(err)
	}
	if !needed {
		t.Fatal("expected HIP report to be needed")
	}

	needed, err = parseHIPCheckXML([]byte(`<response status="success"><hip-report-needed>no</hip-report-needed></response>`))
	if err != nil {
		t.Fatal(err)
	}
	if needed {
		t.Fatal("expected HIP report not to be needed")
	}
}

func TestParseHIPSubmitXMLRejectsFailureStatus(t *testing.T) {
	err := parseHIPSubmitXML([]byte(`<response status="failure"><error>HIP policy rejected</error></response>`))
	if err == nil {
		t.Fatal("accepted failed HIP submission")
	}
}
