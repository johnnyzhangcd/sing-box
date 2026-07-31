//go:build with_globalprotect

package globalprotect

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

func TestPFSCipherSuitesRequireEphemeralKeyExchange(t *testing.T) {
	knownSuites := make(map[uint16]string)
	for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		knownSuites[suite.ID] = suite.Name
	}
	suites := pfsCipherSuites(true)
	if len(suites) == 0 {
		t.Fatal("PFS cipher suite list is empty")
	}
	for _, suiteID := range suites {
		name := knownSuites[suiteID]
		if !strings.Contains(name, "_ECDHE_") {
			t.Fatalf("non-PFS TLS 1.2 cipher suite selected: %s", name)
		}
	}
}

func TestAllowInsecureCryptoEnablesLegacySuites(t *testing.T) {
	config, err := buildTLSConfig(option.GlobalProtectEndpointOptions{
		NoSystemTrust:       true,
		AllowInsecureCrypto: true,
	}, "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS10 {
		t.Fatalf("unexpected minimum TLS version: %x", config.MinVersion)
	}
	enabled := make(map[uint16]struct{}, len(config.CipherSuites))
	for _, suiteID := range config.CipherSuites {
		enabled[suiteID] = struct{}{}
	}
	legacySuites := tls.InsecureCipherSuites()
	if len(legacySuites) == 0 {
		t.Fatal("Go runtime exposes no legacy cipher suites")
	}
	if _, exists := enabled[legacySuites[0].ID]; !exists {
		t.Fatal("allow_insecure_crypto did not enable legacy cipher suites")
	}
}

func TestVerifyPinnedCertificateMatchesOpenConnectFormats(t *testing.T) {
	certificate := &x509.Certificate{
		Raw:                     []byte("certificate-der"),
		RawSubjectPublicKeyInfo: []byte("subject-public-key-info-der"),
	}
	publicKeySHA1 := sha1.Sum(certificate.RawSubjectPublicKeyInfo)
	publicKeySHA256 := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	certificateSHA1 := sha1.Sum(certificate.Raw)

	pins := map[string]string{
		"sha1":                    "sha1:" + hex.EncodeToString(publicKeySHA1[:]),
		"sha256":                  "sha256:" + hex.EncodeToString(publicKeySHA256[:]),
		"pin-sha256":              "pin-sha256:" + base64.StdEncoding.EncodeToString(publicKeySHA256[:]),
		"partial sha256":          "sha256:" + hex.EncodeToString(publicKeySHA256[:])[:8],
		"partial pin-sha256":      "pin-sha256:" + base64.StdEncoding.EncodeToString(publicKeySHA256[:])[:8],
		"legacy certificate sha1": hex.EncodeToString(certificateSHA1[:]),
	}
	for name, pin := range pins {
		t.Run(name, func(t *testing.T) {
			if err := verifyPinnedCertificate(certificate, pin); err != nil {
				t.Fatal(err)
			}
		})
	}

	wrongCertificateHash := sha256.Sum256(certificate.Raw)
	if err := verifyPinnedCertificate(certificate, "sha256:"+hex.EncodeToString(wrongCertificateHash[:])); err == nil {
		t.Fatal("accepted certificate hash where OpenConnect requires a public-key hash")
	}
	if err := verifyPinnedCertificate(certificate, "sha256:abc"); err == nil {
		t.Fatal("accepted fingerprint shorter than OpenConnect minimum")
	}
}

func TestBuildLoginBodyIncludesServerIdentity(t *testing.T) {
	body := buildLoginBody("alice", "secret", nil, "vpn.example.com", "host-01", "mac-intel", true, "")
	values, err := url.ParseQuery(body)
	if err != nil {
		t.Fatal(err)
	}
	if got := values.Get("server"); got != "vpn.example.com" {
		t.Fatalf("unexpected server identity: %q", got)
	}
	if got := values.Get("computer"); got != "host-01" {
		t.Fatalf("unexpected computer identity: %q", got)
	}
}

func TestBuildGetConfigBodyMatchesOpenConnect(t *testing.T) {
	body := buildGetConfigBody("authcookie=secret&user=alice&computer=host-01", "", "mac-intel", true)
	values, err := url.ParseQuery(body)
	if err != nil {
		t.Fatal(err)
	}
	if got := values.Get("app-version"); got != "6.3.0-33" {
		t.Fatalf("unexpected default app version: %q", got)
	}
	if _, exists := values["server"]; exists {
		t.Fatal("getconfig must not add a server field")
	}
	if got := values["computer"]; len(got) != 1 || got[0] != "host-01" {
		t.Fatalf("computer cookie was duplicated: %#v", got)
	}
}

func TestBuildPreloginQueryUsesClientOSName(t *testing.T) {
	query := buildPreloginQuery("mac-intel")
	if got := query.Get("clientos"); got != "Mac" {
		t.Fatalf("unexpected prelogin clientos: %q", got)
	}
	if got := query.Get("clientVer"); got != gpstClientVersion {
		t.Fatalf("unexpected prelogin client version: %q", got)
	}
}

func TestBuildPreloginBody(t *testing.T) {
	if got := buildPreloginBody(); got != "cas-support=yes" {
		t.Fatalf("unexpected prelogin body: %q", got)
	}
}

func TestGPSTClientOS(t *testing.T) {
	tests := map[string]string{
		"mac-intel": "Mac",
		"apple-ios": "iOS",
		"linux-64":  "Linux",
		"android":   "Android",
		"win":       "Windows",
	}
	for reported, want := range tests {
		if got := gpstClientOS(reported); got != want {
			t.Errorf("gpstClientOS(%q) = %q, want %q", reported, got, want)
		}
	}
}

func TestParseLogoutXML(t *testing.T) {
	if err := parseLogoutXML([]byte(`<response status="success"/>`)); err != nil {
		t.Fatal(err)
	}
	if err := parseLogoutXML([]byte(`<response status="error"><error>Invalid cookie</error></response>`)); err == nil {
		t.Fatal("expected logout error")
	}
}

func TestParsePreloginXMLPortalUnavailable(t *testing.T) {
	_, err := parsePreloginXML([]byte(`<prelogin-response><status>Error</status><msg>GlobalProtect portal does not exist</msg></prelogin-response>`))
	if !errors.Is(err, errPortalUnavailable) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePreloginXML(t *testing.T) {
	form, err := parsePreloginXML([]byte(`
<prelogin-response>
  <authentication-message>Sign in</authentication-message>
  <username-label>User name</username-label>
  <password-label>Password</password-label>
</prelogin-response>`))
	if err != nil {
		t.Fatal(err)
	}
	if form.Prompt != "Sign in" {
		t.Fatalf("unexpected prompt: %q", form.Prompt)
	}
	if form.UsernameLabel != "User name" {
		t.Fatalf("unexpected username label: %q", form.UsernameLabel)
	}
	if form.PasswordLabel != "Password" {
		t.Fatalf("unexpected password label: %q", form.PasswordLabel)
	}
}

func TestParsePreloginXMLDetectsSAML(t *testing.T) {
	form, err := parsePreloginXML([]byte(`
<prelogin-response>
  <saml-auth-method>REDIRECT</saml-auth-method>
  <saml-request>https://sso.example.com/saml</saml-request>
  <authentication-message>Browser login required</authentication-message>
</prelogin-response>`))
	if err != nil {
		t.Fatal(err)
	}
	if form.SAMLMethod != "REDIRECT" {
		t.Fatalf("unexpected saml method: %q", form.SAMLMethod)
	}
	if form.SAMLRequest != "https://sso.example.com/saml" {
		t.Fatalf("unexpected saml request: %q", form.SAMLRequest)
	}
	if !strings.Contains(form.Prompt, "Browser login") {
		t.Fatalf("unexpected prompt: %q", form.Prompt)
	}
}

func TestParseLoginXML(t *testing.T) {
	cookie, err := parseLoginXML([]byte(`
<jnlp>
  <application-desc>
    <argument></argument>
    <argument>authcookie-value</argument>
    <argument>persistent-cookie-value</argument>
    <argument>portal.example.com</argument>
    <argument>alice</argument>
    <argument>LDAP</argument>
    <argument>vsys1</argument>
    <argument>corp.example.com</argument>
    <argument></argument>
    <argument></argument>
    <argument></argument>
    <argument></argument>
    <argument>tunnel</argument>
    <argument>30</argument>
    <argument>4100</argument>
    <argument>10.77.0.20</argument>
    <argument></argument>
    <argument></argument>
    <argument>2001:db8::20</argument>
    <argument>4</argument>
    <argument>unknown</argument>
  </application-desc>
</jnlp>`), "host-01")
	if err != nil {
		t.Fatal(err)
	}
	wantParts := []string{
		"authcookie=authcookie-value",
		"portal=portal.example.com",
		"user=alice",
		"domain=corp.example.com",
		"preferred-ip=10.77.0.20",
		"preferred-ipv6=2001%3Adb8%3A%3A20",
		"computer=host-01",
	}
	for _, want := range wantParts {
		if !strings.Contains(cookie, want) {
			t.Fatalf("cookie %q does not contain %q", cookie, want)
		}
	}
}

func TestParsePortalXML(t *testing.T) {
	cfg, err := parsePortalXML([]byte(`
<policy>
  <version>6.3.1-456</version>
  <hip-collection>
    <hip-report-interval>3600</hip-report-interval>
  </hip-collection>
  <gateways>
    <external>
      <list>
        <entry name="gw-a.example.com">
          <description>Primary</description>
        </entry>
        <entry name="gw-b.example.com">
          <description>Secondary</description>
        </entry>
      </list>
    </external>
  </gateways>
  <portal-name>portal.example.com</portal-name>
  <portal-userauthcookie>cookie-a</portal-userauthcookie>
  <portal-prelogonuserauthcookie>cookie-b</portal-prelogonuserauthcookie>
</policy>`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != "6.3.1-456" {
		t.Fatalf("unexpected version: %q", cfg.Version)
	}
	if cfg.PortalName != "portal.example.com" {
		t.Fatalf("unexpected portal name: %q", cfg.PortalName)
	}
	if cfg.PortalUserAuthCookie != "cookie-a" {
		t.Fatalf("unexpected portal cookie: %q", cfg.PortalUserAuthCookie)
	}
	if cfg.PortalPrelogonUserAuthCookie != "cookie-b" {
		t.Fatalf("unexpected prelogon cookie: %q", cfg.PortalPrelogonUserAuthCookie)
	}
	if len(cfg.Gateways) != 2 {
		t.Fatalf("unexpected gateway count: %d", len(cfg.Gateways))
	}
	if cfg.Gateways[0].Name != "gw-a.example.com" || cfg.Gateways[0].Description != "Primary" {
		t.Fatalf("unexpected first gateway: %#v", cfg.Gateways[0])
	}
}

func TestParseTunnelXML(t *testing.T) {
	info, tunnelURL, err := parseTunnelXML([]byte(`
<response status="success">
  <ip-address>10.77.0.20</ip-address>
  <netmask>255.255.255.0</netmask>
  <ip-address-v6>2001:db8::20</ip-address-v6>
  <netmask-v6>64</netmask-v6>
  <mtu>1420</mtu>
  <ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>
</response>`), false)
	if err != nil {
		t.Fatal(err)
	}
	if info.Addr != "10.77.0.20" {
		t.Fatalf("unexpected ipv4 addr: %q", info.Addr)
	}
	if info.Netmask != "255.255.255.0" {
		t.Fatalf("unexpected ipv4 mask: %q", info.Netmask)
	}
	if info.Addr6 != "2001:db8::20" {
		t.Fatalf("unexpected ipv6 addr: %q", info.Addr6)
	}
	if info.Netmask6 != "64" {
		t.Fatalf("unexpected ipv6 mask: %q", info.Netmask6)
	}
	if info.MTU != 1420 {
		t.Fatalf("unexpected mtu: %d", info.MTU)
	}
	if tunnelURL != "/ssl-tunnel-connect.sslvpn" {
		t.Fatalf("unexpected tunnel url: %q", tunnelURL)
	}
}

func TestLogicalServerURLUsesSNIForConfiguredIP(t *testing.T) {
	base := mustURL(t, "https://192.0.2.10:1235")
	got := logicalServerURL(base, "vpn.example.com")
	if got.String() != "https://vpn.example.com:1235" {
		t.Fatalf("unexpected logical URL: %s", got)
	}
	if base.String() != "https://192.0.2.10:1235" {
		t.Fatalf("input URL was mutated: %s", base)
	}
}

func TestPinnedControlAddressUsesConfiguredIPForSNI(t *testing.T) {
	options := option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     "192.0.2.10",
			ServerPort: 1235,
		},
		SNI: "vpn.example.com",
	}
	got, ok := pinnedControlAddress(options, "vpn.example.com:1235")
	if !ok || got != "192.0.2.10:1235" {
		t.Fatalf("unexpected pinned address: %q, %v", got, ok)
	}
	if _, ok = pinnedControlAddress(options, "other.example.com:1235"); ok {
		t.Fatal("unexpected pin for unrelated host")
	}
}

func TestResolveDialTargetUsesDNSRouter(t *testing.T) {
	router := &stubDNSRouter{
		addresses: []netip.Addr{
			netip.MustParseAddr("203.0.113.10"),
			netip.MustParseAddr("2001:db8::10"),
		},
	}

	destination, err := resolveDialTarget(context.Background(), "tcp4", "portal.example.com:1235", router)
	if err != nil {
		t.Fatal(err)
	}
	if got := destination.Addr.String(); got != "203.0.113.10" {
		t.Fatalf("unexpected address: %s", got)
	}
	if destination.Port != 1235 {
		t.Fatalf("unexpected port: %d", destination.Port)
	}
	if router.calls != 1 {
		t.Fatalf("unexpected lookup calls: %d", router.calls)
	}
}

type stubDNSRouter struct {
	adapter.DNSRouter
	addresses []netip.Addr
	calls     int
}

func (s *stubDNSRouter) Start(adapter.StartStage) error { return nil }

func (s *stubDNSRouter) Close() error { return nil }

func (s *stubDNSRouter) Lookup(context.Context, string, adapter.DNSQueryOptions) ([]netip.Addr, error) {
	s.calls++
	return s.addresses, nil
}

func (s *stubDNSRouter) Exchange(context.Context, *dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error) {
	return nil, nil
}

func (s *stubDNSRouter) ClearCache() {}

func (s *stubDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}

func (s *stubDNSRouter) ResetNetwork() {}
