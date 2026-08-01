//go:build with_globalprotect

package globalprotect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestHIPRequiredSubmitsMatchingReport(t *testing.T) {
	var reportRequests atomic.Int32
	var checkedMD5 string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		switch request.URL.Path {
		case "/ssl-vpn/hipreportcheck.esp":
			checkedMD5 = request.Form.Get("md5")
			_, _ = writer.Write([]byte(`<response status="success"><hip-report-needed>yes</hip-report-needed></response>`))
		case "/ssl-vpn/hipreport.esp":
			reportRequests.Add(1)
			report := request.Form.Get("report")
			if checkedMD5 == "" || !strings.Contains(report, "<md5-sum>"+checkedMD5+"</md5-sum>") {
				http.Error(writer, "HIP report MD5 does not match check", http.StatusBadRequest)
				return
			}
			if !strings.Contains(report, "<host-name>host-01</host-name>") {
				http.Error(writer, "HIP report omitted host identity", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write([]byte(`<response status="success"/>`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	publicKeyHash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	client, err := newPortalClient(context.Background(), option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "gateway.example.com"},
		ServerCert:    "sha256:" + hex.EncodeToString(publicKeyHash[:]),
		LocalHostname: "host-01",
		ReportedOS:    "linux-64",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.closeControl()
	serverAddress := server.Listener.Addr().String()
	client.dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}

	gatewayURL := &url.URL{Scheme: "https", Host: "gateway.example.com"}
	config := tunnelConfig{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.77.0.20/24")}}
	cookie := "authcookie=secret&portal=portal.example.com&user=alice&domain=corp&computer=host-01"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	needed, err := client.checkHIP(ctx, gatewayURL, cookie, config, defaultAppVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !needed {
		t.Fatal("gateway required HIP but client reported otherwise")
	}
	if reportRequests.Load() != 1 {
		t.Fatalf("expected one HIP report submission, got %d", reportRequests.Load())
	}
}

func TestPeriodicHIPRecheckUsesActiveSession(t *testing.T) {
	var checkRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/ssl-vpn/hipreportcheck.esp" {
			http.NotFound(writer, request)
			return
		}
		checkRequests.Add(1)
		_, _ = writer.Write([]byte(`<response status="success"><hip-report-needed>no</hip-report-needed></response>`))
	}))
	defer server.Close()

	publicKeyHash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	client, err := newPortalClient(context.Background(), option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "gateway.example.com"},
		ServerCert:    "sha256:" + hex.EncodeToString(publicKeyHash[:]),
		LocalHostname: "host-01",
		ReportedOS:    "linux-64",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.closeControl()
	serverAddress := server.Listener.Addr().String()
	client.dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}
	state := &sessionState{
		GatewayURL:       &url.URL{Scheme: "https", Host: "gateway.example.com"},
		Cookie:           "authcookie=secret&portal=portal.example.com&user=alice&domain=corp&computer=host-01",
		TunnelConfig:     tunnelConfig{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.77.0.20/24")}},
		AppVersion:       defaultAppVersion,
		HIPCheckInterval: time.Hour,
	}
	client.rememberSession(state)
	<-client.sessionChanges()

	loopContext, cancelLoop := context.WithCancel(context.Background())
	endpoint := &Endpoint{
		loopContext: loopContext,
		logger:      log.NewNOPFactory().NewLogger("globalprotect-hip-test"),
		client:      client,
	}
	done := make(chan struct{})
	go func() {
		endpoint.periodicHIPLoop(time.Second)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	updatedState := *state
	updatedState.HIPCheckInterval = 20 * time.Millisecond
	client.rememberSession(&updatedState)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for checkRequests.Load() < 2 {
		select {
		case <-time.After(5 * time.Millisecond):
		case <-deadline.C:
			cancelLoop()
			t.Fatalf("periodic HIP check ran %d times, want at least 2", checkRequests.Load())
		}
	}
	cancelLoop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("periodic HIP loop did not stop after cancellation")
	}
}

func TestPeriodicHIPStopsAfterPermanentTLSFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`<response status="success"><hip-report-needed>no</hip-report-needed></response>`))
	}))
	defer server.Close()

	client, err := newPortalClient(context.Background(), option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: server.URL},
		ServerCert:    "sha256:0000",
		LocalHostname: "host-01",
	})
	if err != nil {
		t.Fatal(err)
	}
	var dialAttempts atomic.Int32
	originalDial := client.dialContext
	client.dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		dialAttempts.Add(1)
		return originalDial(ctx, network, address)
	}
	gatewayURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.rememberSession(&sessionState{
		GatewayURL:       gatewayURL,
		Cookie:           "authcookie=secret&user=alice&computer=host-01",
		TunnelConfig:     tunnelConfig{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.77.0.20/24")}},
		AppVersion:       defaultAppVersion,
		HIPCheckInterval: 20 * time.Millisecond,
	})
	<-client.sessionChanges()

	loopContext, cancelLoop := context.WithCancel(context.Background())
	defer cancelLoop()
	endpoint := &Endpoint{
		loopContext: loopContext,
		logger:      log.NewNOPFactory().NewLogger("globalprotect-hip-permanent-test"),
		client:      client,
	}
	done := make(chan struct{})
	go func() {
		endpoint.periodicHIPLoop(time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("periodic HIP loop retried a permanent TLS failure")
	}
	if attemptCount := dialAttempts.Load(); attemptCount != 1 {
		t.Fatalf("permanent HIP failure made %d dial attempts, want 1", attemptCount)
	}
}
