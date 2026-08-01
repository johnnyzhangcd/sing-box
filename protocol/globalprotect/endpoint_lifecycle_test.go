//go:build with_globalprotect && with_gvisor

package globalprotect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type globalProtectTestOutboundManager struct {
	adapter.OutboundManager
}

func TestEndpointStartupDoesNotWaitForUnavailableGateway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	created, err := NewEndpoint(ctx, nil, log.NewNOPFactory().NewLogger("globalprotect-test"), "gp-test", option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server: "127.0.0.1:1",
		},
		Username: "test-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := created.(*Endpoint)
	defer func() {
		if closeErr := endpoint.Close(); closeErr != nil && !strings.Contains(closeErr.Error(), "operation was canceled") {
			t.Errorf("close endpoint: %v", closeErr)
		}
	}()

	assertStartReturnsPromptly(t, endpoint, adapter.StartStateStart)
	assertStartReturnsPromptly(t, endpoint, adapter.StartStatePostStart)

	_, err = endpoint.DialContext(context.Background(), "tcp", M.ParseSocksaddr("192.0.2.1:443"))
	if err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("expected an explicit not-ready error, got %v", err)
	}
}

func TestEndpointWaitForReadyBlocksStartupUntilContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var options option.GlobalProtectEndpointOptions
	if err := json.Unmarshal([]byte(`{"server":"127.0.0.1:1","username":"test-user","wait_for_ready":true}`), &options); err != nil {
		t.Fatal(err)
	}
	created, err := NewEndpoint(ctx, nil, log.NewNOPFactory().NewLogger("globalprotect-wait-test"), "gp-test", options)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := created.(*Endpoint)
	defer endpoint.Close()

	started := make(chan error, 1)
	go func() {
		started <- endpoint.Start(adapter.StartStateStart)
	}()

	select {
	case err = <-started:
		t.Fatalf("wait-for-ready startup returned before the gateway became ready: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case err = <-started:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wait-for-ready startup returned %v after cancellation, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait-for-ready startup did not stop after context cancellation")
	}
}

func TestEndpointWaitForReadyDialHonorsContext(t *testing.T) {
	endpointContext, cancelEndpoint := context.WithCancel(context.Background())
	defer cancelEndpoint()

	var options option.GlobalProtectEndpointOptions
	if err := json.Unmarshal([]byte(`{"server":"127.0.0.1:1","username":"test-user","wait_for_ready":true}`), &options); err != nil {
		t.Fatal(err)
	}
	created, err := NewEndpoint(endpointContext, nil, log.NewNOPFactory().NewLogger("globalprotect-wait-dial-test"), "gp-test", options)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := created.(*Endpoint)
	defer endpoint.Close()

	started := make(chan error, 1)
	go func() {
		started <- endpoint.Start(adapter.StartStateStart)
	}()

	dialContext, cancelDial := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelDial()
	startTime := time.Now()
	_, err = endpoint.DialContext(dialContext, "tcp", M.ParseSocksaddr("192.0.2.1:443"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait-for-ready dial returned %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(startTime); elapsed < 80*time.Millisecond {
		t.Fatalf("wait-for-ready dial returned too early after %v", elapsed)
	}

	cancelEndpoint()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("wait-for-ready startup did not stop after endpoint cancellation")
	}
}

func TestEndpointDeclaresDetourDependency(t *testing.T) {
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &globalProtectTestOutboundManager{})
	created, err := NewEndpoint(ctx, nil, log.NewNOPFactory().NewLogger("globalprotect-test"), "gp-test", option.GlobalProtectEndpointOptions{
		DialerOptions: option.DialerOptions{Detour: "upstream"},
		ServerOptions: option.ServerOptions{Server: "192.0.2.1"},
		Username:      "test-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := created.(*Endpoint)
	defer endpoint.Close()
	dependencies := endpoint.Dependencies()
	if len(dependencies) != 1 || dependencies[0] != "upstream" {
		t.Fatalf("unexpected detour dependencies: %#v", dependencies)
	}
}

func TestEndpointCloseInterruptsStalledControlRead(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	var startedOnce sync.Once
	var releaseOnce sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		startedOnce.Do(func() { close(requestStarted) })
		<-releaseResponse
		_, _ = writer.Write([]byte(`<prelogin-response><status>Success</status></prelogin-response>`))
	}))
	defer func() {
		releaseOnce.Do(func() { close(releaseResponse) })
		server.Close()
	}()

	publicKeyHash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	created, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().NewLogger("globalprotect-close-test"), "gp-test", option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: server.URL},
		Username:      "test-user",
		ServerCert:    "sha256:" + hex.EncodeToString(publicKeyHash[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := created.(*Endpoint)
	if err = endpoint.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("control request did not reach stalled server")
	}

	closed := make(chan error, 1)
	go func() { closed <- endpoint.Close() }()
	select {
	case err = <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		releaseOnce.Do(func() { close(releaseResponse) })
		t.Fatal("Close did not interrupt the stalled control response")
	}
}

func TestEndpointStopsAfterPermanentAuthenticationFailure(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		_, _ = writer.Write([]byte(`<prelogin-response><status>Error</status><msg>Invalid username or password</msg></prelogin-response>`))
	}))
	defer server.Close()

	publicKeyHash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	created, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().NewLogger("globalprotect-auth-test"), "gp-test", option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: server.URL},
		Username:      "test-user",
		ServerCert:    "sha256:" + hex.EncodeToString(publicKeyHash[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := created.(*Endpoint)
	defer endpoint.Close()
	if err = endpoint.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	select {
	case <-endpoint.loopDone:
	case <-time.After(time.Second):
		t.Fatal("permanent authentication failure remained in the retry loop")
	}
	if requestCount := requests.Load(); requestCount != 1 {
		t.Fatalf("permanent authentication failure sent %d requests, want 1", requestCount)
	}
}

func TestEndpointStopsAfterPermanentPortalLoginFailure(t *testing.T) {
	var loginRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/global-protect/prelogin.esp":
			_, _ = writer.Write([]byte(`<prelogin-response><status>Success</status></prelogin-response>`))
		case "/global-protect/getconfig.esp":
			loginRequests.Add(1)
			_, _ = writer.Write([]byte(`<response status="error"><error>Invalid username or password</error></response>`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	publicKeyHash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	created, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().NewLogger("globalprotect-portal-auth-test"), "gp-test", option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: server.URL},
		Username:      "test-user",
		Password:      "invalid-password",
		ServerCert:    "sha256:" + hex.EncodeToString(publicKeyHash[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := created.(*Endpoint)
	defer endpoint.Close()
	if err = endpoint.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	select {
	case <-endpoint.loopDone:
	case <-time.After(time.Second):
		t.Fatal("permanent portal login failure remained in the retry loop")
	}
	if requestCount := loginRequests.Load(); requestCount != 1 {
		t.Fatalf("permanent portal login failure sent %d login requests, want 1", requestCount)
	}
}

func TestEndpointStopsAfterPortalReturnsNoGateways(t *testing.T) {
	var configRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/global-protect/prelogin.esp":
			_, _ = writer.Write([]byte(`<prelogin-response><status>Success</status></prelogin-response>`))
		case "/global-protect/getconfig.esp":
			configRequests.Add(1)
			_, _ = writer.Write([]byte(`<policy><gateways><external><list/></external></gateways></policy>`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	publicKeyHash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	created, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().NewLogger("globalprotect-empty-policy-test"), "gp-test", option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: server.URL},
		Username:      "test-user",
		Password:      "test-password",
		ServerCert:    "sha256:" + hex.EncodeToString(publicKeyHash[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := created.(*Endpoint)
	defer endpoint.Close()
	if err = endpoint.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	select {
	case <-endpoint.loopDone:
	case <-time.After(time.Second):
		t.Fatal("empty gateway policy remained in the retry loop")
	}
	if requestCount := configRequests.Load(); requestCount != 1 {
		t.Fatalf("empty gateway policy sent %d config requests, want 1", requestCount)
	}
}

func assertStartReturnsPromptly(t *testing.T, endpoint *Endpoint, stage adapter.StartStage) {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		result <- endpoint.Start(stage)
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("start at %s: %v", stage, err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("start at %s blocked on the unavailable gateway", stage)
	}
}
