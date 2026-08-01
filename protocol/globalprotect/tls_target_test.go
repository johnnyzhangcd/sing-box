//go:build with_globalprotect

package globalprotect

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestPortalClientUsesGatewayTLSIdentity(t *testing.T) {
	serverName := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`<response status="success"/>`))
	}))
	server.StartTLS()
	defer server.Close()
	server.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		select {
		case serverName <- hello.ServerName:
		default:
		}
		return nil, nil
	}

	publicKeyHash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	client, err := newPortalClient(context.Background(), option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "portal.example.com"},
		ServerCert:    "sha256:" + hex.EncodeToString(publicKeyHash[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.closeControl()
	serverAddress := server.Listener.Addr().String()
	client.dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}

	target := &url.URL{Scheme: "https", Host: "gateway.example.com", Path: "/ssl-vpn/hipreportcheck.esp"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = client.doRequest(ctx, http.MethodGet, target, "", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-serverName:
		if actual != "gateway.example.com" {
			t.Fatalf("gateway TLS handshake used %q as SNI", actual)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestPortalClientKeepsExplicitSNIForGateway(t *testing.T) {
	serverName := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`<response status="success"/>`))
	}))
	server.StartTLS()
	defer server.Close()
	server.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		select {
		case serverName <- hello.ServerName:
		default:
		}
		return nil, nil
	}

	publicKeyHash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	client, err := newPortalClient(context.Background(), option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "portal.example.com"},
		ServerCert:    "sha256:" + hex.EncodeToString(publicKeyHash[:]),
		SNI:           "fixed.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.closeControl()
	serverAddress := server.Listener.Addr().String()
	client.dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}

	target := &url.URL{Scheme: "https", Host: "gateway.example.com", Path: "/ssl-vpn/hipreportcheck.esp"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = client.doRequest(ctx, http.MethodGet, target, "", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-serverName:
		if actual != "fixed.example.com" {
			t.Fatalf("explicit SNI changed to %q for gateway", actual)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestPortalClientTreatsCertificateFailureAsPermanent(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := newPortalClient(context.Background(), option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: server.URL},
		ServerCert:    "sha256:0000",
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.doRequest(ctx, http.MethodGet, target, "", nil)
	if !isPermanentRetry(err) {
		t.Fatalf("certificate failure was treated as retryable: %v", err)
	}
}
