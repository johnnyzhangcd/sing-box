//go:build with_globalprotect

package globalprotect

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func TestNewTunnelDialerRefreshesSession(t *testing.T) {
	client := &stubTunnelSessionClient{
		sessions: []*sessionState{
			{
				GatewayURL: mustURL(t, "https://gw1.example.com"),
				Cookie:     "cookie-1",
				TunnelURL:  "/tunnel-1",
			},
		},
	}

	initial := &sessionState{
		GatewayURL: mustURL(t, "https://gw0.example.com"),
		Cookie:     "cookie-0",
		TunnelURL:  "/tunnel-0",
	}
	client.openErrors = []error{nil, errors.New("stale session"), nil}
	var refreshedCookie string
	dial := newTunnelDialer(client, initial, func(state *sessionState) error {
		refreshedCookie = state.Cookie
		return nil
	}, nil)

	firstConn, err := dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = firstConn.Close()

	secondConn, err := dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = secondConn.Close()

	client.mu.Lock()
	defer client.mu.Unlock()

	if client.obtainCalls != 1 {
		t.Fatalf("unexpected obtainSession calls: %d", client.obtainCalls)
	}
	if len(client.openCalls) != 3 {
		t.Fatalf("unexpected openTunnel calls: %d", len(client.openCalls))
	}
	if client.openCalls[0].cookie != "cookie-0" || client.openCalls[0].tunnelURL != "/tunnel-0" {
		t.Fatalf("unexpected first tunnel call: %#v", client.openCalls[0])
	}
	if client.openCalls[1].cookie != "cookie-0" || client.openCalls[1].tunnelURL != "/tunnel-0" {
		t.Fatalf("unexpected stale-session retry: %#v", client.openCalls[1])
	}
	if client.openCalls[2].cookie != "cookie-1" || client.openCalls[2].tunnelURL != "/tunnel-1" {
		t.Fatalf("unexpected refreshed tunnel call: %#v", client.openCalls[2])
	}
	if refreshedCookie != "cookie-1" {
		t.Fatalf("unexpected refreshed cookie: %q", refreshedCookie)
	}
}

func TestNewTunnelDialerDropsExpiredSessionBeforeNextAttempt(t *testing.T) {
	client := &expiringTunnelSessionClient{}
	initial := &sessionState{
		GatewayURL: mustURL(t, "https://stale.example.com"),
		Cookie:     "stale-cookie",
		TunnelURL:  "/stale-tunnel",
	}
	var refreshedCookie string
	dial := newTunnelDialer(client, initial, func(state *sessionState) error {
		refreshedCookie = state.Cookie
		return nil
	}, nil)

	firstConn, err := dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = firstConn.Close()

	expiredContext, cancelExpired := context.WithTimeout(context.Background(), 10*time.Millisecond)
	_, err = dial(expiredContext)
	cancelExpired()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected expired-session error: %v", err)
	}

	retryContext, cancelRetry := context.WithTimeout(context.Background(), time.Second)
	refreshedConn, err := dial(retryContext)
	cancelRetry()
	if err != nil {
		t.Fatal(err)
	}
	_ = refreshedConn.Close()
	if client.obtainCalls != 1 {
		t.Fatalf("unexpected authentication attempts: %d", client.obtainCalls)
	}
	if refreshedCookie != "fresh-cookie" {
		t.Fatalf("unexpected refreshed cookie: %q", refreshedCookie)
	}
}

type expiringTunnelSessionClient struct {
	mu                 sync.Mutex
	staleSessionOpened bool
	obtainCalls        int
}

func (c *expiringTunnelSessionClient) obtainSession(ctx context.Context, _ logger.ContextLogger) (*sessionState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.obtainCalls++
	c.mu.Unlock()
	return &sessionState{
		GatewayURL: mustURLValue("https://fresh.example.com"),
		Cookie:     "fresh-cookie",
		TunnelURL:  "/fresh-tunnel",
	}, nil
}

func (c *expiringTunnelSessionClient) openTunnel(ctx context.Context, _ *url.URL, cookie, _ string) (net.Conn, error) {
	c.mu.Lock()
	if cookie == "stale-cookie" && !c.staleSessionOpened {
		c.staleSessionOpened = true
		c.mu.Unlock()
		return closedPipe(), nil
	}
	c.mu.Unlock()
	if cookie == "stale-cookie" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return closedPipe(), nil
}

func closedPipe() net.Conn {
	local, remote := net.Pipe()
	_ = remote.Close()
	return local
}

func mustURLValue(raw string) *url.URL {
	parsed, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return parsed
}

type stubTunnelSessionClient struct {
	mu          sync.Mutex
	sessions    []*sessionState
	obtainCalls int
	openCalls   []stubTunnelOpenCall
	openErrors  []error
}

type stubTunnelOpenCall struct {
	gatewayURL string
	cookie     string
	tunnelURL  string
}

func (s *stubTunnelSessionClient) obtainSession(context.Context, logger.ContextLogger) (*sessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.obtainCalls++
	if len(s.sessions) == 0 {
		return nil, context.Canceled
	}
	state := s.sessions[0]
	s.sessions = s.sessions[1:]
	return state, nil
}

func (s *stubTunnelSessionClient) openTunnel(_ context.Context, gatewayURL *url.URL, cookie, tunnelURL string) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.openCalls = append(s.openCalls, stubTunnelOpenCall{
		gatewayURL: gatewayURL.String(),
		cookie:     cookie,
		tunnelURL:  tunnelURL,
	})
	if len(s.openErrors) > 0 {
		err := s.openErrors[0]
		s.openErrors = s.openErrors[1:]
		if err != nil {
			return nil, err
		}
	}
	local, remote := net.Pipe()
	_ = remote.Close()
	return local, nil
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
