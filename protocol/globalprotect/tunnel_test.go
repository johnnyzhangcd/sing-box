//go:build with_globalprotect

package globalprotect

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func TestEncodeGPSTDataFrame(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x14}
	frame := encodeGPSTFrame(0x0800, payload, false)
	if len(frame) != 16+len(payload) {
		t.Fatalf("unexpected frame length: %d", len(frame))
	}
	wantPrefix := []byte{
		0x1a, 0x2b, 0x3c, 0x4d,
		0x08, 0x00,
		0x00, 0x04,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(frame[:16], wantPrefix) {
		t.Fatalf("unexpected header: %x", frame[:16])
	}
	if !bytes.Equal(frame[16:], payload) {
		t.Fatalf("unexpected payload: %x", frame[16:])
	}
}

func TestEncodeGPSTKeepaliveFrame(t *testing.T) {
	frame := encodeGPSTFrame(0, nil, true)
	want := []byte{
		0x1a, 0x2b, 0x3c, 0x4d,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(frame, want) {
		t.Fatalf("unexpected keepalive frame: %x", frame)
	}
}

func TestDecodeGPSTFrame(t *testing.T) {
	encoded := encodeGPSTFrame(0x86DD, []byte{0x60, 0x00, 0x00, 0x00}, false)
	ethertype, payload, keepalive, err := decodeGPSTFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if keepalive {
		t.Fatal("expected data frame")
	}
	if ethertype != 0x86DD {
		t.Fatalf("unexpected ethertype: %#x", ethertype)
	}
	if !bytes.Equal(payload, []byte{0x60, 0x00, 0x00, 0x00}) {
		t.Fatalf("unexpected payload: %x", payload)
	}
}

func TestWriteGPSTFrameHandlesShortWrites(t *testing.T) {
	conn := &shortWriteConn{}
	frame := encodeGPSTFrame(0x0800, []byte{0x45, 0, 0, 20}, false)
	if err := writeGPSTFrame(context.Background(), conn, frame); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(conn.Bytes(), frame) {
		t.Fatalf("short write truncated frame: got %d bytes, want %d", conn.Len(), len(frame))
	}
}

type shortWriteConn struct {
	bytes.Buffer
}

func (c *shortWriteConn) Write(p []byte) (int, error) {
	n := len(p) / 2
	if n == 0 {
		n = len(p)
	}
	return c.Buffer.Write(p[:n])
}

func (c *shortWriteConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *shortWriteConn) Close() error                     { return nil }
func (c *shortWriteConn) LocalAddr() net.Addr              { return stubAddr("local") }
func (c *shortWriteConn) RemoteAddr() net.Addr             { return stubAddr("remote") }
func (c *shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *shortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *shortWriteConn) SetWriteDeadline(time.Time) error { return nil }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }
func (a stubAddr) String() string  { return string(a) }

func TestTunnelPumpStopsWhenOutboundEnds(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	session := newTunnelSession(&stubTunnelEndpoint{}, nil, nil, time.Second, time.Second)
	done := make(chan error, 1)
	go func() {
		done <- session.pump(context.Background(), local)
	}()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("pump did not close idle reader after outbound ended")
	}
}

func TestTunnelSessionStopClosesConnection(t *testing.T) {
	localConn, remoteConn := net.Pipe()
	defer localConn.Close()
	defer remoteConn.Close()

	session := newTunnelSession(&stubTunnelEndpoint{}, func(context.Context) (net.Conn, error) {
		return localConn, nil
	}, nil, time.Second, time.Second)

	ready := session.start(context.Background())
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session did not become ready")
	}

	done := make(chan struct{})
	go func() {
		session.stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session stop timed out")
	}
}

func TestTunnelSessionReportsDisconnectedState(t *testing.T) {
	localConn, remoteConn := net.Pipe()
	defer remoteConn.Close()

	session := newTunnelSession(&blockingTunnelEndpoint{}, func(context.Context) (net.Conn, error) {
		return localConn, nil
	}, nil, time.Second, time.Second)
	ready := session.start(context.Background())
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("session did not become ready")
	}
	if !session.Ready() {
		t.Fatal("session did not publish connected state")
	}
	if err := remoteConn.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for session.Ready() {
		select {
		case <-time.After(5 * time.Millisecond):
		case <-deadline.C:
			t.Fatal("session remained ready after tunnel disconnect")
		}
	}
	session.stop()
}

func TestTunnelSessionWaitReadyHonorsContextDuringReconnect(t *testing.T) {
	firstLocal, firstRemote := net.Pipe()
	defer firstRemote.Close()
	secondLocal, secondRemote := net.Pipe()
	defer secondRemote.Close()

	allowReconnect := make(chan struct{})
	var attempts atomic.Int32
	session := newTunnelSession(&blockingTunnelEndpoint{}, func(ctx context.Context) (net.Conn, error) {
		if attempts.Add(1) == 1 {
			return firstLocal, nil
		}
		select {
		case <-allowReconnect:
			return secondLocal, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, nil, time.Second, time.Second)
	ready := session.start(context.Background())
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("session did not become ready")
	}

	if err := firstRemote.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for session.Ready() {
		select {
		case <-time.After(5 * time.Millisecond):
		case <-deadline.C:
			t.Fatal("session remained ready after tunnel disconnect")
		}
	}

	waitContext, cancelWait := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelWait()
	if err := session.WaitReady(waitContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait during reconnect returned %v, want context deadline exceeded", err)
	}

	close(allowReconnect)
	recoveredContext, cancelRecovered := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancelRecovered()
	if err := session.WaitReady(recoveredContext); err != nil {
		t.Fatalf("wait for recovered tunnel: %v", err)
	}
	if !session.Ready() {
		t.Fatal("session did not publish recovered state")
	}
	session.stop()
}

func TestTunnelSessionStopsAfterPermanentDialFailure(t *testing.T) {
	var attempts atomic.Int32
	session := newTunnelSession(&blockingTunnelEndpoint{}, func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		return nil, markPermanentRetry(errors.New("invalid credentials"))
	}, nil, time.Second, time.Second)
	ready := session.start(context.Background())
	select {
	case err := <-ready:
		if !isPermanentRetry(err) {
			t.Fatalf("unexpected ready error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("permanent dial failure remained in retry loop")
	}
	select {
	case <-session.done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop after permanent dial failure")
	}
	if attemptCount := attempts.Load(); attemptCount != 1 {
		t.Fatalf("permanent dial failure made %d attempts, want 1", attemptCount)
	}
}

func TestTunnelSessionStopBeforeStartReturns(t *testing.T) {
	session := newTunnelSession(&stubTunnelEndpoint{}, func(context.Context) (net.Conn, error) {
		return nil, context.Canceled
	}, nil, time.Second, time.Second)
	done := make(chan struct{})
	go func() {
		session.stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("session stop before start timed out")
	}
}

func TestNormalizedReconnectTimeout(t *testing.T) {
	if got := normalizedReconnectTimeout(0); got != defaultReconnectTimeout {
		t.Fatalf("unexpected default reconnect timeout: %s", got)
	}
	configured := 17 * time.Second
	if got := normalizedReconnectTimeout(configured); got != configured {
		t.Fatalf("unexpected configured reconnect timeout: %s", got)
	}
}

func TestTunnelSessionRecoversFromInitialDialFailure(t *testing.T) {
	localConn, remoteConn := net.Pipe()
	defer localConn.Close()
	defer remoteConn.Close()

	attempts := 0
	hadDeadline := false
	session := newTunnelSession(&stubTunnelEndpoint{}, func(ctx context.Context) (net.Conn, error) {
		attempts++
		_, hadDeadline = ctx.Deadline()
		if attempts == 1 {
			return nil, errors.New("temporary gateway failure")
		}
		return localConn, nil
	}, nil, time.Second, 50*time.Millisecond)

	ready := session.start(context.Background())
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session did not recover from initial dial failure")
	}
	if attempts < 2 {
		t.Fatalf("unexpected dial attempts: %d", attempts)
	}
	if !hadDeadline {
		t.Fatal("dial attempt has no reconnect deadline")
	}
	session.stop()
}

type stubTunnelEndpoint struct{}

func (s *stubTunnelEndpoint) ReadContext(context.Context) *stack.PacketBuffer {
	return nil
}

func (s *stubTunnelEndpoint) InjectInbound(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

type blockingTunnelEndpoint struct{}

func (s *blockingTunnelEndpoint) ReadContext(ctx context.Context) *stack.PacketBuffer {
	<-ctx.Done()
	return nil
}

func (s *blockingTunnelEndpoint) InjectInbound(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}
