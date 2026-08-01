package globalprotect

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	gpstMagic               = 0x1a2b3c4d
	defaultReconnectTimeout = 5 * time.Minute
	stableConnectionTime    = 30 * time.Second
)

type tunnelPacketEndpoint interface {
	ReadContext(ctx context.Context) *stack.PacketBuffer
	InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer)
}

type framePacket struct {
	ethertype uint16
	payload   []byte
}

type tunnelSession struct {
	endpoint         tunnelPacketEndpoint
	dial             func(context.Context) (net.Conn, error)
	logger           logger.ContextLogger
	keepalive        time.Duration
	reconnectTimeout time.Duration

	startOnce    sync.Once
	stateMu      sync.Mutex
	started      bool
	ready        chan error
	cancel       context.CancelFunc
	done         chan struct{}
	stateChanged chan struct{}
	terminalErr  error
	connMu       sync.Mutex
	conn         net.Conn
	closed       atomic.Bool
	connected    atomic.Bool
}

func normalizedReconnectTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return defaultReconnectTimeout
	}
	return timeout
}

func newTunnelSession(endpoint tunnelPacketEndpoint, dial func(context.Context) (net.Conn, error), log logger.ContextLogger, keepalive, reconnectTimeout time.Duration) *tunnelSession {
	if keepalive <= 0 {
		keepalive = 10 * time.Second
	}
	return &tunnelSession{
		endpoint:         endpoint,
		dial:             dial,
		logger:           log,
		keepalive:        keepalive,
		reconnectTimeout: normalizedReconnectTimeout(reconnectTimeout),
		ready:            make(chan error, 1),
		done:             make(chan struct{}),
		stateChanged:     make(chan struct{}),
	}
}

func (s *tunnelSession) start(ctx context.Context) <-chan error {
	s.startOnce.Do(func() {
		s.stateMu.Lock()
		defer s.stateMu.Unlock()
		if s.closed.Load() {
			s.sendReady(net.ErrClosed)
			return
		}
		runCtx, cancel := context.WithCancel(ctx)
		s.cancel = cancel
		s.started = true
		go s.run(runCtx)
	})
	return s.ready
}

func (s *tunnelSession) stop() {
	if s.closed.Swap(true) {
		return
	}
	s.publishState(false, net.ErrClosed)
	s.stateMu.Lock()
	if !s.started {
		close(s.done)
		s.stateMu.Unlock()
		return
	}
	cancel := s.cancel
	s.stateMu.Unlock()
	cancel()
	s.closeConn()
	<-s.done
}

func (s *tunnelSession) Ready() bool {
	return s.connected.Load()
}

func (s *tunnelSession) WaitReady(ctx context.Context) error {
	for {
		s.stateMu.Lock()
		connected := s.connected.Load()
		terminalErr := s.terminalErr
		stateChanged := s.stateChanged
		s.stateMu.Unlock()
		if connected {
			return nil
		}
		if terminalErr != nil {
			return terminalErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stateChanged:
		}
	}
}

func (s *tunnelSession) publishState(connected bool, terminalErr error) {
	s.stateMu.Lock()
	s.connected.Store(connected)
	if terminalErr != nil && s.terminalErr == nil {
		s.terminalErr = terminalErr
	}
	close(s.stateChanged)
	s.stateChanged = make(chan struct{})
	s.stateMu.Unlock()
}

func (s *tunnelSession) setConn(conn net.Conn) {
	s.connMu.Lock()
	s.conn = conn
	s.connMu.Unlock()
}

func (s *tunnelSession) clearConn(conn net.Conn) {
	s.connMu.Lock()
	if s.conn == conn {
		s.conn = nil
	}
	s.connMu.Unlock()
}

func (s *tunnelSession) closeConn() {
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (s *tunnelSession) run(ctx context.Context) {
	var terminalErr error
	defer func() {
		if terminalErr == nil {
			terminalErr = ctx.Err()
		}
		if terminalErr == nil {
			terminalErr = net.ErrClosed
		}
		s.publishState(false, terminalErr)
		close(s.done)
	}()

	first := true
	var backoff retryBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		attemptContext, cancelAttempt := context.WithTimeout(ctx, s.reconnectTimeout)
		conn, err := s.dial(attemptContext)
		cancelAttempt()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isPermanentRetry(err) {
				terminalErr = err
				if first {
					s.sendReady(err)
				}
				if s.logger != nil {
					s.logger.Error("GlobalProtect tunnel stopped after a permanent authentication or configuration error: ", err)
				}
				return
			}
			retryDelay := backoff.Next()
			if s.logger != nil {
				if first {
					s.logger.Warn("GlobalProtect tunnel connection failed; retrying in ", retryDelay, ": ", err)
				} else {
					s.logger.Warn("GlobalProtect tunnel reconnect failed; retrying in ", retryDelay, ": ", err)
				}
			}
			if !sleepContext(ctx, retryDelay) {
				return
			}
			continue
		}

		s.setConn(conn)
		s.publishState(true, nil)
		if first {
			s.sendReady(nil)
			first = false
		}

		connectedAt := time.Now()
		err = s.pump(ctx, conn)
		s.publishState(false, nil)
		_ = conn.Close()
		s.clearConn(conn)
		if ctx.Err() != nil {
			return
		}
		if time.Since(connectedAt) >= stableConnectionTime {
			backoff.Reset()
		}
		retryDelay := backoff.Next()
		if err != nil && s.logger != nil {
			s.logger.Warn("GlobalProtect tunnel disconnected; reconnecting in ", retryDelay, ": ", err)
		}
		if !sleepContext(ctx, retryDelay) {
			return
		}
	}
}

func (s *tunnelSession) sendReady(err error) {
	select {
	case s.ready <- err:
	default:
	}
}

func (s *tunnelSession) pump(ctx context.Context, conn net.Conn) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	packetFrames := make(chan framePacket, 128)
	errCh := make(chan error, 3)

	go func() {
		errCh <- s.outboundLoop(runCtx, packetFrames)
	}()
	go func() {
		errCh <- s.writerLoop(runCtx, conn, packetFrames)
	}()
	go func() {
		errCh <- s.readerLoop(runCtx, conn)
	}()

	var firstErr error
	for i := 0; i < 3; i++ {
		err := <-errCh
		if i == 0 {
			cancel()
			_ = conn.Close()
		}
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
			continue
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *tunnelSession) outboundLoop(ctx context.Context, frames chan<- framePacket) error {
	defer close(frames)

	for {
		pkt := s.endpoint.ReadContext(ctx)
		if pkt == nil {
			return ctx.Err()
		}
		payload := packetBufferBytes(pkt)
		pkt.DecRef()
		if len(payload) == 0 {
			continue
		}
		ethertype := uint16(0x0800)
		if payload[0]>>4 == 6 {
			ethertype = 0x86DD
		}
		select {
		case frames <- framePacket{ethertype: ethertype, payload: payload}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *tunnelSession) writerLoop(ctx context.Context, conn net.Conn, frames <-chan framePacket) error {
	ticker := time.NewTicker(s.keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame, ok := <-frames:
			if !ok {
				return nil
			}
			if err := writeGPSTFrame(ctx, conn, encodeGPSTFrame(frame.ethertype, frame.payload, false)); err != nil {
				return err
			}
		case <-ticker.C:
			if err := writeGPSTFrame(ctx, conn, encodeGPSTFrame(0, nil, true)); err != nil {
				return err
			}
		}
	}
}

func (s *tunnelSession) readerLoop(ctx context.Context, conn net.Conn) error {
	reader := bufio.NewReader(conn)
	timeout := s.keepalive*3 + 5*time.Second
	if timeout <= 0 {
		timeout = 35 * time.Second
	}
	for {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		frame, err := readGPSTFrame(reader)
		if err != nil {
			return err
		}
		ethertype, payload, keepalive, err := decodeGPSTFrame(frame)
		if err != nil {
			return err
		}
		if keepalive || ethertype == 0 {
			if s.logger != nil {
				s.logger.Debug("GlobalProtect RX keepalive")
			}
			continue
		}
		payloadCopy := append([]byte(nil), payload...)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(payloadCopy),
		})
		switch ethertype {
		case 0x0800:
			s.endpoint.InjectInbound(header.IPv4ProtocolNumber, pkt)
		case 0x86DD:
			s.endpoint.InjectInbound(header.IPv6ProtocolNumber, pkt)
		default:
			pkt.DecRef()
			return E.New("unknown GlobalProtect ethertype: ", ethertype)
		}
		pkt.DecRef()
	}
}

func packetBufferBytes(pkt *stack.PacketBuffer) []byte {
	slices := pkt.AsSlices()
	size := 0
	for _, slice := range slices {
		size += len(slice)
	}
	if size == 0 {
		return nil
	}
	out := make([]byte, size)
	offset := 0
	for _, slice := range slices {
		offset += copy(out[offset:], slice)
	}
	return out
}

func writeGPSTFrame(ctx context.Context, conn net.Conn, frame []byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
	for len(frame) > 0 {
		written, err := conn.Write(frame)
		if written > 0 {
			frame = frame[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readGPSTFrame(r io.Reader) ([]byte, error) {
	headerBuf := make([]byte, 16)
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, err
	}
	payloadLen := binary.BigEndian.Uint16(headerBuf[6:8])
	frame := make([]byte, 16+int(payloadLen))
	copy(frame, headerBuf)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, frame[16:]); err != nil {
			return nil, err
		}
	}
	return frame, nil
}

func encodeGPSTFrame(ethertype uint16, payload []byte, keepalive bool) []byte {
	frame := make([]byte, 16+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], gpstMagic)
	binary.BigEndian.PutUint16(frame[4:6], ethertype)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	if keepalive {
		binary.LittleEndian.PutUint32(frame[8:12], 0)
		binary.LittleEndian.PutUint32(frame[12:16], 0)
	} else {
		binary.LittleEndian.PutUint32(frame[8:12], 1)
		binary.LittleEndian.PutUint32(frame[12:16], 0)
	}
	copy(frame[16:], payload)
	return frame
}

func decodeGPSTFrame(frame []byte) (uint16, []byte, bool, error) {
	if len(frame) < 16 {
		return 0, nil, false, E.New("short GlobalProtect frame")
	}
	if binary.BigEndian.Uint32(frame[0:4]) != gpstMagic {
		return 0, nil, false, E.New("invalid GlobalProtect magic")
	}
	ethertype := binary.BigEndian.Uint16(frame[4:6])
	payloadLen := int(binary.BigEndian.Uint16(frame[6:8]))
	if len(frame) != 16+payloadLen {
		return 0, nil, false, E.New("unexpected GlobalProtect payload length")
	}
	one := binary.LittleEndian.Uint32(frame[8:12])
	zero := binary.LittleEndian.Uint32(frame[12:16])
	keepalive := ethertype == 0 && one == 0 && zero == 0
	if !keepalive && one != 1 {
		return 0, nil, false, E.New("invalid GlobalProtect packet marker")
	}
	if keepalive {
		return ethertype, nil, true, nil
	}
	return ethertype, frame[16:], false, nil
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return true
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
