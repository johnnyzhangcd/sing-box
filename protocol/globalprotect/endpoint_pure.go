//go:build with_globalprotect && with_gvisor

package globalprotect

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	Cst "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var _ adapter.Outbound = (*Endpoint)(nil)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.GlobalProtectEndpointOptions](registry, Cst.TypeGlobalProtect, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	loopContext context.Context
	cancelLoop  context.CancelFunc
	logger      logger.ContextLogger
	dnsRouter   adapter.DNSRouter
	options     option.GlobalProtectEndpointOptions
	client      *portalClient

	lifecycleAccess sync.Mutex
	started         bool
	closed          bool
	loopDone        chan struct{}
	closeOnce       sync.Once
	closeErr        error
	firstReadyOnce  sync.Once
	firstReadyDone  chan struct{}
	firstReadyErr   error

	transportAccess sync.RWMutex
	transport       tunnelTransport
}

const logoutTimeout = 3 * time.Second

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.GlobalProtectEndpointOptions) (adapter.Endpoint, error) {
	if options.Server == "" {
		return nil, E.New("missing server")
	}
	if options.Username == "" {
		return nil, E.New("missing username")
	}
	if !options.DisableDTLS && logger != nil {
		logger.Warn("GlobalProtect pure-Go endpoint uses TLS/GPST only; DTLS and ESP are unavailable")
	}
	loopContext, cancelLoop := context.WithCancel(ctx)
	client, err := newPortalClient(ctx, options)
	if err != nil {
		cancelLoop()
		return nil, err
	}
	return &Endpoint{
		Adapter:        endpoint.NewAdapterWithDialerOptions(Cst.TypeGlobalProtect, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		loopContext:    loopContext,
		cancelLoop:     cancelLoop,
		logger:         logger,
		dnsRouter:      service.FromContext[adapter.DNSRouter](ctx),
		options:        options,
		client:         client,
		loopDone:       make(chan struct{}),
		firstReadyDone: make(chan struct{}),
	}, nil
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	waitForReady := e.options.WaitForReady
	if waitForReady && stage != adapter.StartStateStart {
		return nil
	}
	if !waitForReady && stage != adapter.StartStatePostStart {
		return nil
	}
	e.lifecycleAccess.Lock()
	if e.closed {
		e.lifecycleAccess.Unlock()
		return net.ErrClosed
	}
	if !e.started {
		e.started = true
		go e.startLoop()
	}
	e.lifecycleAccess.Unlock()
	if waitForReady {
		return e.waitFirstReady(e.loopContext)
	}
	return nil
}

func (e *Endpoint) startLoop() {
	defer close(e.loopDone)
	defer func() {
		if err := e.loopContext.Err(); err != nil {
			e.signalFirstReady(err)
		}
	}()
	reconnectTimeout := normalizedReconnectTimeout(time.Duration(e.options.ReconnectTimeout))
	var backoff retryBackoff
	for {
		attemptContext, cancel := context.WithTimeout(e.loopContext, reconnectTimeout)
		state, err := e.client.obtainSession(attemptContext, e.logger)
		cancel()
		if err == nil {
			transport, transportErr := newTunnelTransport(e.loopContext, e.logger, e.client, state, reconnectTimeout)
			if transportErr == nil {
				e.transportAccess.Lock()
				if e.loopContext.Err() != nil {
					e.transportAccess.Unlock()
					_ = transport.Close()
					return
				}
				e.transport = transport
				e.transportAccess.Unlock()
				e.signalFirstReady(nil)
				e.periodicHIPLoop(reconnectTimeout)
				return
			}
			err = transportErr
		}
		if e.loopContext.Err() != nil {
			return
		}
		if isPermanentRetry(err) {
			_ = e.client.closeControl()
			e.signalFirstReady(err)
			if e.logger != nil {
				e.logger.Error("GlobalProtect connection stopped after a permanent authentication or configuration error: ", err)
			}
			return
		}
		retryDelay := backoff.Next()
		if e.logger != nil {
			e.logger.Warn("GlobalProtect initial connection failed; retrying in ", retryDelay, ": ", err)
		}
		if !sleepContext(e.loopContext, retryDelay) {
			return
		}
	}
}

func (e *Endpoint) signalFirstReady(err error) {
	e.firstReadyOnce.Do(func() {
		e.firstReadyErr = err
		close(e.firstReadyDone)
	})
}

func (e *Endpoint) waitFirstReady(ctx context.Context) error {
	select {
	case <-e.firstReadyDone:
		return e.firstReadyErr
	case <-ctx.Done():
		return ctx.Err()
	case <-e.loopContext.Done():
		select {
		case <-e.firstReadyDone:
			return e.firstReadyErr
		default:
			return e.loopContext.Err()
		}
	}
}

func (e *Endpoint) readyTransport(ctx context.Context) (tunnelTransport, error) {
	transport := e.currentTransport()
	if transport != nil && transport.Ready() {
		return transport, nil
	}
	if !e.options.WaitForReady {
		return nil, E.New("GlobalProtect tunnel is not ready")
	}
	if transport == nil {
		if err := e.waitFirstReady(ctx); err != nil {
			return nil, err
		}
		transport = e.currentTransport()
	}
	if transport == nil {
		return nil, E.New("GlobalProtect tunnel is not ready")
	}
	if err := transport.WaitReady(ctx); err != nil {
		return nil, err
	}
	return transport, nil
}

func (e *Endpoint) periodicHIPLoop(checkTimeout time.Duration) {
	var retryDelay time.Duration
	for {
		state := e.client.session()
		interval := defaultHIPCheckInterval
		if state != nil && state.HIPCheckInterval > 0 {
			interval = state.HIPCheckInterval
		}
		delay := interval
		if retryDelay > 0 && retryDelay < delay {
			delay = retryDelay
		}
		timer := time.NewTimer(delay)
		select {
		case <-e.loopContext.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-e.client.sessionChanges():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			continue
		case <-timer.C:
		}

		attemptContext, cancel := context.WithTimeout(e.loopContext, checkTimeout)
		needed, err := e.client.recheckHIP(attemptContext)
		cancel()
		if err != nil {
			if isPermanentRetry(err) {
				if e.logger != nil && e.loopContext.Err() == nil {
					e.logger.Error("GlobalProtect periodic HIP checks stopped after a permanent authentication or configuration error: ", err)
				}
				return
			}
			retryDelay = min(interval, time.Minute)
			if e.logger != nil && e.loopContext.Err() == nil {
				e.logger.Warn("GlobalProtect periodic HIP check failed; retrying: ", err)
			}
			continue
		}
		retryDelay = 0
		if needed && e.logger != nil {
			e.logger.Info("GlobalProtect periodic HIP report submitted")
		}
	}
}

func (e *Endpoint) Close() error {
	e.closeOnce.Do(func() {
		e.lifecycleAccess.Lock()
		e.closed = true
		started := e.started
		e.cancelLoop()
		e.lifecycleAccess.Unlock()
		if started {
			<-e.loopDone
		}

		var closeErrors []error
		e.transportAccess.Lock()
		transport := e.transport
		e.transport = nil
		e.transportAccess.Unlock()
		if transport != nil {
			if err := transport.Close(); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
		if e.client != nil {
			logoutContext, cancel := context.WithTimeout(context.Background(), logoutTimeout)
			if err := e.client.logout(logoutContext); err != nil {
				closeErrors = append(closeErrors, err)
			} else if e.logger != nil {
				e.logger.Info("GlobalProtect logout successful")
			}
			cancel()
		}
		e.closeErr = errors.Join(closeErrors...)
	})
	return e.closeErr
}

func (e *Endpoint) currentTransport() tunnelTransport {
	e.transportAccess.RLock()
	defer e.transportAccess.RUnlock()
	return e.transport
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	transport, err := e.readyTransport(ctx)
	if err != nil {
		return nil, err
	}
	if e.logger != nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			e.logger.InfoContext(ctx, "outbound connection to ", destination)
		case N.NetworkUDP:
			e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
	}
	if destination.IsDomain() {
		if e.dnsRouter == nil {
			return nil, E.New("missing DNS router")
		}
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, transport, network, destination, destinationAddresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return transport.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	transport, err := e.readyTransport(ctx)
	if err != nil {
		return nil, err
	}
	if e.logger != nil {
		e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsDomain() {
		if e.dnsRouter == nil {
			return nil, E.New("missing DNS router")
		}
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, destinationAddress, err := N.ListenSerial(ctx, transport, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
			return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
		}
		return packetConn, nil
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return transport.ListenPacket(ctx, destination)
}
