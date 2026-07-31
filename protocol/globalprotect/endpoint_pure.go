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
	ctx       context.Context
	logger    logger.ContextLogger
	dnsRouter adapter.DNSRouter
	options   option.GlobalProtectEndpointOptions
	client    *portalClient
	transport tunnelTransport

	startOnce sync.Once
	startErr  error
}

const initialConnectRetryDelay = 2 * time.Second

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
	client, err := newPortalClient(ctx, options)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		Adapter:   endpoint.NewAdapter(Cst.TypeGlobalProtect, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		ctx:       ctx,
		logger:    logger,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		options:   options,
		client:    client,
	}, nil
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	e.startOnce.Do(func() {
		e.startErr = e.start()
	})
	return e.startErr
}

func (e *Endpoint) start() error {
	reconnectTimeout := normalizedReconnectTimeout(time.Duration(e.options.ReconnectTimeout))
	for {
		attemptContext, cancel := context.WithTimeout(e.ctx, reconnectTimeout)
		state, err := e.client.obtainSession(attemptContext, e.logger)
		cancel()
		if err == nil {
			transport, transportErr := newTunnelTransport(e.ctx, e.logger, e.client, state, reconnectTimeout)
			if transportErr == nil {
				e.transport = transport
				return nil
			}
			err = transportErr
		}
		if e.ctx.Err() != nil {
			return e.ctx.Err()
		}
		if e.logger != nil {
			e.logger.Warn("GlobalProtect initial connection failed; retrying: ", err)
		}
		if !sleepContext(e.ctx, initialConnectRetryDelay) {
			return e.ctx.Err()
		}
	}
}

func (e *Endpoint) Close() error {
	var closeErrors []error
	if e.transport != nil {
		if err := e.transport.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	if e.client != nil {
		logoutContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := e.client.logout(logoutContext); err != nil {
			closeErrors = append(closeErrors, err)
		} else {
			e.logger.Info("GlobalProtect logout successful")
		}
		cancel()
	}
	return errors.Join(closeErrors...)
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if e.transport == nil {
		return nil, E.New("GlobalProtect tunnel is not ready")
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		e.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
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
		return N.DialSerial(ctx, e.transport, network, destination, destinationAddresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return e.transport.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if e.transport == nil {
		return nil, E.New("GlobalProtect tunnel is not ready")
	}
	e.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsDomain() {
		if e.dnsRouter == nil {
			return nil, E.New("missing DNS router")
		}
		destinationAddresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, destinationAddress, err := N.ListenSerial(ctx, e.transport, destination, destinationAddresses)
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
	return e.transport.ListenPacket(ctx, destination)
}
