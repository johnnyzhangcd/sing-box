//go:build with_globalprotect && with_gvisor

package globalprotect

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-box/transport/wireguard"
	singTun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type tunnelTransport interface {
	N.Dialer
	Close() error
}

type globalProtectTransport struct {
	linkedEndpoint *channel.Endpoint
	stack          *stack.Stack
	session        *tunnelSession

	stateAccess  sync.RWMutex
	prefixes     []netip.Prefix
	inet4Address netip.Addr
	inet6Address netip.Addr
	closeOnce    sync.Once
}

func newTunnelTransport(ctx context.Context, log logger.ContextLogger, client *portalClient, state *sessionState, reconnectTimeout time.Duration) (tunnelTransport, error) {
	if state == nil {
		return nil, E.New("missing GlobalProtect session state")
	}
	if state.GatewayURL == nil {
		return nil, E.New("missing GlobalProtect gateway URL")
	}

	linkedEndpoint := channel.New(256, state.TunnelConfig.MTU, "")
	ipStack, err := singTun.NewGVisorStackWithOptions(linkedEndpoint, stack.NICOptions{}, true)
	if err != nil {
		return nil, err
	}

	transport := &globalProtectTransport{
		linkedEndpoint: linkedEndpoint,
		stack:          ipStack,
	}
	if err = transport.updateTunnelConfig(state.TunnelConfig); err != nil {
		return nil, err
	}
	onRefresh := func(refreshed *sessionState) error {
		if refreshed == nil {
			return E.New("missing refreshed GlobalProtect session")
		}
		if log != nil {
			log.Info("GlobalProtect tunnel configuration refreshed")
		}
		return transport.updateTunnelConfig(refreshed.TunnelConfig)
	}
	session := newTunnelSession(linkedEndpoint, newTunnelDialer(client, state, onRefresh, log), log, 10*time.Second, reconnectTimeout)
	transport.session = session
	success := false
	defer func() {
		if !success {
			_ = transport.Close()
		}
	}()

	if log != nil {
		log.Info("GlobalProtect tunnel MTU: ", state.TunnelConfig.MTU)
		for _, prefix := range state.TunnelConfig.Prefixes {
			log.Info("GlobalProtect tunnel address: ", prefix.String())
		}
	}
	ready := session.start(ctx)
	select {
	case err := <-ready:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	transport.session = session
	success = true
	return transport, nil
}

func (t *globalProtectTransport) updateTunnelConfig(config tunnelConfig) error {
	t.stateAccess.Lock()
	defer t.stateAccess.Unlock()
	if len(config.Prefixes) == 0 {
		return E.New("missing GlobalProtect tunnel address")
	}
	for _, prefix := range t.prefixes {
		if slices.Contains(config.Prefixes, prefix) {
			continue
		}
		if gErr := t.stack.RemoveAddress(singTun.DefaultNIC, singTun.AddressFromAddr(prefix.Addr())); gErr != nil {
			return E.New("remove GlobalProtect tunnel address ", prefix, ": ", gErr.String())
		}
	}
	for _, prefix := range config.Prefixes {
		if slices.Contains(t.prefixes, prefix) {
			continue
		}
		protoAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   singTun.AddressFromAddr(prefix.Addr()),
				PrefixLen: prefix.Bits(),
			},
		}
		if prefix.Addr().Is4() {
			protoAddr.Protocol = ipv4.ProtocolNumber
		} else {
			protoAddr.Protocol = ipv6.ProtocolNumber
		}
		if gErr := t.stack.AddProtocolAddress(singTun.DefaultNIC, protoAddr, stack.AddressProperties{}); gErr != nil {
			return E.New("add GlobalProtect tunnel address ", protoAddr.AddressWithPrefix, ": ", gErr.String())
		}
	}
	t.linkedEndpoint.SetMTU(uint32(config.MTU))
	t.prefixes = append(t.prefixes[:0], config.Prefixes...)
	t.inet4Address = netip.Addr{}
	t.inet6Address = netip.Addr{}
	for _, prefix := range config.Prefixes {
		if prefix.Addr().Is4() && !t.inet4Address.IsValid() {
			t.inet4Address = prefix.Addr()
		}
		if prefix.Addr().Is6() && !t.inet6Address.IsValid() {
			t.inet6Address = prefix.Addr()
		}
	}
	return nil
}

func (t *globalProtectTransport) tunnelAddresses() (netip.Addr, netip.Addr) {
	t.stateAccess.RLock()
	defer t.stateAccess.RUnlock()
	return t.inet4Address, t.inet6Address
}

func (t *globalProtectTransport) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}

	addr := tcpip.FullAddress{
		NIC:  singTun.DefaultNIC,
		Port: destination.Port,
		Addr: singTun.AddressFromAddr(destination.Addr),
	}
	bind := tcpip.FullAddress{NIC: singTun.DefaultNIC}
	var networkProtocol tcpip.NetworkProtocolNumber
	inet4Address, inet6Address := t.tunnelAddresses()
	if destination.IsIPv4() {
		if !inet4Address.IsValid() {
			return nil, E.New("missing IPv4 tunnel address")
		}
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = singTun.AddressFromAddr(inet4Address)
	} else {
		if !inet6Address.IsValid() {
			return nil, E.New("missing IPv6 tunnel address")
		}
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = singTun.AddressFromAddr(inet6Address)
	}

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		tcpConn, err := wireguard.DialTCPWithBind(ctx, t.stack, bind, addr, networkProtocol)
		if err != nil {
			return nil, err
		}
		return tcpConn, nil
	case N.NetworkUDP:
		udpConn, err := gonet.DialUDP(t.stack, &bind, &addr, networkProtocol)
		if err != nil {
			return nil, err
		}
		return udpConn, nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (t *globalProtectTransport) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}

	bind := tcpip.FullAddress{NIC: singTun.DefaultNIC}
	var networkProtocol tcpip.NetworkProtocolNumber
	inet4Address, inet6Address := t.tunnelAddresses()
	if destination.IsIPv4() {
		if !inet4Address.IsValid() {
			return nil, E.New("missing IPv4 tunnel address")
		}
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = singTun.AddressFromAddr(inet4Address)
	} else {
		if !inet6Address.IsValid() {
			return nil, E.New("missing IPv6 tunnel address")
		}
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = singTun.AddressFromAddr(inet6Address)
	}

	udpConn, err := gonet.DialUDP(t.stack, &bind, nil, networkProtocol)
	if err != nil {
		return nil, err
	}
	return udpConn, nil
}

func (t *globalProtectTransport) Close() error {
	var errs []error
	t.closeOnce.Do(func() {
		if t.session != nil {
			t.session.stop()
		}
		if t.linkedEndpoint != nil {
			t.linkedEndpoint.Attach(nil)
		}
		if t.stack != nil {
			t.stack.Close()
			for _, endpoint := range t.stack.CleanupEndpoints() {
				endpoint.Abort()
			}
		}
		if t.linkedEndpoint != nil {
			t.linkedEndpoint.Close()
		}
	})
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
