//go:build with_globalprotect

package globalprotect

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

type openconnectIPInfo struct {
	Addr     string
	Netmask  string
	Addr6    string
	Netmask6 string
	MTU      int
}

type tunnelConfig struct {
	Prefixes []netip.Prefix
	MTU      uint32
}

func buildTunnelConfig(info openconnectIPInfo) (tunnelConfig, error) {
	var prefixes []netip.Prefix

	if prefix, ok, err := parseOpenConnectIPv4Prefix(info.Addr, info.Netmask); err != nil {
		return tunnelConfig{}, err
	} else if ok {
		prefixes = append(prefixes, prefix)
	}

	if prefix, ok, err := parseOpenConnectIPv6Prefix(info.Addr6, info.Netmask6); err != nil {
		return tunnelConfig{}, err
	} else if ok {
		prefixes = append(prefixes, prefix)
	}

	if len(prefixes) == 0 {
		return tunnelConfig{}, E.New("missing tunnel address")
	}

	mtu := uint32(info.MTU)
	if mtu == 0 {
		mtu = 1400
	}

	return tunnelConfig{
		Prefixes: prefixes,
		MTU:      mtu,
	}, nil
}

func parseOpenConnectIPv4Prefix(addr, netmask string) (netip.Prefix, bool, error) {
	addr = strings.TrimSpace(addr)
	netmask = strings.TrimSpace(netmask)
	if addr == "" && netmask == "" {
		return netip.Prefix{}, false, nil
	}

	if addr == "" {
		prefix, err := netip.ParsePrefix(netmask)
		if err != nil {
			return netip.Prefix{}, false, E.New("missing IPv4 address")
		}
		if !prefix.Addr().Is4() {
			return netip.Prefix{}, false, E.New("invalid IPv4 prefix: ", prefix)
		}
		return prefix, true, nil
	}

	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Prefix{}, false, E.Cause(err, "parse IPv4 address")
	}
	if !ip.Is4() {
		return netip.Prefix{}, false, E.New("invalid IPv4 address: ", addr)
	}
	if netmask == "" {
		return netip.PrefixFrom(ip, 32), true, nil
	}

	if prefix, err := netip.ParsePrefix(netmask); err == nil && prefix.Addr().Is4() {
		return netip.PrefixFrom(ip, prefix.Bits()), true, nil
	}

	if maskAddr, err := netip.ParseAddr(netmask); err == nil && maskAddr.Is4() {
		if bits, total := net.IPMask(maskAddr.AsSlice()).Size(); total > 0 {
			return netip.PrefixFrom(ip, bits), true, nil
		}
	}

	if bits, err := strconv.Atoi(netmask); err == nil && bits >= 0 && bits <= 32 {
		return netip.PrefixFrom(ip, bits), true, nil
	}

	return netip.Prefix{}, false, E.New("invalid IPv4 netmask: ", netmask)
}

func parseOpenConnectIPv6Prefix(addr, netmask string) (netip.Prefix, bool, error) {
	addr = strings.TrimSpace(addr)
	netmask = strings.TrimSpace(netmask)
	if addr == "" && netmask == "" {
		return netip.Prefix{}, false, nil
	}

	if addr == "" {
		prefix, err := netip.ParsePrefix(netmask)
		if err != nil {
			return netip.Prefix{}, false, E.New("missing IPv6 address")
		}
		if !prefix.Addr().Is6() {
			return netip.Prefix{}, false, E.New("invalid IPv6 prefix: ", prefix)
		}
		return prefix, true, nil
	}

	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Prefix{}, false, E.Cause(err, "parse IPv6 address")
	}
	if !ip.Is6() {
		return netip.Prefix{}, false, E.New("invalid IPv6 address: ", addr)
	}
	if netmask == "" {
		return netip.PrefixFrom(ip, 128), true, nil
	}

	if prefix, err := netip.ParsePrefix(netmask); err == nil && prefix.Addr().Is6() {
		return netip.PrefixFrom(ip, prefix.Bits()), true, nil
	}

	if maskAddr, err := netip.ParseAddr(netmask); err == nil && maskAddr.Is6() {
		if bits, total := net.IPMask(maskAddr.AsSlice()).Size(); total > 0 {
			return netip.PrefixFrom(ip, bits), true, nil
		}
	}

	if bits, err := strconv.Atoi(netmask); err == nil && bits >= 0 && bits <= 128 {
		return netip.PrefixFrom(ip, bits), true, nil
	}

	return netip.Prefix{}, false, E.New("invalid IPv6 netmask: ", netmask)
}
