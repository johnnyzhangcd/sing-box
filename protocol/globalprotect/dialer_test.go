//go:build with_globalprotect

package globalprotect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestControlDialHonorsIPv4BindAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	bindAddress := badoption.Addr(netip.MustParseAddr("127.0.0.2"))
	client, err := newPortalClient(context.Background(), option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{Server: listener.Addr().String()},
		DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
			Inet4BindAddress: &bindAddress,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientConn, err := client.dialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	select {
	case err = <-acceptErr:
		t.Fatal(err)
	case serverConn := <-accepted:
		defer serverConn.Close()
		remoteAddress := serverConn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
		if remoteAddress.String() != "127.0.0.2" {
			t.Fatalf("control connection ignored inet4_bind_address: %s", remoteAddress)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestControlDialPinsConfiguredIPBeforeSOCKS(t *testing.T) {
	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()

	type proxyResult struct {
		target string
		err    error
	}
	result := make(chan proxyResult, 1)
	go func() {
		conn, acceptErr := proxyListener.Accept()
		if acceptErr != nil {
			result <- proxyResult{err: acceptErr}
			return
		}
		defer conn.Close()
		target, handshakeErr := acceptSOCKS5Connect(conn)
		result <- proxyResult{target: target, err: handshakeErr}
	}()

	client, err := newPortalClient(context.Background(), option.GlobalProtectEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     "192.0.2.10",
			ServerPort: 1235,
		},
		SNI:   "vpn.example.com",
		Proxy: "socks5://" + proxyListener.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientConn, err := client.dialContext(ctx, "tcp", client.baseURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.target != "192.0.2.10:1235" {
			t.Fatalf("SOCKS CONNECT target = %q, want configured server IP", got.target)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func acceptSOCKS5Connect(conn net.Conn) (string, error) {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return "", err
	}
	if greeting[0] != 5 || greeting[1] == 0 {
		return "", fmt.Errorf("invalid SOCKS greeting: %x", greeting)
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}

	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return "", err
	}
	if request[0] != 5 || request[1] != 1 {
		return "", fmt.Errorf("invalid SOCKS CONNECT request: %x", request)
	}
	var host string
	switch request[3] {
	case 1:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 4:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return "", err
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = string(address)
	default:
		return "", fmt.Errorf("unsupported SOCKS address type: %d", request[3])
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return "", err
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
