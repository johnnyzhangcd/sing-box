package globalprotect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/proxy"
)

type portalClient struct {
	options     option.GlobalProtectEndpointOptions
	baseURL     *url.URL
	serverHost  string
	localHost   string
	reportedOS  string
	dnsRouter   adapter.DNSRouter
	tlsConfig   *tls.Config
	dialContext func(context.Context, string, string) (net.Conn, error)

	controlMu     sync.Mutex
	controlConn   net.Conn
	controlReader *bufio.Reader
	controlHost   string

	sessionMu   sync.Mutex
	activeState *sessionState
}

type tunnelSessionDialer interface {
	obtainSession(context.Context, logger.ContextLogger) (*sessionState, error)
	openTunnel(context.Context, *url.URL, string, string) (net.Conn, error)
}

var errPortalUnavailable = errors.New("GlobalProtect portal unavailable")

func classifyPortalError(message string) error {
	if strings.Contains(strings.ToLower(message), "portal does not exist") {
		return fmt.Errorf("%w: %s", errPortalUnavailable, message)
	}
	return E.New(message)
}

type sessionState struct {
	GatewayURL   *url.URL
	Cookie       string
	TunnelURL    string
	TunnelConfig tunnelConfig
	AppVersion   string
}

func newPortalClient(ctx context.Context, options option.GlobalProtectEndpointOptions) (*portalClient, error) {
	baseURL, err := parseServerURL(options.Server, options.ServerPort)
	if err != nil {
		return nil, err
	}

	localHost := strings.TrimSpace(options.LocalHostname)
	if localHost == "" {
		localHost, _ = os.Hostname()
		localHost = strings.TrimSpace(localHost)
	}
	if localHost == "" {
		localHost = "sing-box"
	}

	serverName := strings.TrimSpace(options.SNI)
	if serverName == "" {
		serverName = baseURL.Hostname()
	}

	tlsConfig, err := buildTLSConfig(options, serverName)
	if err != nil {
		return nil, err
	}
	baseURL = logicalServerURL(baseURL, options.SNI)

	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	dialer, err := buildProxyDialer(ctx, options, dnsRouter)
	if err != nil {
		return nil, err
	}

	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialWithContext(ctx, dialer, network, address)
	}

	client := &portalClient{
		options:     options,
		baseURL:     baseURL,
		serverHost:  baseURL.Hostname(),
		localHost:   localHost,
		reportedOS:  options.ReportedOS,
		dnsRouter:   dnsRouter,
		tlsConfig:   tlsConfig,
		dialContext: dialContext,
	}
	return client, nil
}

type proxyForwardDialer struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func (d proxyForwardDialer) Dial(network, address string) (net.Conn, error) {
	return d.dial(context.Background(), network, address)
}

func (d proxyForwardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

func parseServerURL(server string, serverPort uint16) (*url.URL, error) {
	serverURL, err := buildServerURL(server, serverPort)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return nil, E.Cause(err, "parse server URL")
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}
	if parsed.Host == "" {
		return nil, E.New("missing server host")
	}
	return parsed, nil
}

func logicalServerURL(baseURL *url.URL, sni string) *url.URL {
	if baseURL == nil {
		return nil
	}
	next := *baseURL
	sni = strings.TrimSpace(sni)
	if sni == "" {
		return &next
	}
	if _, err := netip.ParseAddr(baseURL.Hostname()); err != nil {
		return &next
	}
	if port := baseURL.Port(); port != "" {
		next.Host = net.JoinHostPort(sni, port)
	} else {
		next.Host = sni
	}
	return &next
}

func buildServerURL(server string, serverPort uint16) (string, error) {
	if server == "" {
		return "", E.New("missing server")
	}
	if strings.Contains(server, "://") {
		return server, nil
	}
	host := server
	port := ""
	if parsedHost, parsedPort, err := net.SplitHostPort(server); err == nil {
		host = parsedHost
		port = parsedPort
	} else if serverPort != 0 {
		port = fmt.Sprint(serverPort)
	}
	if port == "" {
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
		return "https://" + host, nil
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

func pinnedControlAddress(options option.GlobalProtectEndpointOptions, address string) (string, bool) {
	sni := strings.TrimSpace(options.SNI)
	if sni == "" {
		return "", false
	}
	targetHost, targetPort, err := net.SplitHostPort(address)
	if err != nil || !strings.EqualFold(strings.TrimSuffix(targetHost, "."), strings.TrimSuffix(sni, ".")) {
		return "", false
	}
	baseURL, err := parseServerURL(options.Server, options.ServerPort)
	if err != nil {
		return "", false
	}
	baseAddress, err := netip.ParseAddr(baseURL.Hostname())
	if err != nil {
		return "", false
	}
	basePort := baseURL.Port()
	if basePort == "" {
		basePort = "443"
	}
	if targetPort != basePort {
		return "", false
	}
	return net.JoinHostPort(baseAddress.String(), targetPort), true
}

func buildProxyDialer(ctx context.Context, options option.GlobalProtectEndpointOptions, dnsRouter adapter.DNSRouter) (proxy.Dialer, error) {
	netDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if options.BindInterface != "" {
		bindFunc := control.BindToInterface(control.NewDefaultInterfaceFinder(), options.BindInterface, -1)
		netDialer.Control = control.Append(netDialer.Control, bindFunc)
	}
	directDialer := proxyForwardDialer{dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if pinnedAddress, ok := pinnedControlAddress(options, address); ok {
			address = pinnedAddress
		}
		destination, err := resolveDialTarget(ctx, network, address, dnsRouter)
		if err != nil {
			return nil, err
		}
		return netDialer.DialContext(ctx, network, destination.String())
	}}
	if strings.TrimSpace(options.Proxy) == "" {
		return directDialer, nil
	}
	parsed, err := url.Parse(options.Proxy)
	if err != nil {
		return nil, E.Cause(err, "parse proxy URL")
	}
	return proxy.FromURL(parsed, directDialer)
}

func resolveDialTarget(ctx context.Context, network, address string, dnsRouter adapter.DNSRouter) (M.Socksaddr, error) {
	destination := M.ParseSocksaddr(address)
	if destination.IsDomain() {
		lookupNetwork := "ip"
		switch {
		case strings.Contains(network, "4"):
			lookupNetwork = "ip4"
		case strings.Contains(network, "6"):
			lookupNetwork = "ip6"
		}
		if dnsRouter != nil {
			addresses, err := dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
			if err != nil {
				return M.Socksaddr{}, err
			}
			if len(addresses) == 0 {
				return M.Socksaddr{}, E.New("no address found for ", destination.Fqdn)
			}
			for _, addr := range addresses {
				switch lookupNetwork {
				case "ip4":
					if addr.Is4() {
						destination.Addr = addr
						goto resolved
					}
				case "ip6":
					if addr.Is6() {
						destination.Addr = addr
						goto resolved
					}
				default:
					destination.Addr = addr
					goto resolved
				}
			}
			return M.Socksaddr{}, E.New("no address found for ", destination.Fqdn)
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, lookupNetwork, destination.Fqdn)
		if err != nil {
			return M.Socksaddr{}, err
		}
		if len(addresses) == 0 {
			return M.Socksaddr{}, E.New("no address found for ", destination.Fqdn)
		}
		destination.Addr = addresses[0]
	}
resolved:
	if !destination.Addr.IsValid() {
		return M.Socksaddr{}, E.New("invalid address: ", address)
	}
	return destination, nil
}

func dialWithContext(ctx context.Context, d proxy.Dialer, network, address string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if contextDialer, ok := d.(interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}); ok {
		return contextDialer.DialContext(ctx, network, address)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := d.Dial(network, address)
		ch <- result{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.conn, res.err
	}
}

func newTunnelDialer(client tunnelSessionDialer, initialState *sessionState, onRefresh func(*sessionState) error, log logger.ContextLogger) func(context.Context) (net.Conn, error) {
	var dialMu sync.Mutex
	activeState := initialState
	firstDial := true
	return func(ctx context.Context) (net.Conn, error) {
		dialMu.Lock()
		defer dialMu.Unlock()
		if activeState == nil {
			state, err := client.obtainSession(ctx, log)
			if err != nil {
				return nil, err
			}
			if onRefresh != nil {
				if err = onRefresh(state); err != nil {
					return nil, err
				}
			}
			activeState = state
		}
		if firstDial {
			firstDial = false
			return client.openTunnel(ctx, activeState.GatewayURL, activeState.Cookie, activeState.TunnelURL)
		}
		conn, err := client.openTunnel(ctx, activeState.GatewayURL, activeState.Cookie, activeState.TunnelURL)
		if err == nil {
			return conn, nil
		}
		if log != nil {
			log.Warn("GlobalProtect session resume failed; refreshing authentication: ", err)
		}
		activeState = nil
		if ctx.Err() != nil {
			return nil, errors.Join(err, ctx.Err())
		}
		state, refreshErr := client.obtainSession(ctx, log)
		if refreshErr != nil {
			return nil, errors.Join(err, refreshErr)
		}
		if onRefresh != nil {
			if refreshErr = onRefresh(state); refreshErr != nil {
				return nil, errors.Join(err, refreshErr)
			}
		}
		activeState = state
		return client.openTunnel(ctx, state.GatewayURL, state.Cookie, state.TunnelURL)
	}
}

func buildTLSConfig(options option.GlobalProtectEndpointOptions, serverName string) (*tls.Config, error) {
	roots, err := buildRootCAs(options)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerCertificate(rawCerts, roots, serverName, options.ServerCert)
		},
	}
	if options.AllowInsecureCrypto {
		cfg.MinVersion = tls.VersionTLS10
		cfg.CipherSuites = allCipherSuites()
	}
	if options.PFS {
		cfg.CipherSuites = pfsCipherSuites(options.AllowInsecureCrypto)
	}
	return cfg, nil
}

func allCipherSuites() []uint16 {
	secureSuites := tls.CipherSuites()
	insecureSuites := tls.InsecureCipherSuites()
	result := make([]uint16, 0, len(secureSuites)+len(insecureSuites))
	for _, suite := range append(secureSuites, insecureSuites...) {
		result = append(result, suite.ID)
	}
	return result
}

func pfsCipherSuites(includeInsecure bool) []uint16 {
	suites := tls.CipherSuites()
	if includeInsecure {
		suites = append(suites, tls.InsecureCipherSuites()...)
	}
	result := make([]uint16, 0, len(suites))
	for _, suite := range suites {
		// TLS 1.3 always provides forward secrecy and its cipher suites are not configurable.
		// For TLS 1.2 and older, require ephemeral ECDH key exchange.
		if strings.Contains(suite.Name, "_ECDHE_") {
			result = append(result, suite.ID)
		}
	}
	return result
}

func buildRootCAs(options option.GlobalProtectEndpointOptions) (*x509.CertPool, error) {
	var roots *x509.CertPool
	if !options.NoSystemTrust {
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			systemRoots = x509.NewCertPool()
		}
		roots = systemRoots
	} else {
		roots = x509.NewCertPool()
	}
	if options.CAFile != "" {
		caData, err := os.ReadFile(options.CAFile)
		if err != nil {
			return nil, E.Cause(err, "read CA file")
		}
		if !roots.AppendCertsFromPEM(caData) {
			return nil, E.New("append CA file: no certificates found")
		}
	}
	return roots, nil
}

func verifyPeerCertificate(rawCerts [][]byte, roots *x509.CertPool, serverName, serverCert string) error {
	if len(rawCerts) == 0 {
		return E.New("empty server certificate chain")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return E.Cause(err, "parse server certificate")
	}
	if serverCert != "" {
		return verifyPinnedCertificate(leaf, serverCert)
	}
	intermediates := x509.NewCertPool()
	for _, rawCert := range rawCerts[1:] {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return E.Cause(err, "parse intermediate certificate")
		}
		intermediates.AddCert(cert)
	}
	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName,
	}
	if _, err := leaf.Verify(verifyOpts); err != nil {
		return E.Cause(err, "verify server certificate")
	}
	return nil
}

func verifyPinnedCertificate(cert *x509.Certificate, pin string) error {
	var fingerprint string
	var provided string
	caseSensitive := false
	switch {
	case strings.HasPrefix(pin, "sha1:"):
		provided = strings.TrimPrefix(pin, "sha1:")
		sum := sha1.Sum(cert.RawSubjectPublicKeyInfo)
		fingerprint = hex.EncodeToString(sum[:])
	case strings.HasPrefix(pin, "sha256:"):
		provided = strings.TrimPrefix(pin, "sha256:")
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		fingerprint = hex.EncodeToString(sum[:])
	case strings.HasPrefix(pin, "pin-sha256:"):
		provided = strings.TrimPrefix(pin, "pin-sha256:")
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		fingerprint = base64.StdEncoding.EncodeToString(sum[:])
		caseSensitive = true
	case !strings.Contains(pin, ":"):
		// OpenConnect's legacy unprefixed form is a SHA-1 hash of the full certificate.
		provided = pin
		sum := sha1.Sum(cert.Raw)
		fingerprint = hex.EncodeToString(sum[:])
	default:
		return E.New("unknown server certificate format")
	}
	if len(provided) < 4 {
		return E.New("server certificate fingerprint is shorter than 4 characters")
	}
	if len(provided) > len(fingerprint) {
		return E.New("server certificate fingerprint mismatch")
	}
	if caseSensitive {
		if !strings.HasPrefix(fingerprint, provided) {
			return E.New("server certificate fingerprint mismatch")
		}
	} else if !strings.EqualFold(fingerprint[:len(provided)], provided) {
		return E.New("server certificate fingerprint mismatch")
	}
	return nil
}

func (c *portalClient) rememberSession(state *sessionState) {
	c.sessionMu.Lock()
	c.activeState = state
	c.sessionMu.Unlock()
}

func (c *portalClient) session() *sessionState {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	return c.activeState
}

func (c *portalClient) closeControl() error {
	c.controlMu.Lock()
	defer c.controlMu.Unlock()
	var err error
	if c.controlConn != nil {
		err = c.controlConn.Close()
	}
	c.controlConn = nil
	c.controlReader = nil
	c.controlHost = ""
	return err
}

func (c *portalClient) logout(ctx context.Context) error {
	state := c.session()
	if state == nil || state.GatewayURL == nil || state.Cookie == "" {
		return c.closeControl()
	}
	_ = c.closeControl()
	target := *state.GatewayURL
	target.Path = joinURLPath(state.GatewayURL.Path, "ssl-vpn/logout.esp")
	target.RawQuery = ""
	data, err := c.doRequest(ctx, http.MethodPost, &target, "application/x-www-form-urlencoded", []byte(state.Cookie))
	if err != nil {
		_ = c.closeControl()
		return E.Cause(err, "GlobalProtect logout")
	}
	if err = parseLogoutXML(data); err != nil {
		_ = c.closeControl()
		return err
	}
	c.sessionMu.Lock()
	c.activeState = nil
	c.sessionMu.Unlock()
	return c.closeControl()
}

func parseLogoutXML(content []byte) error {
	type logoutXML struct {
		Status string `xml:"status,attr"`
		Error  string `xml:"error"`
	}
	var response logoutXML
	if err := xml.Unmarshal(content, &response); err != nil {
		return E.Cause(err, "parse GlobalProtect logout response")
	}
	if !strings.EqualFold(strings.TrimSpace(response.Status), "success") {
		message := strings.TrimSpace(response.Error)
		if message == "" {
			message = "unknown error"
		}
		return E.New("GlobalProtect logout failed: ", message)
	}
	return nil
}

func (c *portalClient) closeControlConnLocked() {
	if c.controlConn != nil {
		_ = c.controlConn.Close()
	}
	c.controlConn = nil
	c.controlReader = nil
	c.controlHost = ""
}

func (c *portalClient) ensureControlConnLocked(ctx context.Context, target *url.URL) (net.Conn, *bufio.Reader, error) {
	port := target.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(target.Hostname(), port)
	if c.controlConn != nil && c.controlHost == address {
		return c.controlConn, c.controlReader, nil
	}
	c.closeControlConnLocked()
	rawConn, err := c.dialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	tlsConn := tls.Client(rawConn, c.tlsConfig.Clone())
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	c.controlConn = tlsConn
	c.controlReader = bufio.NewReader(tlsConn)
	c.controlHost = address
	return c.controlConn, c.controlReader, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *portalClient) doRequest(ctx context.Context, method string, target *url.URL, contentType string, body []byte) ([]byte, error) {
	c.controlMu.Lock()
	defer c.controlMu.Unlock()
	conn, responseReader, err := c.ensureControlConnLocked(ctx, target)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "PAN GlobalProtect")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	if err = req.Write(conn); err != nil {
		c.closeControlConnLocked()
		return nil, err
	}
	resp, err := http.ReadResponse(responseReader, req)
	if err != nil {
		c.closeControlConnLocked()
		return nil, err
	}
	defer resp.Body.Close()
	const maxControlResponse = 16 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxControlResponse+1))
	if err != nil {
		c.closeControlConnLocked()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	if len(data) > maxControlResponse {
		c.closeControlConnLocked()
		return nil, E.New("GlobalProtect control response too large")
	}
	if resp.Close {
		c.closeControlConnLocked()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, E.New("GlobalProtect HTTP status: ", resp.Status)
	}
	return data, nil
}

func (c *portalClient) requestURL(suffix string) *url.URL {
	next := *c.baseURL
	next.Path = joinURLPath(c.baseURL.Path, suffix)
	next.RawQuery = ""
	next.Fragment = ""
	return &next
}

func joinURLPath(basePath, suffix string) string {
	basePath = strings.TrimSuffix(basePath, "/")
	suffix = strings.TrimPrefix(suffix, "/")
	if basePath == "" || basePath == "/" {
		return "/" + suffix
	}
	return path.Join(basePath, suffix)
}

func (c *portalClient) prelogin(ctx context.Context, portal bool) (*authForm, error) {
	suffix := "ssl-vpn/prelogin.esp"
	if portal {
		suffix = "global-protect/prelogin.esp"
	}
	target := c.requestURL(suffix)
	target.RawQuery = buildPreloginQuery(c.reportedOS).Encode()
	body := buildPreloginBody()
	data, err := c.doRequest(ctx, http.MethodPost, target, "application/x-www-form-urlencoded", []byte(body))
	if err != nil {
		return nil, err
	}
	return parsePreloginXML(data)
}

func (c *portalClient) portalConfig(ctx context.Context, form *authForm) (*portalConfig, error) {
	target := c.requestURL("global-protect/getconfig.esp")
	body := buildLoginBody(c.options.Username, c.options.Password, nil, c.serverHost, c.localHost, c.reportedOS, c.options.DisableIPv6, form.InputStr)
	data, err := c.doRequest(ctx, http.MethodPost, target, "application/x-www-form-urlencoded", []byte(body))
	if err != nil {
		return nil, err
	}
	cfg, err := parsePortalXML(data)
	if err != nil {
		return nil, err
	}
	if cfg.AppVersion == "" {
		cfg.AppVersion = defaultAppVersion
	}
	return cfg, nil
}

func (c *portalClient) gatewayLogin(ctx context.Context, gatewayURL *url.URL, portalCfg *portalConfig, form *authForm) (string, error) {
	target := *gatewayURL
	target.Path = joinURLPath(gatewayURL.Path, "ssl-vpn/login.esp")
	target.RawQuery = ""
	body := buildLoginBody(c.options.Username, c.options.Password, portalCfg, gatewayURL.Hostname(), c.localHost, c.reportedOS, c.options.DisableIPv6, form.InputStr)
	data, err := c.doRequest(ctx, http.MethodPost, &target, "application/x-www-form-urlencoded", []byte(body))
	if err != nil {
		return "", err
	}
	cookie, err := parseLoginXML(data, c.localHost)
	if err != nil {
		return "", err
	}
	return cookie, nil
}

func (c *portalClient) getConfig(ctx context.Context, gatewayURL *url.URL, cookie string, appVersion string) (openconnectIPInfo, string, error) {
	target := *gatewayURL
	target.Path = joinURLPath(gatewayURL.Path, "ssl-vpn/getconfig.esp")
	target.RawQuery = ""
	body := buildGetConfigBody(cookie, appVersion, c.reportedOS, c.options.DisableIPv6)
	data, err := c.doRequest(ctx, http.MethodPost, &target, "application/x-www-form-urlencoded", []byte(body))
	if err != nil {
		return openconnectIPInfo{}, "", err
	}
	return parseTunnelXML(data, c.options.DisableIPv6)
}

func (c *portalClient) checkHIP(ctx context.Context, gatewayURL *url.URL, cookie string, config tunnelConfig) (bool, error) {
	target := *gatewayURL
	target.Path = joinURLPath(gatewayURL.Path, "ssl-vpn/hipreportcheck.esp")
	target.RawQuery = ""
	body := buildHIPCheckBody(cookie, config.Prefixes)
	data, err := c.doRequest(ctx, http.MethodPost, &target, "application/x-www-form-urlencoded", []byte(body))
	if err != nil {
		return false, err
	}
	return parseHIPCheckXML(data)
}

func parseHIPCheckXML(content []byte) (bool, error) {
	type hipCheckXML struct {
		Status string `xml:"status,attr"`
		Needed string `xml:"hip-report-needed"`
	}
	var response hipCheckXML
	if err := xml.Unmarshal(content, &response); err != nil {
		return false, E.Cause(err, "parse HIP check response")
	}
	if status := strings.TrimSpace(response.Status); status != "" && !strings.EqualFold(status, "success") {
		return false, E.New("GlobalProtect HIP check failed: ", status)
	}
	switch strings.ToLower(strings.TrimSpace(response.Needed)) {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	default:
		return false, E.New("invalid GlobalProtect HIP check response")
	}
}

func (c *portalClient) openTunnel(ctx context.Context, gatewayURL *url.URL, cookie, tunnelURL string) (net.Conn, error) {
	target := *gatewayURL
	if tunnelURL != "" {
		if strings.HasPrefix(tunnelURL, "http://") || strings.HasPrefix(tunnelURL, "https://") {
			parsed, err := url.Parse(tunnelURL)
			if err == nil {
				target = *parsed
			}
		} else {
			target.Path = joinURLPath(gatewayURL.Path, tunnelURL)
		}
	}
	target.RawQuery = buildTunnelQuery(cookie)
	if target.Scheme == "" {
		target.Scheme = "https"
	}
	requestPath := target.Path
	if requestPath == "" {
		requestPath = "/ssl-tunnel-connect.sslvpn"
	}
	if target.RawQuery != "" {
		requestPath += "?" + target.RawQuery
	}
	c.controlMu.Lock()
	conn, responseReader, err := c.ensureControlConnLocked(ctx, &target)
	if err != nil {
		c.controlMu.Unlock()
		return nil, err
	}
	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	request := []byte("GET " + requestPath + " HTTP/1.1\r\n\r\n")
	for len(request) > 0 {
		written, writeErr := conn.Write(request)
		if written > 0 {
			request = request[written:]
		}
		if writeErr != nil {
			c.closeControlConnLocked()
			c.controlMu.Unlock()
			return nil, writeErr
		}
		if written == 0 {
			c.closeControlConnLocked()
			c.controlMu.Unlock()
			return nil, io.ErrShortWrite
		}
	}
	buf := make([]byte, len("START_TUNNEL"))
	if _, err = io.ReadFull(responseReader, buf); err != nil {
		c.closeControlConnLocked()
		c.controlMu.Unlock()
		return nil, err
	}
	if string(buf) != "START_TUNNEL" {
		c.closeControlConnLocked()
		c.controlMu.Unlock()
		return nil, E.New("unexpected tunnel handshake: ", string(buf))
	}
	_ = conn.SetDeadline(time.Time{})
	tunnelConn := &bufferedConn{Conn: conn, reader: responseReader}
	c.controlConn = nil
	c.controlReader = nil
	c.controlHost = ""
	c.controlMu.Unlock()
	return tunnelConn, nil
}

func (c *portalClient) chooseGateway(cfg *portalConfig) (*url.URL, error) {
	if cfg == nil || len(cfg.Gateways) == 0 {
		return nil, E.New("globalprotect portal has no gateways")
	}
	selected := cfg.Gateways[0]
	if authGroup := strings.TrimSpace(c.options.AuthGroup); authGroup != "" {
		found := false
		for _, gw := range cfg.Gateways {
			if matchGatewayChoice(gw, authGroup) {
				selected = gw
				found = true
				break
			}
		}
		if !found {
			return nil, E.New("gateway not found: ", authGroup)
		}
	}
	return parseServerURL(selected.Name, c.options.ServerPort)
}

func matchGatewayChoice(choice portalGatewayChoice, authGroup string) bool {
	authGroupLower := strings.ToLower(strings.TrimSpace(authGroup))
	nameLower := strings.ToLower(strings.TrimSpace(choice.Name))
	labelLower := strings.ToLower(strings.TrimSpace(choice.Description))
	if authGroupLower == "" {
		return false
	}
	if nameLower == authGroupLower || labelLower == authGroupLower {
		return true
	}
	return strings.HasPrefix(labelLower, authGroupLower)
}

func (c *portalClient) obtainSession(ctx context.Context, log logger.ContextLogger) (*sessionState, error) {
	if c.baseURL == nil {
		return nil, E.New("missing base URL")
	}
	flow := c.detectFlow()
	switch flow {
	case "gateway":
		return c.obtainGatewaySession(ctx)
	default:
		state, err := c.obtainPortalSession(ctx)
		if err == nil {
			return state, nil
		}
		if !errors.Is(err, errPortalUnavailable) {
			return nil, err
		}
		if log != nil {
			log.Warn("GlobalProtect portal unavailable; falling back to gateway flow: ", err)
		}
		return c.obtainGatewaySession(ctx)
	}
}

func (c *portalClient) detectFlow() string {
	path := strings.ToLower(c.baseURL.Path)
	if strings.Contains(path, "ssl-vpn") || strings.Contains(path, "gateway") {
		return "gateway"
	}
	return "portal"
}

func (c *portalClient) obtainPortalSession(ctx context.Context) (*sessionState, error) {
	form, err := c.prelogin(ctx, true)
	if err != nil {
		return nil, err
	}
	if form.SAMLMethod != "" || form.SAMLRequest != "" || form.InputStr != "" {
		return nil, E.New("unsupported GlobalProtect challenge flow")
	}
	cfg, err := c.portalConfig(ctx, form)
	if err != nil {
		return nil, err
	}
	gatewayURL, err := c.chooseGateway(cfg)
	if err != nil {
		return nil, err
	}
	cookie, err := c.gatewayLogin(ctx, gatewayURL, cfg, form)
	if err != nil {
		return nil, err
	}
	info, tunnelURL, err := c.getConfig(ctx, gatewayURL, cookie, cfg.AppVersion)
	if err != nil {
		return nil, err
	}
	tunnelConfig, err := buildTunnelConfig(info)
	if err != nil {
		return nil, err
	}
	if _, err = c.checkHIP(ctx, gatewayURL, cookie, tunnelConfig); err != nil {
		return nil, err
	}
	state := &sessionState{
		GatewayURL:   gatewayURL,
		Cookie:       cookie,
		TunnelURL:    tunnelURL,
		TunnelConfig: tunnelConfig,
		AppVersion:   cfg.AppVersion,
	}
	c.rememberSession(state)
	return state, nil
}

func (c *portalClient) obtainGatewaySession(ctx context.Context) (*sessionState, error) {
	form, err := c.prelogin(ctx, false)
	if err != nil {
		return nil, err
	}
	if form.SAMLMethod != "" || form.SAMLRequest != "" || form.InputStr != "" {
		return nil, E.New("unsupported GlobalProtect challenge flow")
	}
	cookie, err := c.gatewayLogin(ctx, c.baseURL, nil, form)
	if err != nil {
		return nil, err
	}
	info, tunnelURL, err := c.getConfig(ctx, c.baseURL, cookie, defaultAppVersion)
	if err != nil {
		return nil, err
	}
	tunnelConfig, err := buildTunnelConfig(info)
	if err != nil {
		return nil, err
	}
	if _, err = c.checkHIP(ctx, c.baseURL, cookie, tunnelConfig); err != nil {
		return nil, err
	}
	state := &sessionState{
		GatewayURL:   c.baseURL,
		Cookie:       cookie,
		TunnelURL:    tunnelURL,
		TunnelConfig: tunnelConfig,
		AppVersion:   defaultAppVersion,
	}
	c.rememberSession(state)
	return state, nil
}

func parsePreloginXML(content []byte) (*authForm, error) {
	type preloginXML struct {
		XMLName           xml.Name
		Status            string `xml:"status"`
		Message           string `xml:"msg"`
		Error             string `xml:"error"`
		SAMLMethod        string `xml:"saml-auth-method"`
		SAMLRequest       string `xml:"saml-request"`
		AuthenticationMsg string `xml:"authentication-message"`
		UsernameLabel     string `xml:"username-label"`
		PasswordLabel     string `xml:"password-label"`
	}
	var resp preloginXML
	if err := xml.Unmarshal(content, &resp); err == nil {
		switch resp.XMLName.Local {
		case "prelogin-response":
			status := strings.TrimSpace(resp.Status)
			if status != "" && !strings.EqualFold(status, "success") {
				message := strings.TrimSpace(resp.Message)
				if message == "" {
					message = strings.TrimSpace(resp.Error)
				}
				if message == "" {
					message = "GlobalProtect prelogin failed"
				}
				return nil, classifyPortalError(message)
			}
			return &authForm{
				Prompt:        strings.TrimSpace(resp.AuthenticationMsg),
				UsernameLabel: strings.TrimSpace(resp.UsernameLabel),
				PasswordLabel: strings.TrimSpace(resp.PasswordLabel),
				SAMLMethod:    strings.TrimSpace(resp.SAMLMethod),
				SAMLRequest:   strings.TrimSpace(resp.SAMLRequest),
			}, nil
		case "response":
			message := strings.TrimSpace(resp.Error)
			if message != "" {
				return nil, classifyPortalError(message)
			}
		}
	}
	if form, ok := parseJSChallenge(content); ok {
		return form, nil
	}
	return nil, E.New("failed to parse prelogin response")
}

func parseJSChallenge(content []byte) (*authForm, bool) {
	text := string(content)
	statusMarker := `var respStatus = "`
	statusStart := strings.Index(text, statusMarker)
	if statusStart < 0 {
		return nil, false
	}
	statusStart += len(statusMarker)
	statusEnd := strings.Index(text[statusStart:], `"`)
	if statusEnd < 0 {
		return nil, false
	}
	status := text[statusStart : statusStart+statusEnd]
	promptMarker := `var respMsg = "`
	promptStart := strings.Index(text[statusStart+statusEnd:], promptMarker)
	if promptStart < 0 {
		return nil, false
	}
	promptStart += statusStart + statusEnd + len(promptMarker)
	promptEnd := strings.Index(text[promptStart:], `"`)
	if promptEnd < 0 {
		return nil, false
	}
	prompt := text[promptStart : promptStart+promptEnd]
	inputMarker := `thisForm.inputStr.value = "`
	inputStart := strings.Index(text[promptStart+promptEnd:], inputMarker)
	if inputStart < 0 {
		return nil, false
	}
	inputStart += promptStart + promptEnd + len(inputMarker)
	inputEnd := strings.Index(text[inputStart:], `"`)
	if inputEnd < 0 {
		return nil, false
	}
	form := &authForm{
		Prompt:   strings.TrimSpace(prompt),
		InputStr: text[inputStart : inputStart+inputEnd],
	}
	if strings.HasPrefix(status, "Error") {
		return form, true
	}
	if strings.HasPrefix(status, "Challenge") {
		return form, true
	}
	return nil, false
}

func parseLoginXML(content []byte, localHostname string) (string, error) {
	type loginXML struct {
		ApplicationDesc struct {
			Arguments []string `xml:"argument"`
		} `xml:"application-desc"`
	}
	var resp loginXML
	if err := xml.Unmarshal(content, &resp); err != nil {
		return "", E.Cause(err, "parse login response")
	}
	specs := []struct {
		save  bool
		check string
	}{
		{},
		{save: true},
		{},
		{save: true},
		{save: true},
		{},
		{},
		{save: true},
		{},
		{},
		{},
		{},
		{check: "tunnel"},
		{},
		{check: gpstClientVersion},
		{save: true},
		{},
		{},
		{save: true},
		{},
		{},
	}
	args := resp.ApplicationDesc.Arguments
	if len(args) < len(specs) {
		return "", E.New("unexpected GlobalProtect login response")
	}
	var q queryBuilder
	for i, spec := range specs {
		value := normalizeLoginValue(args[i])
		if spec.check != "" && value != spec.check {
			return "", E.New("unexpected GlobalProtect login argument ", i, ": ", value)
		}
		if spec.save && value != "" {
			if decoded, err := url.QueryUnescape(value); err == nil {
				value = decoded
			}
			q.Add(loginArgName(i), value)
		}
	}
	q.Add("computer", localHostname)
	return q.String(), nil
}

func loginArgName(index int) string {
	switch index {
	case 1:
		return "authcookie"
	case 3:
		return "portal"
	case 4:
		return "user"
	case 7:
		return "domain"
	case 15:
		return "preferred-ip"
	case 18:
		return "preferred-ipv6"
	default:
		return ""
	}
}

func normalizeLoginValue(value string) string {
	value = strings.TrimSpace(value)
	switch value {
	case "", "(null)", "-1":
		return ""
	default:
		return value
	}
}

func parsePortalXML(content []byte) (*portalConfig, error) {
	type gatewayEntry struct {
		Name        string `xml:"name,attr"`
		Description string `xml:"description"`
	}
	type portalPolicyXML struct {
		Version  string `xml:"version"`
		Gateways struct {
			External struct {
				List struct {
					Entries []gatewayEntry `xml:"entry"`
				} `xml:"list"`
			} `xml:"external"`
		} `xml:"gateways"`
		PortalName                   string `xml:"portal-name"`
		PortalUserAuthCookie         string `xml:"portal-userauthcookie"`
		PortalPrelogonUserAuthCookie string `xml:"portal-prelogonuserauthcookie"`
	}
	type portalEnvelopeXML struct {
		XMLName xml.Name
		Status  string          `xml:"status,attr"`
		Error   string          `xml:"error"`
		Policy  portalPolicyXML `xml:"policy"`
	}
	var envelope portalEnvelopeXML
	if err := xml.Unmarshal(content, &envelope); err != nil {
		return nil, E.Cause(err, "parse portal response")
	}
	if strings.EqualFold(strings.TrimSpace(envelope.Status), "error") {
		message := strings.TrimSpace(envelope.Error)
		if message == "" {
			message = "unknown error"
		}
		return nil, E.New("GlobalProtect portal error: ", message)
	}
	policy := envelope.Policy
	if envelope.XMLName.Local == "policy" {
		if err := xml.Unmarshal(content, &policy); err != nil {
			return nil, E.Cause(err, "parse portal policy")
		}
	}
	cfg := &portalConfig{
		Version:                      strings.TrimSpace(policy.Version),
		PortalName:                   strings.TrimSpace(policy.PortalName),
		PortalUserAuthCookie:         strings.TrimSpace(policy.PortalUserAuthCookie),
		PortalPrelogonUserAuthCookie: strings.TrimSpace(policy.PortalPrelogonUserAuthCookie),
	}
	if cfg.Version == "" {
		cfg.Version = defaultAppVersion
	}
	cfg.AppVersion = cfg.Version
	for _, entry := range policy.Gateways.External.List.Entries {
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			continue
		}
		cfg.Gateways = append(cfg.Gateways, portalGatewayChoice{
			Name:        name,
			Description: strings.TrimSpace(entry.Description),
		})
	}
	if len(cfg.Gateways) == 0 {
		return nil, E.New("globalprotect portal has no gateways")
	}
	if cfg.PortalUserAuthCookie == "empty" {
		cfg.PortalUserAuthCookie = ""
	}
	if cfg.PortalPrelogonUserAuthCookie == "empty" {
		cfg.PortalPrelogonUserAuthCookie = ""
	}
	return cfg, nil
}

func parseTunnelXML(content []byte, disableIPv6 bool) (openconnectIPInfo, string, error) {
	type tunnelXML struct {
		Status     string `xml:"status,attr"`
		IPAddress  string `xml:"ip-address"`
		Netmask    string `xml:"netmask"`
		IPAddress6 string `xml:"ip-address-v6"`
		Netmask6   string `xml:"netmask-v6"`
		MTU        int    `xml:"mtu"`
		TunnelURL  string `xml:"ssl-tunnel-url"`
	}
	var resp tunnelXML
	if err := xml.Unmarshal(content, &resp); err != nil {
		return openconnectIPInfo{}, "", E.Cause(err, "parse tunnel response")
	}
	info := openconnectIPInfo{
		Addr:    strings.TrimSpace(resp.IPAddress),
		Netmask: strings.TrimSpace(resp.Netmask),
		MTU:     resp.MTU,
	}
	if !disableIPv6 {
		info.Addr6 = strings.TrimSpace(resp.IPAddress6)
		info.Netmask6 = strings.TrimSpace(resp.Netmask6)
	}
	return info, strings.TrimSpace(resp.TunnelURL), nil
}

func resolveURL(base *url.URL, suffix string) *url.URL {
	next := *base
	next.Path = joinURLPath(base.Path, suffix)
	next.RawQuery = ""
	next.Fragment = ""
	return &next
}

func parseIPVersion(addr string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}
