package globalprotect

import (
	"crypto/md5"
	"encoding/hex"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
)

const (
	gpstClientVersion = "4100"
	defaultAppVersion = "6.3.0-33"
)

type authForm struct {
	Prompt        string
	UsernameLabel string
	PasswordLabel string
	SAMLMethod    string
	SAMLRequest   string
	InputStr      string
}

type portalGatewayChoice struct {
	Name        string
	Description string
}

type portalConfig struct {
	Version                      string
	PortalName                   string
	PortalUserAuthCookie         string
	PortalPrelogonUserAuthCookie string
	Gateways                     []portalGatewayChoice
	AppVersion                   string
}

type queryBuilder struct {
	b strings.Builder
}

func (q *queryBuilder) Add(key, value string) {
	if value == "" {
		return
	}
	if q.b.Len() > 0 {
		q.b.WriteByte('&')
	}
	q.b.WriteString(url.QueryEscape(key))
	q.b.WriteByte('=')
	q.b.WriteString(url.QueryEscape(value))
}

func (q *queryBuilder) AddRaw(value string) {
	if value == "" {
		return
	}
	if q.b.Len() > 0 {
		q.b.WriteByte('&')
	}
	q.b.WriteString(value)
}

func (q *queryBuilder) String() string {
	return q.b.String()
}

func gpstClientOS(reported string) string {
	switch strings.ToLower(strings.TrimSpace(reported)) {
	case "mac-intel":
		return "Mac"
	case "apple-ios":
		return "iOS"
	case "android":
		return "Android"
	case "linux-64", "linux":
		return "Linux"
	default:
		return "Windows"
	}
}

func gpstPlatformName(reported string) string {
	reported = strings.TrimSpace(reported)
	if reported != "" {
		return reported
	}
	switch runtime.GOOS {
	case "darwin":
		return "mac-intel"
	case "windows":
		return "win"
	case "android":
		return "android"
	default:
		if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
			return "linux-64"
		}
		return "linux"
	}
}

func buildPreloginQuery(reportedOS string) url.Values {
	query := url.Values{}
	query.Set("tmp", "tmp")
	query.Set("clientVer", gpstClientVersion)
	query.Set("clientos", gpstClientOS(reportedOS))
	return query
}

func buildPreloginBody() string {
	var q queryBuilder
	q.Add("cas-support", "yes")
	return q.String()
}

func buildLoginBody(username, password string, portalCfg *portalConfig, serverHost, localHostname, reportedOS string, disableIPv6 bool, inputStr string) string {
	var q queryBuilder
	q.Add("jnlpReady", "jnlpReady")
	q.Add("ok", "Login")
	q.Add("direct", "yes")
	q.Add("clientVer", gpstClientVersion)
	q.Add("prot", "https:")
	q.Add("internal", "no")
	if disableIPv6 {
		q.Add("ipv6-support", "no")
	} else {
		q.Add("ipv6-support", "yes")
	}
	q.Add("clientos", gpstClientOS(reportedOS))
	q.Add("os-version", gpstPlatformName(reportedOS))
	q.Add("server", serverHost)
	q.Add("computer", localHostname)
	if portalCfg != nil {
		q.Add("portal-userauthcookie", portalCfg.PortalUserAuthCookie)
		q.Add("portal-prelogonuserauthcookie", portalCfg.PortalPrelogonUserAuthCookie)
	}
	if inputStr != "" {
		q.Add("inputStr", inputStr)
	}
	q.Add("user", username)
	q.Add("passwd", password)
	return q.String()
}

func buildGetConfigBody(cookie, appVersion, reportedOS string, disableIPv6 bool) string {
	if appVersion == "" {
		appVersion = defaultAppVersion
	}
	var q queryBuilder
	q.Add("client-type", "1")
	q.Add("protocol-version", "p1")
	q.Add("internal", "no")
	q.Add("app-version", appVersion)
	if disableIPv6 {
		q.Add("ipv6-support", "no")
	} else {
		q.Add("ipv6-support", "yes")
	}
	q.Add("clientos", gpstClientOS(reportedOS))
	q.Add("os-version", gpstPlatformName(reportedOS))
	q.Add("hmac-algo", "sha1,md5,sha256")
	q.Add("enc-algo", "aes-128-cbc,aes-256-cbc")
	q.AddRaw(cookie)
	return q.String()
}

func buildTunnelQuery(cookie string) string {
	var q queryBuilder
	for _, part := range strings.Split(cookie, "&") {
		if part == "" {
			continue
		}
		key, _, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch key {
		case "user", "authcookie":
			q.AddRaw(part)
		}
	}
	return q.String()
}

func buildHIPCheckBody(cookie string, prefixes []netip.Prefix) string {
	var q queryBuilder
	q.Add("client-role", "global-protect-full")
	q.AddRaw(cookie)
	for _, prefix := range prefixes {
		address := prefix.Addr()
		switch {
		case address.Is4():
			q.Add("client-ip", address.String())
		case address.Is6():
			q.Add("client-ipv6", address.String())
		}
	}
	filteredCookie := filterCookieOptions(cookie, "authcookie", "preferred-ip", "preferred-ipv6")
	digest := md5.Sum([]byte(filteredCookie))
	q.Add("md5", hex.EncodeToString(digest[:]))
	return q.String()
}

func filterCookieOptions(cookie string, excluded ...string) string {
	exclude := make(map[string]struct{}, len(excluded))
	for _, key := range excluded {
		exclude[key] = struct{}{}
	}
	var q queryBuilder
	for _, part := range strings.Split(cookie, "&") {
		key, _, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if _, exists := exclude[key]; exists {
			continue
		}
		q.AddRaw(part)
	}
	return q.String()
}
