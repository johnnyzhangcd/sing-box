package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

type GlobalProtectEndpointOptions struct {
	DialerOptions
	ServerOptions
	Username            string             `json:"username"`
	Password            string             `json:"password"`
	AuthGroup           string             `json:"auth_group,omitempty"`
	ServerCert          string             `json:"server_cert,omitempty"`
	CAFile              string             `json:"ca_file,omitempty"`
	NoSystemTrust       bool               `json:"no_system_trust,omitempty"`
	SNI                 string             `json:"sni,omitempty"`
	LocalHostname       string             `json:"local_hostname,omitempty"`
	ReportedOS          string             `json:"reported_os,omitempty"`
	DisableIPv6         bool               `json:"disable_ipv6,omitempty"`
	DisableDTLS         bool               `json:"disable_dtls,omitempty"`
	Proxy               string             `json:"proxy,omitempty"`
	AllowInsecureCrypto bool               `json:"allow_insecure_crypto,omitempty"`
	PFS                 bool               `json:"pfs,omitempty"`
	WaitForReady        bool               `json:"wait_for_ready,omitempty"`
	ReconnectTimeout    badoption.Duration `json:"reconnect_timeout,omitempty"`
}
