//go:build with_globalprotect && with_gvisor

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/globalprotect"
)

func registerGlobalProtectEndpoint(registry *endpoint.Registry) {
	globalprotect.RegisterEndpoint(registry)
}
