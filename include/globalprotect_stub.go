//go:build !with_globalprotect || !with_gvisor

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerGlobalProtectEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.GlobalProtectEndpointOptions](registry, C.TypeGlobalProtect, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.GlobalProtectEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New("GlobalProtect requires -tags with_globalprotect,with_gvisor")
	})
}
