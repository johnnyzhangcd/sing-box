package include

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestEndpointRegistryIncludesGlobalProtect(t *testing.T) {
	registry := EndpointRegistry()
	options, loaded := registry.CreateOptions(C.TypeGlobalProtect)
	if !loaded {
		t.Fatal("globalprotect endpoint type is not registered")
	}
	if _, ok := options.(*option.GlobalProtectEndpointOptions); !ok {
		t.Fatalf("unexpected options type: %T", options)
	}
}
