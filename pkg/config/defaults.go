package config

import (
	"net/netip"
	"os"
	"strings"
	"time"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/filter"
	"vxlan-controller/pkg/types"
)

// resolveAddrSelect resolves an addr_select value to Lua script content.
// If the value is a path to an existing file, the file content is read.
// Otherwise the value is treated as inline Lua code.
// If empty, a default script is chosen based on the AF name.
func resolveAddrSelect(addrSelect, afName string) (string, error) {
	if addrSelect == "" {
		if strings.Contains(strings.ToLower(afName), "v6") || strings.Contains(strings.ToLower(afName), "ipv6") {
			return filter.DefaultAddrSelectV6, nil
		}
		return filter.DefaultAddrSelectV4, nil
	}

	// Try as file path
	if data, err := os.ReadFile(addrSelect); err == nil {
		return string(data), nil
	}

	// Treat as inline Lua
	return addrSelect, nil
}

func DefaultClientConfigYAML() ([]byte, error) {
	cfg := cloneClientConfig(&DefaultClientConfig)
	priv, pub := crypto.GenerateKeyPair()
	cfg.PrivateKey = priv

	// Add placeholder controllers for the generated YAML
	for _, af := range cfg.AFSettings {
		af.Controllers = []ControllerEndpoint{
			{PubKey: pub, Addr: placeholderAddrPort(af.BindAddr)},
		}
	}

	return MarshalClientConfig(cfg)
}

func DefaultControllerConfigYAML() ([]byte, error) {
	cfg := cloneControllerConfig(&DefaultControllerConfig)
	priv, pub := crypto.GenerateKeyPair()
	cfg.PrivateKey = priv

	cfg.AllowedClients = []types.PerClientConfig{
		{ClientID: types.ClientID(pub), ClientName: "node-1"},
	}

	cfg.WebUI = &WebUIConfig{
		Title: "<b>VXLAN</b> Controller",
	}

	return MarshalControllerConfig(cfg)
}

func placeholderAddrPort(bindAddr netip.Addr) netip.AddrPort {
	if bindAddr.Is6() {
		return netip.MustParseAddrPort("[fd00::1]:5000")
	}
	return netip.MustParseAddrPort("192.168.1.1:5000")
}

var DefaultNTPServers = []string{
	"time.cloudflare.com",
	"time.google.com",
	"time.apple.com",
	"pool.ntp.org",
	"0.pool.ntp.org",
	"1.pool.ntp.org",
	"2.pool.ntp.org",
	"3.pool.ntp.org",
	"ntp.ubuntu.com",
}

const (
	DefaultControllerSocket = "/var/run/vxlan-controller.sock"
	DefaultClientSocket     = "/var/run/vxlan-client.sock"
)

var DefaultClientConfig = ClientConfig{
	BridgeName:         "br-vxlan",
	ClampMSSToMTU:      false,
	ClampMSSTable:      "vxlan_mss",
	NeighSuppress:      false,
	VxlanFirewall:      false,
	VxlanFirewallTable: "vxlan_fw",
	InitTimeout:        10 * time.Second,
	StatsInterval:      5 * time.Second,
	ProbeWindowSize:    15,
	AFSwitchCost:       20,
	NTPServers:         DefaultNTPServers,
	NTPPeriod:          23 * time.Hour,
	NTPRTTThreshold:    50 * time.Millisecond,
	SyncCheckMaxDelay:  20,
	SyncCheckInterval:  60 * time.Second,
	AFSettings: map[types.AFName]*ClientAFConfig{
		"v4": {
			Enable:            true,
			BindAddr:          netip.MustParseAddr("0.0.0.0"),
			ProbePort:         4790,
			VxlanName:         "vxlan-v4",
			VxlanVNI:          100,
			VxlanMTU:          1400,
			VxlanDstPort:      4789,
			VxlanSrcPortStart: 4789,
			VxlanSrcPortEnd:   4790,
			Priority:          10,
			ForwardCost:       20,
		},
		"v6": {
			Enable:            false,
			BindAddr:          netip.MustParseAddr("::"),
			ProbePort:         4790,
			VxlanName:         "vxlan-v6",
			VxlanVNI:          100,
			VxlanMTU:          1400,
			VxlanDstPort:      4789,
			VxlanSrcPortStart: 4789,
			VxlanSrcPortEnd:   4790,
			Priority:          10,
			ForwardCost:       20,
		},
	},
}

var DefaultControllerConfig = ControllerConfig{
	CostMode:                  "probe",
	ClientOfflineTimeout:      30 * time.Second,
	SyncNewClientDebounce:     3 * time.Second,
	SyncNewClientDebounceMax:  10 * time.Second,
	TopologyUpdateDebounce:    3 * time.Second,
	TopologyUpdateDebounceMax: 7 * time.Second,
	Probing: ProbingConfig{
		ProbeIntervalS:    5,
		ProbeTimes:        5,
		InProbeIntervalMs: 200,
		ProbeTimeoutMs:    1000,
	},
	AFSettings: map[types.AFName]*ControllerAFConfig{
		"v4": {
			Enable:            true,
			BindAddr:          netip.MustParseAddr("0.0.0.0"),
			CommunicationPort: 5000,
			VxlanVNI:          100,
			VxlanDstPort:      4789,
			VxlanSrcPortStart: 4789,
			VxlanSrcPortEnd:   4789,
		},
		"v6": {
			Enable:            false,
			BindAddr:          netip.MustParseAddr("::"),
			CommunicationPort: 5000,
			VxlanVNI:          100,
			VxlanDstPort:      4789,
			VxlanSrcPortStart: 4789,
			VxlanSrcPortEnd:   4789,
		},
	},
}
