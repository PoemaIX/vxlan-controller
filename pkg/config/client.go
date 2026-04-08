package config

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"vxlan-controller/pkg/filter"
	"vxlan-controller/pkg/types"

	"gopkg.in/yaml.v3"
)

type ClientConfigFile struct {
	PrivateKey        string                          `yaml:"private_key"`
	PublicKey         string                          `yaml:"public_key,omitempty"`
	BridgeName        string                          `yaml:"bridge_name"`
	ClampMSSToMTU      bool                            `yaml:"clamp_mss_to_mtu"`
	ClampMSSTable      string                          `yaml:"clamp_mss_table"`
	NeighSuppress     bool                            `yaml:"neigh_suppress"`
	VxlanFirewall      bool                            `yaml:"vxlan_firewall"`
	VxlanFirewallTable string                          `yaml:"vxlan_firewall_table"`
	AFSettings        map[string]*ClientAFConfigFile   `yaml:"address_families"`
	InitTimeout       int                             `yaml:"init_timeout"`
	StatsIntervalS    int                             `yaml:"stats_interval_s"`
	NTPServers        []string                        `yaml:"ntp_servers"`
	NTPPeriodH        int                             `yaml:"ntp_period_h"`
	NTPRTTThresholdMs int                             `yaml:"ntp_rtt_threshold_ms"`
	Filters           *filter.FilterConfigFile         `yaml:"filters"`
	LogLevel          string                          `yaml:"log_level"`
	APISocket         string                          `yaml:"api_socket"`
}

type ClientAFConfigFile struct {
	Enable               bool                            `yaml:"enable"`
	BindAddr             string                          `yaml:"bind_addr"`
	AutoIPInterface  string                          `yaml:"autoip_interface"`
	AddrSelect           string                          `yaml:"addr_select"`
	ProbePort            uint16                          `yaml:"probe_port"`
	CommunicationPort    uint16                          `yaml:"communication_port"`
	VxlanName            string                          `yaml:"vxlan_name"`
	VxlanVNI             uint32                          `yaml:"vxlan_vni"`
	VxlanMTU             int                             `yaml:"vxlan_mtu"`
	VxlanDstPort         uint16                          `yaml:"vxlan_dst_port"`
	VxlanSrcPortStart    uint16                          `yaml:"vxlan_src_port_start"`
	VxlanSrcPortEnd      uint16                          `yaml:"vxlan_src_port_end"`
	Priority             int                             `yaml:"priority"`
	AdditionalCost       float64                         `yaml:"additional_cost"`
	Controllers          []ControllerEndpointFile        `yaml:"controllers"`
}

type ControllerEndpointFile struct {
	PubKey string `yaml:"pubkey"`
	Addr   string `yaml:"addr"`
}

// ClientConfig is the parsed client configuration.
type ClientConfig struct {
	PrivateKey       [32]byte
	BridgeName       string
	ClampMSSToMTU    bool
	ClampMSSTable    string
	NeighSuppress    bool
	VxlanFirewall      bool
	VxlanFirewallTable string
	AFSettings       map[types.AFName]*ClientAFConfig
	InitTimeout      time.Duration
	StatsInterval    time.Duration
	NTPServers       []string
	NTPPeriod        time.Duration
	NTPRTTThreshold  time.Duration
	Filters          *filter.FilterConfig
	LogLevel         string
	APISocket        string
}

type ClientAFConfig struct {
	Name                types.AFName
	Enable              bool
	BindAddr            netip.Addr
	AutoIPInterface string
	AddrSelectScript    string // resolved Lua code for addr selection
	ProbePort           uint16
	CommunicationPort   uint16
	VxlanName           string
	VxlanVNI            uint32
	VxlanMTU            int
	VxlanDstPort        uint16
	VxlanSrcPortStart   uint16
	VxlanSrcPortEnd     uint16
	Priority            int
	AdditionalCost      float64
	Controllers         []ControllerEndpoint
}

type ControllerEndpoint struct {
	PubKey [32]byte
	Addr   netip.AddrPort
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	configDir := filepath.Dir(path)

	// Start from defaults, then overlay user config
	raw := DefaultClientConfig
	raw.AFSettings = nil // clear so user must specify
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	cfg := &ClientConfig{
		BridgeName:         raw.BridgeName,
		ClampMSSToMTU:      raw.ClampMSSToMTU,
		ClampMSSTable:      raw.ClampMSSTable,
		NeighSuppress:      raw.NeighSuppress,
		VxlanFirewall:      raw.VxlanFirewall,
		VxlanFirewallTable: raw.VxlanFirewallTable,
		NTPServers:         raw.NTPServers,
		InitTimeout:        time.Duration(raw.InitTimeout) * time.Second,
		StatsInterval:      time.Duration(raw.StatsIntervalS) * time.Second,
		NTPPeriod:          time.Duration(raw.NTPPeriodH) * time.Hour,
		NTPRTTThreshold:    time.Duration(raw.NTPRTTThresholdMs) * time.Millisecond,
		Filters:            filter.ParseFilterConfigFile(raw.Filters, configDir),
		LogLevel:           raw.LogLevel,
		APISocket:          raw.APISocket,
	}

	// Parse private key
	keyBytes, err := base64.StdEncoding.DecodeString(raw.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private_key base64: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("private_key must be 32 bytes, got %d", len(keyBytes))
	}
	copy(cfg.PrivateKey[:], keyBytes)

	// Parse AF settings
	cfg.AFSettings = make(map[types.AFName]*ClientAFConfig)
	for name, afRaw := range raw.AFSettings {
		afName := types.AFName(name)
		af := &ClientAFConfig{
			Name:              afName,
			Enable:            afRaw.Enable,
			ProbePort:         afRaw.ProbePort,
			CommunicationPort: afRaw.CommunicationPort,
			VxlanName:         afRaw.VxlanName,
			VxlanVNI:          afRaw.VxlanVNI,
			VxlanMTU:          afRaw.VxlanMTU,
			VxlanDstPort:      afRaw.VxlanDstPort,
			VxlanSrcPortStart: afRaw.VxlanSrcPortStart,
			VxlanSrcPortEnd:   afRaw.VxlanSrcPortEnd,
			Priority:          afRaw.Priority,
			AdditionalCost:    afRaw.AdditionalCost,
		}

		hasBindAddr := afRaw.BindAddr != ""
		hasAutoDetect := afRaw.AutoIPInterface != ""

		if hasBindAddr && hasAutoDetect {
			return nil, fmt.Errorf("af %s: bind_addr and autoip_interface are mutually exclusive", name)
		}
		if !hasBindAddr && !hasAutoDetect {
			return nil, fmt.Errorf("af %s: either bind_addr or autoip_interface must be set", name)
		}

		if hasAutoDetect {
			af.AutoIPInterface = afRaw.AutoIPInterface
			script, err := resolveAddrSelect(afRaw.AddrSelect, name)
			if err != nil {
				return nil, fmt.Errorf("af %s: %w", name, err)
			}
			af.AddrSelectScript = script
			// BindAddr left as zero value; resolved at startup by addrWatchLoop
		} else {
			af.BindAddr, err = netip.ParseAddr(afRaw.BindAddr)
			if err != nil {
				return nil, fmt.Errorf("af %s: invalid bind_addr: %w", name, err)
			}
		}

		for _, ctrl := range afRaw.Controllers {
			ce := ControllerEndpoint{}
			pubBytes, err := base64.StdEncoding.DecodeString(ctrl.PubKey)
			if err != nil {
				return nil, fmt.Errorf("af %s: invalid controller pubkey: %w", name, err)
			}
			if len(pubBytes) != 32 {
				return nil, fmt.Errorf("af %s: controller pubkey must be 32 bytes", name)
			}
			copy(ce.PubKey[:], pubBytes)

			ce.Addr, err = netip.ParseAddrPort(ctrl.Addr)
			if err != nil {
				return nil, fmt.Errorf("af %s: invalid controller addr: %w", name, err)
			}

			af.Controllers = append(af.Controllers, ce)
		}

		cfg.AFSettings[afName] = af
	}

	return cfg, nil
}
