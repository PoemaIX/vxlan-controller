package config

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vxlan-controller/pkg/filter"
	"vxlan-controller/pkg/types"

	"gopkg.in/yaml.v3"
)

type ControllerConfigFile struct {
	PrivateKey             string                              `yaml:"private_key"`
	PublicKey              string                              `yaml:"public_key,omitempty"`
	AFSettings             map[string]*ControllerAFConfigFile  `yaml:"address_families"`
	ClientOfflineTimeout   int                                 `yaml:"client_offline_timeout"`
	SyncNewClientDebounce  int                                 `yaml:"sync_new_client_debounce"`
	SyncNewClientDebounceMax int                               `yaml:"sync_new_client_debounce_max"`
	TopologyUpdateDebounce int                                 `yaml:"topology_update_debounce"`
	TopologyUpdateDebounceMax int                              `yaml:"topology_update_debounce_max"`
	Probing                ProbingConfigFile                   `yaml:"probing"`
	AllowedClients         []PerClientConfigFile               `yaml:"allowed_clients"`
	LogLevel               string                             `yaml:"log_level"`
	WebUI                  *WebUIConfigFile                    `yaml:"web_ui"`
	CostMode               string                             `yaml:"cost_mode"`
	StaticCosts            map[string]map[string]map[string]float64 `yaml:"static_costs"`
	APISocket              string                             `yaml:"api_socket"`
}

type WebUIConfigFile struct {
	BindAddr   string                       `yaml:"bind_addr"`
	MacAliases map[string]string            `yaml:"mac_aliases"`
	Nodes      map[string]*WebUINodeFile    `yaml:"nodes"`
}

type WebUINodeFile struct {
	Label string     `yaml:"label"`
	Pos   [2]float64 `yaml:"pos"`
}

type ControllerAFConfigFile struct {
	Enable            bool   `yaml:"enable"`
	BindAddr          string `yaml:"bind_addr"`
	AutoIPInterface   string `yaml:"autoip_interface"`
	AddrSelect        string `yaml:"addr_select"`
	AddrSelectFile    string `yaml:"addr_select_file"`
	CommunicationPort uint16 `yaml:"communication_port"`
	VxlanVNI          uint32 `yaml:"vxlan_vni"`
	VxlanDstPort      uint16 `yaml:"vxlan_dst_port"`
	VxlanSrcPortStart uint16 `yaml:"vxlan_src_port_start"`
	VxlanSrcPortEnd   uint16 `yaml:"vxlan_src_port_end"`
}

type ProbingConfigFile struct {
	ProbeIntervalS    int `yaml:"probe_interval_s"`
	ProbeTimes        int `yaml:"probe_times"`
	InProbeIntervalMs int `yaml:"in_probe_interval_ms"`
	ProbeTimeoutMs    int `yaml:"probe_timeout_ms"`
}

type PerClientConfigFile struct {
	ClientID   string                   `yaml:"client_id"`
	ClientName string                   `yaml:"client_name"`
	Filters    *filter.FilterConfigFile `yaml:"filters"`
}

// ControllerConfig is the parsed controller configuration.
type ControllerConfig struct {
	PrivateKey                [32]byte
	AFSettings                map[types.AFName]*ControllerAFConfig
	ClientOfflineTimeout      time.Duration
	SyncNewClientDebounce     time.Duration
	SyncNewClientDebounceMax  time.Duration
	TopologyUpdateDebounce    time.Duration
	TopologyUpdateDebounceMax time.Duration
	Probing                   ProbingConfig
	AllowedClients            []types.PerClientConfig
	LogLevel                  string
	WebUI                     *WebUIConfig
	CostMode                  string // "probe" or "static"
	StaticCosts               map[string]map[string]map[types.AFName]float64 // [src_name][dst_name][af]cost
	APISocket                 string
	ConfigPath                string // path to config file (for write-back)
}

type WebUIConfig struct {
	BindAddr   string
	MacAliases map[string]string
	Nodes      map[string]*WebUINode
}

type WebUINode struct {
	Label string
	Pos   [2]float64
}

type ControllerAFConfig struct {
	Name              types.AFName
	Enable            bool
	BindAddr          netip.Addr
	AutoIPInterface   string
	AddrSelectScript  string // resolved Lua code for addr selection
	CommunicationPort uint16
	VxlanVNI          uint32
	VxlanDstPort      uint16
	VxlanSrcPortStart uint16
	VxlanSrcPortEnd   uint16
}

type ProbingConfig struct {
	ProbeIntervalS    int
	ProbeTimes        int
	InProbeIntervalMs int
	ProbeTimeoutMs    int
}

func LoadControllerConfig(path string) (*ControllerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	configDir := filepath.Dir(path)

	// Start from defaults, then overlay user config
	raw := DefaultControllerConfig
	raw.AFSettings = nil      // clear so user must specify
	raw.AllowedClients = nil  // clear so user must specify
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	cfg := &ControllerConfig{
		ClientOfflineTimeout:      time.Duration(raw.ClientOfflineTimeout) * time.Second,
		SyncNewClientDebounce:     time.Duration(raw.SyncNewClientDebounce) * time.Second,
		SyncNewClientDebounceMax:  time.Duration(raw.SyncNewClientDebounceMax) * time.Second,
		TopologyUpdateDebounce:    time.Duration(raw.TopologyUpdateDebounce) * time.Second,
		TopologyUpdateDebounceMax: time.Duration(raw.TopologyUpdateDebounceMax) * time.Second,
		LogLevel:                  raw.LogLevel,
		Probing: ProbingConfig{
			ProbeIntervalS:    raw.Probing.ProbeIntervalS,
			ProbeTimes:        raw.Probing.ProbeTimes,
			InProbeIntervalMs: raw.Probing.InProbeIntervalMs,
			ProbeTimeoutMs:    raw.Probing.ProbeTimeoutMs,
		},
	}

	// CostMode
	cfg.CostMode = raw.CostMode
	if cfg.CostMode != "probe" && cfg.CostMode != "static" {
		return nil, fmt.Errorf("invalid cost_mode %q (must be probe or static)", cfg.CostMode)
	}

	cfg.APISocket = raw.APISocket
	cfg.ConfigPath = path

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
	cfg.AFSettings = make(map[types.AFName]*ControllerAFConfig)
	for name, afRaw := range raw.AFSettings {
		afName := types.AFName(name)
		af := &ControllerAFConfig{
			Name:              afName,
			Enable:            afRaw.Enable,
			CommunicationPort: afRaw.CommunicationPort,
			VxlanVNI:          afRaw.VxlanVNI,
			VxlanDstPort:      afRaw.VxlanDstPort,
			VxlanSrcPortStart: afRaw.VxlanSrcPortStart,
			VxlanSrcPortEnd:   afRaw.VxlanSrcPortEnd,
		}

		hasBindAddr := afRaw.BindAddr != ""
		hasAutoIP := afRaw.AutoIPInterface != ""

		if hasBindAddr && hasAutoIP {
			return nil, fmt.Errorf("af %s: bind_addr and autoip_interface are mutually exclusive", name)
		}
		if !hasBindAddr && !hasAutoIP {
			return nil, fmt.Errorf("af %s: either bind_addr or autoip_interface must be set", name)
		}

		if hasAutoIP {
			af.AutoIPInterface = afRaw.AutoIPInterface
			if afRaw.AddrSelect != "" {
				af.AddrSelectScript = afRaw.AddrSelect
			} else if afRaw.AddrSelectFile != "" {
				data, err := os.ReadFile(afRaw.AddrSelectFile)
				if err != nil {
					return nil, fmt.Errorf("af %s: read addr_select_file: %w", name, err)
				}
				af.AddrSelectScript = string(data)
			} else {
				if strings.Contains(strings.ToLower(name), "v6") || strings.Contains(strings.ToLower(name), "ipv6") {
					af.AddrSelectScript = filter.DefaultAddrSelectV6
				} else {
					af.AddrSelectScript = filter.DefaultAddrSelectV4
				}
			}
		} else {
			af.BindAddr, err = netip.ParseAddr(afRaw.BindAddr)
			if err != nil {
				return nil, fmt.Errorf("af %s: invalid bind_addr: %w", name, err)
			}
		}

		cfg.AFSettings[afName] = af
	}

	// Parse allowed clients
	for _, clientRaw := range raw.AllowedClients {
		pc := types.PerClientConfig{
			ClientName: clientRaw.ClientName,
			Filters:    filter.ParseFilterConfigFile(clientRaw.Filters, configDir),
		}

		pubBytes, err := base64.StdEncoding.DecodeString(clientRaw.ClientID)
		if err != nil {
			return nil, fmt.Errorf("client %s: invalid client_id base64: %w", clientRaw.ClientName, err)
		}
		if len(pubBytes) != 32 {
			return nil, fmt.Errorf("client %s: client_id must be 32 bytes", clientRaw.ClientName)
		}
		copy(pc.ClientID[:], pubBytes)

		cfg.AllowedClients = append(cfg.AllowedClients, pc)
	}

	// Parse static costs (name-indexed -> name-indexed with AFName keys)
	if len(raw.StaticCosts) > 0 {
		// Build name set for validation
		nameSet := make(map[string]bool)
		for _, pc := range cfg.AllowedClients {
			nameSet[pc.ClientName] = true
		}
		cfg.StaticCosts = make(map[string]map[string]map[types.AFName]float64)
		for src, dsts := range raw.StaticCosts {
			if !nameSet[src] {
				return nil, fmt.Errorf("static_costs: unknown client name %q", src)
			}
			cfg.StaticCosts[src] = make(map[string]map[types.AFName]float64)
			for dst, afs := range dsts {
				if !nameSet[dst] {
					return nil, fmt.Errorf("static_costs: unknown client name %q", dst)
				}
				cfg.StaticCosts[src][dst] = make(map[types.AFName]float64)
				for af, cost := range afs {
					cfg.StaticCosts[src][dst][types.AFName(af)] = cost
				}
			}
		}
	}

	// Parse WebUI config
	if raw.WebUI != nil && raw.WebUI.BindAddr != "" {
		wui := &WebUIConfig{
			BindAddr:   raw.WebUI.BindAddr,
			MacAliases: raw.WebUI.MacAliases,
		}
		if len(raw.WebUI.Nodes) > 0 {
			wui.Nodes = make(map[string]*WebUINode, len(raw.WebUI.Nodes))
			for name, n := range raw.WebUI.Nodes {
				wui.Nodes[name] = &WebUINode{
					Label: n.Label,
					Pos:   n.Pos,
				}
			}
		}
		cfg.WebUI = wui
	}

	return cfg, nil
}
