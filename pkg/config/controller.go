package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"vxlan-controller/pkg/filter"
	"vxlan-controller/pkg/types"

	"gopkg.in/yaml.v3"
)

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
	BindAddr   string                `yaml:"bind_addr"`
	Title      string                `yaml:"title"`
	URL        string                `yaml:"url"`
	MacAliases map[string]string     `yaml:"mac_aliases"`
	Nodes      map[string]*WebUINode `yaml:"nodes"`
}

type WebUINode struct {
	Label string     `yaml:"label"`
	Pos   [2]float64 `yaml:"pos"`
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
	ProbeIntervalS    int `yaml:"probe_interval_s"`
	ProbeTimes        int `yaml:"probe_times"`
	InProbeIntervalMs int `yaml:"in_probe_interval_ms"`
	ProbeTimeoutMs    int `yaml:"probe_timeout_ms"`
}

func LoadControllerConfig(path string) (*ControllerConfig, []DefaultApplied, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	configDir := filepath.Dir(path)

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse yaml: %w", err)
	}

	m := nodeMap(&doc)
	if m == nil {
		return nil, nil, fmt.Errorf("config must be a YAML mapping")
	}

	dt := newDefaultTracker()
	cfg := cloneControllerConfig(&DefaultControllerConfig)
	cfg.AFSettings = nil
	cfg.AllowedClients = nil
	cfg.ConfigPath = path

	// Scalar fields
	if err := trackedSet(&cfg.LogLevel, m, "log_level", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.CostMode, m, "cost_mode", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.APISocket, m, "api_socket", dt); err != nil {
		return nil, nil, err
	}

	if cfg.CostMode != "probe" && cfg.CostMode != "static" {
		return nil, nil, fmt.Errorf("invalid cost_mode %q (must be probe or static)", cfg.CostMode)
	}

	// Duration fields
	if err := trackedSetDuration(&cfg.ClientOfflineTimeout, m, "client_offline_timeout", time.Second, dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSetDuration(&cfg.SyncNewClientDebounce, m, "sync_new_client_debounce", time.Second, dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSetDuration(&cfg.SyncNewClientDebounceMax, m, "sync_new_client_debounce_max", time.Second, dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSetDuration(&cfg.TopologyUpdateDebounce, m, "topology_update_debounce", time.Second, dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSetDuration(&cfg.TopologyUpdateDebounceMax, m, "topology_update_debounce_max", time.Second, dt); err != nil {
		return nil, nil, err
	}

	// Probing (simple struct — track individual fields)
	probDt := dt.sub("probing")
	if n, ok := m["probing"]; ok {
		pm := nodeMap(n)
		if err := trackedSet(&cfg.Probing.ProbeIntervalS, pm, "probe_interval_s", probDt); err != nil {
			return nil, nil, err
		}
		if err := trackedSet(&cfg.Probing.ProbeTimes, pm, "probe_times", probDt); err != nil {
			return nil, nil, err
		}
		if err := trackedSet(&cfg.Probing.InProbeIntervalMs, pm, "in_probe_interval_ms", probDt); err != nil {
			return nil, nil, err
		}
		if err := trackedSet(&cfg.Probing.ProbeTimeoutMs, pm, "probe_timeout_ms", probDt); err != nil {
			return nil, nil, err
		}
	} else {
		probDt.record("probe_interval_s", cfg.Probing.ProbeIntervalS)
		probDt.record("probe_times", cfg.Probing.ProbeTimes)
		probDt.record("in_probe_interval_ms", cfg.Probing.InProbeIntervalMs)
		probDt.record("probe_timeout_ms", cfg.Probing.ProbeTimeoutMs)
	}

	// Private key (not tracked — required field)
	if err := nodeSetBase64Key32(&cfg.PrivateKey, m, "private_key"); err != nil {
		return nil, nil, err
	}

	// AF settings
	if afNode, ok := m["address_families"]; ok {
		cfg.AFSettings = make(map[types.AFName]*ControllerAFConfig)
		afMap := nodeMap(afNode)
		for name, afValueNode := range afMap {
			afDt := dt.sub("address_families." + name)
			af, err := overlayControllerAF(name, afValueNode, afDt)
			if err != nil {
				return nil, nil, fmt.Errorf("af %s: %w", name, err)
			}
			cfg.AFSettings[types.AFName(name)] = af
		}
	}

	// Allowed clients (not tracked — required field)
	if clientsNode, ok := m["allowed_clients"]; ok && clientsNode.Kind == yaml.SequenceNode {
		for _, cNode := range clientsNode.Content {
			pc, err := decodePerClient(cNode, configDir)
			if err != nil {
				return nil, nil, err
			}
			cfg.AllowedClients = append(cfg.AllowedClients, pc)
		}
	}

	// Static costs
	if costsNode, ok := m["static_costs"]; ok {
		var rawCosts map[string]map[string]map[string]float64
		if err := costsNode.Decode(&rawCosts); err != nil {
			return nil, nil, fmt.Errorf("static_costs: %w", err)
		}

		nameSet := make(map[string]bool)
		for _, pc := range cfg.AllowedClients {
			nameSet[pc.ClientName] = true
		}

		cfg.StaticCosts = make(map[string]map[string]map[types.AFName]float64)
		for src, dsts := range rawCosts {
			if !nameSet[src] {
				return nil, nil, fmt.Errorf("static_costs: unknown client name %q", src)
			}
			cfg.StaticCosts[src] = make(map[string]map[types.AFName]float64)
			for dst, afs := range dsts {
				if !nameSet[dst] {
					return nil, nil, fmt.Errorf("static_costs: unknown client name %q", dst)
				}
				cfg.StaticCosts[src][dst] = make(map[types.AFName]float64)
				for af, cost := range afs {
					cfg.StaticCosts[src][dst][types.AFName(af)] = cost
				}
			}
		}
	}

	// WebUI
	if wNode, ok := m["web_ui"]; ok {
		var wui WebUIConfig
		if err := wNode.Decode(&wui); err != nil {
			return nil, nil, fmt.Errorf("web_ui: %w", err)
		}
		if wui.BindAddr != "" {
			cfg.WebUI = &wui
		}
	}

	return cfg, dt.result(), nil
}

func overlayControllerAF(name string, node *yaml.Node, dt *defaultTracker) (*ControllerAFConfig, error) {
	afName := types.AFName(name)

	var base *ControllerAFConfig
	if def, ok := DefaultControllerConfig.AFSettings[afName]; ok {
		clone := *def
		base = &clone
	} else {
		for _, def := range DefaultControllerConfig.AFSettings {
			clone := *def
			base = &clone
			break
		}
	}
	if base == nil {
		base = &ControllerAFConfig{}
	}
	base.Name = afName

	m := nodeMap(node)

	if err := trackedSet(&base.Enable, m, "enable", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.CommunicationPort, m, "communication_port", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.VxlanVNI, m, "vxlan_vni", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.VxlanDstPort, m, "vxlan_dst_port", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.VxlanSrcPortStart, m, "vxlan_src_port_start", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.VxlanSrcPortEnd, m, "vxlan_src_port_end", dt); err != nil {
		return nil, err
	}

	// bind_addr vs autoip_interface
	bindStr, hasBind := nodeString(m, "bind_addr")
	autoIP, hasAutoIP := nodeString(m, "autoip_interface")

	if hasBind && hasAutoIP {
		return nil, fmt.Errorf("bind_addr and autoip_interface are mutually exclusive")
	}
	if hasBind {
		addr, err := netip.ParseAddr(bindStr)
		if err != nil {
			return nil, fmt.Errorf("invalid bind_addr: %w", err)
		}
		base.BindAddr = addr
		base.AutoIPInterface = ""
	} else if hasAutoIP {
		base.AutoIPInterface = autoIP
		addrSelectStr, _ := nodeString(m, "addr_select")
		script, err := resolveAddrSelect(addrSelectStr, name)
		if err != nil {
			return nil, err
		}
		base.AddrSelectScript = script
		base.BindAddr = netip.Addr{}
	} else if !base.BindAddr.IsValid() && base.AutoIPInterface == "" {
		return nil, fmt.Errorf("either bind_addr or autoip_interface must be set")
	} else if base.BindAddr.IsValid() {
		dt.record("bind_addr", base.BindAddr)
	}

	return base, nil
}

func decodePerClient(node *yaml.Node, configDir string) (types.PerClientConfig, error) {
	m := nodeMap(node)
	pc := types.PerClientConfig{}

	if err := nodeSet(&pc.ClientName, m, "client_name"); err != nil {
		return pc, err
	}

	if err := nodeSetBase64Key32((*[32]byte)(&pc.ClientID), m, "client_id"); err != nil {
		return pc, fmt.Errorf("client %s: %w", pc.ClientName, err)
	}

	// Filters
	if n, ok := m["filters"]; ok {
		pc.Filters = filter.ParseFilterNode(n, configDir)
	}

	// Per-AF settings
	if afNode, ok := m["af_settings"]; ok {
		var raw map[string]*types.PerClientAFConfig
		if err := afNode.Decode(&raw); err != nil {
			return pc, fmt.Errorf("client %s: af_settings: %w", pc.ClientName, err)
		}
		if len(raw) > 0 {
			pc.AFSettings = make(map[types.AFName]*types.PerClientAFConfig, len(raw))
			for afStr, afCfg := range raw {
				pc.AFSettings[types.AFName(afStr)] = afCfg
			}
		}
	}

	return pc, nil
}

func cloneControllerConfig(src *ControllerConfig) *ControllerConfig {
	dst := *src
	if src.AFSettings != nil {
		dst.AFSettings = make(map[types.AFName]*ControllerAFConfig, len(src.AFSettings))
		for k, v := range src.AFSettings {
			clone := *v
			dst.AFSettings[k] = &clone
		}
	}
	if src.AllowedClients != nil {
		dst.AllowedClients = make([]types.PerClientConfig, len(src.AllowedClients))
		copy(dst.AllowedClients, src.AllowedClients)
	}
	return &dst
}
