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

// ClientConfig is the parsed client configuration.
type ClientConfig struct {
	PrivateKey         [32]byte
	BridgeName         string
	ClampMSSToMTU      bool
	ClampMSSTable      string
	NeighSuppress      bool
	VxlanFirewall      bool
	VxlanFirewallTable string
	AFSettings         map[types.AFName]*ClientAFConfig
	InitTimeout        time.Duration
	StatsInterval      time.Duration
	ProbeWindowSize    int
	AFSwitchCost       float64
	NTPServers         []string
	NTPPeriod          time.Duration
	NTPRTTThreshold    time.Duration
	Filters            *filter.FilterConfig
	LogLevel           string
	APISocket          string
	SyncCheckInterval  time.Duration
	SyncCheckMaxDelay  uint64
}

type ClientAFConfig struct {
	Name              types.AFName
	Enable            bool
	BindAddr          netip.Addr
	AutoIPInterface   string
	AddrSelectScript  string // resolved Lua code for addr selection
	ProbePort         uint16
	CommunicationPort uint16
	VxlanName         string
	VxlanVNI          uint32
	VxlanMTU          int
	VxlanDstPort      uint16
	VxlanSrcPortStart uint16
	VxlanSrcPortEnd   uint16
	Priority          int
	ForwardCost       float64
	Controllers       []ControllerEndpoint
}

type ControllerEndpoint struct {
	PubKey [32]byte
	Addr   netip.AddrPort
}

func LoadClientConfig(path string) (*ClientConfig, []DefaultApplied, error) {
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
	cfg := cloneClientConfig(&DefaultClientConfig)
	cfg.AFSettings = nil

	// Scalar fields
	if err := trackedSet(&cfg.BridgeName, m, "bridge_name", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.ClampMSSToMTU, m, "clamp_mss_to_mtu", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.ClampMSSTable, m, "clamp_mss_table", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.NeighSuppress, m, "neigh_suppress", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.VxlanFirewall, m, "vxlan_firewall", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.VxlanFirewallTable, m, "vxlan_firewall_table", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.ProbeWindowSize, m, "probe_window_size", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.AFSwitchCost, m, "af_switch_cost", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.LogLevel, m, "log_level", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.APISocket, m, "api_socket", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.SyncCheckMaxDelay, m, "sync_check_max_delay", dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSet(&cfg.NTPServers, m, "ntp_servers", dt); err != nil {
		return nil, nil, err
	}

	// Duration fields
	if err := trackedSetDuration(&cfg.InitTimeout, m, "init_timeout", time.Second, dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSetDuration(&cfg.StatsInterval, m, "stats_interval_s", time.Second, dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSetDuration(&cfg.NTPPeriod, m, "ntp_period_h", time.Hour, dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSetDuration(&cfg.NTPRTTThreshold, m, "ntp_rtt_threshold_ms", time.Millisecond, dt); err != nil {
		return nil, nil, err
	}
	if err := trackedSetDuration(&cfg.SyncCheckInterval, m, "sync_check_interval_s", time.Second, dt); err != nil {
		return nil, nil, err
	}

	// Private key (not tracked — required field)
	if err := nodeSetBase64Key32(&cfg.PrivateKey, m, "private_key"); err != nil {
		return nil, nil, err
	}

	// Filters
	if n, ok := m["filters"]; ok {
		cfg.Filters = filter.ParseFilterNode(n, configDir)
	}

	// AF settings (map overlay: keys from user, values default from matching or first default AF)
	if afNode, ok := m["address_families"]; ok {
		cfg.AFSettings = make(map[types.AFName]*ClientAFConfig)
		afMap := nodeMap(afNode)
		for name, afValueNode := range afMap {
			afDt := dt.sub("address_families." + name)
			af, err := overlayClientAF(name, afValueNode, afDt)
			if err != nil {
				return nil, nil, fmt.Errorf("af %s: %w", name, err)
			}
			cfg.AFSettings[types.AFName(name)] = af
		}
	}

	return cfg, dt.result(), nil
}

func overlayClientAF(name string, node *yaml.Node, dt *defaultTracker) (*ClientAFConfig, error) {
	afName := types.AFName(name)

	// Clone matching default AF, or first available
	var base *ClientAFConfig
	if def, ok := DefaultClientConfig.AFSettings[afName]; ok {
		base = cloneClientAFConfig(def)
	} else {
		for _, def := range DefaultClientConfig.AFSettings {
			base = cloneClientAFConfig(def)
			break
		}
	}
	if base == nil {
		base = &ClientAFConfig{}
	}
	base.Name = afName
	base.Controllers = nil

	m := nodeMap(node)

	if err := trackedSet(&base.Enable, m, "enable", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.ProbePort, m, "probe_port", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.CommunicationPort, m, "communication_port", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.VxlanName, m, "vxlan_name", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.VxlanVNI, m, "vxlan_vni", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.VxlanMTU, m, "vxlan_mtu", dt); err != nil {
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
	if err := trackedSet(&base.Priority, m, "priority", dt); err != nil {
		return nil, err
	}
	if err := trackedSet(&base.ForwardCost, m, "forward_cost", dt); err != nil {
		return nil, err
	}

	// bind_addr vs autoip_interface (tracked via dt for bind_addr default)
	bindStr, _ := nodeString(m, "bind_addr")
	autoIP, _ := nodeString(m, "autoip_interface")
	hasBind := bindStr != ""
	hasAutoIP := autoIP != ""

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

	// Controllers
	if ctrlNode, ok := m["controllers"]; ok && ctrlNode.Kind == yaml.SequenceNode {
		for _, cNode := range ctrlNode.Content {
			cm := nodeMap(cNode)
			ce := ControllerEndpoint{}

			if err := nodeSetBase64Key32(&ce.PubKey, cm, "pubkey"); err != nil {
				return nil, fmt.Errorf("invalid controller pubkey: %w", err)
			}

			addr, _, err := nodeAddrPort(cm, "addr")
			if err != nil {
				return nil, fmt.Errorf("invalid controller addr: %w", err)
			}
			ce.Addr = addr

			base.Controllers = append(base.Controllers, ce)
		}
	}

	return base, nil
}

func cloneClientConfig(src *ClientConfig) *ClientConfig {
	dst := *src
	if src.NTPServers != nil {
		dst.NTPServers = make([]string, len(src.NTPServers))
		copy(dst.NTPServers, src.NTPServers)
	}
	if src.AFSettings != nil {
		dst.AFSettings = make(map[types.AFName]*ClientAFConfig, len(src.AFSettings))
		for k, v := range src.AFSettings {
			dst.AFSettings[k] = cloneClientAFConfig(v)
		}
	}
	return &dst
}

func cloneClientAFConfig(src *ClientAFConfig) *ClientAFConfig {
	dst := *src
	if src.Controllers != nil {
		dst.Controllers = make([]ControllerEndpoint, len(src.Controllers))
		copy(dst.Controllers, src.Controllers)
	}
	return &dst
}
