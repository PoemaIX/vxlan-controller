package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/types"

	"gopkg.in/yaml.v3"
)

// AutogenConfig is the topology file for generating controller+client configs.
type AutogenConfig struct {
	BridgeName        string  `yaml:"bridge_name"`
	ClampMSSToMTU     *bool   `yaml:"clamp_mss_to_mtu"`
	VxlanFirewall     *bool   `yaml:"vxlan_firewall"`
	VxlanNamePrefix   string  `yaml:"vxlan_name_prefix"`
	VxlanDstPort      uint16  `yaml:"vxlan_dst_port"`
	VxlanSrcPortStart uint16  `yaml:"vxlan_src_port_start"`
	VxlanSrcPortEnd   uint16  `yaml:"vxlan_src_port_end"`
	CommunicationPort uint16  `yaml:"communication_port"`
	VxlanVNI          uint32  `yaml:"vxlan_vni"`
	VxlanMTU          int     `yaml:"vxlan_mtu"`
	ProbePort         uint16  `yaml:"probe_port"`
	Priority          int     `yaml:"priority"`
	ForwardCost       float64 `yaml:"forward_cost"`

	// Nodes[nodeName][afName][channelName] = endpoint config.
	// YAML shorthand: a scalar or a map with "bind" key is treated as a single
	// channel named types.DefaultChannelName.
	Nodes       map[string]map[string]AutogenAFChannels `yaml:"nodes"`
	Controllers []string                                `yaml:"controllers"`
	Clients     []string                                `yaml:"clients"`
	WebUI       *AutogenWebUI                           `yaml:"web_ui"`
}

type AutogenWebUI struct {
	BindAddr string                `yaml:"bind_addr"`
	Title    string                `yaml:"title"`
	URL      string                `yaml:"url"`
	Nodes    map[string]*WebUINode `yaml:"nodes"`
}

// AutogenAFChannels holds per-channel configs for a single AF of a single node.
// Accepts three YAML forms:
//  1. scalar:            "1.2.3.4"           → {DefaultChannel: {Bind: "1.2.3.4"}}
//  2. single-AF object:  "{bind: eth3}"      → {DefaultChannel: {Bind: "eth3"}}
//  3. channel map:       "{ISP1: ..., ISP2: ...}"
type AutogenAFChannels map[types.ChannelName]*AutogenAF

func (a *AutogenAFChannels) UnmarshalYAML(value *yaml.Node) error {
	*a = make(AutogenAFChannels)
	switch value.Kind {
	case yaml.ScalarNode:
		(*a)[types.DefaultChannelName] = &AutogenAF{Bind: value.Value}
		return nil
	case yaml.MappingNode:
		// Peek keys: if "bind" (or "ddns") is a top-level key, treat as single-channel shorthand.
		isShorthand := false
		for i := 0; i < len(value.Content); i += 2 {
			k := value.Content[i].Value
			if k == "bind" || k == "ddns" {
				isShorthand = true
				break
			}
		}
		if isShorthand {
			var af AutogenAF
			if err := value.Decode(&af); err != nil {
				return err
			}
			(*a)[types.DefaultChannelName] = &af
			return nil
		}
		// Channel map form
		type plain map[types.ChannelName]*AutogenAF
		var chans plain
		if err := value.Decode(&chans); err != nil {
			return err
		}
		for ch, af := range chans {
			(*a)[ch] = af
		}
		return nil
	}
	return fmt.Errorf("unexpected YAML kind for AF channels: %v", value.Kind)
}

// AutogenAF represents a per-channel bind config.
// Supports shorthand "ISP1: 1.2.3.4" or full form "ISP1: {bind: eth3, ddns: host.example.com}".
type AutogenAF struct {
	Bind string `yaml:"bind"`
	DDNS string `yaml:"ddns,omitempty"`
}

func (a *AutogenAF) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		a.Bind = value.Value
		return nil
	}
	// Map form
	type plain AutogenAF
	return value.Decode((*plain)(a))
}

// IsAutoIP returns true if bind is an interface name (not a parseable IP).
func (a *AutogenAF) IsAutoIP() bool {
	_, err := netip.ParseAddr(a.Bind)
	return err != nil
}

// Endpoint returns the address clients should use to reach this controller AF.
// Returns bind IP if static, or ddns if set. Error if autoip without ddns.
func (a *AutogenAF) Endpoint() (string, error) {
	if a.DDNS != "" {
		return a.DDNS, nil
	}
	if a.IsAutoIP() {
		return "", fmt.Errorf("autoip_interface %q requires ddns for controller", a.Bind)
	}
	return a.Bind, nil
}

type autogenNodeKeys struct {
	Priv [32]byte
	Pub  [32]byte
}

var DefaultAutogenConfig = AutogenConfig{
	BridgeName:        "br-vxlan",
	VxlanNamePrefix:   "vxlan-",
	VxlanDstPort:      4789,
	VxlanSrcPortStart: 4789,
	VxlanSrcPortEnd:   4789,
	CommunicationPort: 5000,
	VxlanVNI:          100,
	VxlanMTU:          1400,
	ProbePort:         5010,
	Priority:          10,
	ForwardCost:       20,
}

// Autogen loads a topology file and generates controller+client configs.
// Output files are written to the same directory as the input file.
func Autogen(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read topology: %w", err)
	}

	ag := DefaultAutogenConfig
	if err := yaml.Unmarshal(data, &ag); err != nil {
		return fmt.Errorf("parse topology: %w", err)
	}

	// Validate node references
	allRoles := map[string]bool{}
	for _, name := range ag.Controllers {
		if _, ok := ag.Nodes[name]; !ok {
			return fmt.Errorf("controller %q not found in nodes", name)
		}
		allRoles[name] = true
	}
	for _, name := range ag.Clients {
		if _, ok := ag.Nodes[name]; !ok {
			return fmt.Errorf("client %q not found in nodes", name)
		}
		allRoles[name] = true
	}

	// Generate keypairs for all nodes
	keys := make(map[string]*autogenNodeKeys, len(ag.Nodes))
	for name := range ag.Nodes {
		priv, pub := crypto.GenerateKeyPair()
		keys[name] = &autogenNodeKeys{Priv: priv, Pub: pub}
	}

	// Validate controller (af, channel) have reachable endpoints
	for _, name := range ag.Controllers {
		for afName, chans := range ag.Nodes[name] {
			for chName, af := range chans {
				if _, err := af.Endpoint(); err != nil {
					return fmt.Errorf("controller %q AF %s channel %s: %w", name, afName, chName, err)
				}
			}
		}
	}

	outDir := filepath.Dir(path)

	// Generate controller configs
	for _, name := range ag.Controllers {
		cfg := ag.buildControllerConfig(name, keys)
		data, err := MarshalControllerConfig(cfg)
		if err != nil {
			return fmt.Errorf("marshal controller config for %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(outDir, name+".controller.yaml"), data, 0644); err != nil {
			return fmt.Errorf("write controller config for %s: %w", name, err)
		}
		fmt.Printf("  %s.controller.yaml\n", name)
	}

	// Generate client configs
	for _, name := range ag.Clients {
		cfg := ag.buildClientConfig(name, keys)
		data, err := MarshalClientConfig(cfg)
		if err != nil {
			return fmt.Errorf("marshal client config for %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(outDir, name+".client.yaml"), data, 0644); err != nil {
			return fmt.Errorf("write client config for %s: %w", name, err)
		}
		fmt.Printf("  %s.client.yaml\n", name)
	}

	return nil
}

func (ag *AutogenConfig) buildControllerConfig(name string, keys map[string]*autogenNodeKeys) *ControllerConfig {
	k := keys[name]
	cfg := cloneControllerConfig(&DefaultControllerConfig)

	cfg.PrivateKey = k.Priv

	// AF settings from this node's (af, channel) pairs
	cfg.AFSettings = make(map[types.AFName]map[types.ChannelName]*ControllerChannelConfig)
	for afName, chans := range ag.Nodes[name] {
		inner := make(map[types.ChannelName]*ControllerChannelConfig, len(chans))
		for chName, af := range chans {
			cc := &ControllerChannelConfig{
				AF:                types.AFName(afName),
				Channel:           chName,
				Enable:            true,
				CommunicationPort: ag.CommunicationPort,
				VxlanVNI:          ag.VxlanVNI,
				VxlanDstPort:      ag.VxlanDstPort,
				VxlanSrcPortStart: ag.VxlanSrcPortStart,
				VxlanSrcPortEnd:   ag.VxlanSrcPortEnd,
			}
			if af.IsAutoIP() {
				cc.AutoIPInterface = af.Bind
			} else {
				cc.BindAddr = netip.MustParseAddr(af.Bind)
			}
			inner[chName] = cc
		}
		cfg.AFSettings[types.AFName(afName)] = inner
	}

	// WebUI config
	if ag.WebUI != nil {
		bindAddr := ag.WebUI.BindAddr
		if bindAddr == "" {
			bindAddr = ":8080"
		}
		cfg.WebUI = &WebUIConfig{
			BindAddr: bindAddr,
			Title:    ag.WebUI.Title,
			URL:      ag.WebUI.URL,
		}
		if len(ag.WebUI.Nodes) > 0 {
			cfg.WebUI.Nodes = make(map[string]*WebUINode, len(ag.WebUI.Nodes))
			for nodeName, n := range ag.WebUI.Nodes {
				cfg.WebUI.Nodes[nodeName] = &WebUINode{
					Label: n.Label,
					Pos:   n.Pos,
				}
			}
		}
	}

	// Allowed clients = all client nodes
	cfg.AllowedClients = nil
	for _, clientName := range ag.Clients {
		ck := keys[clientName]
		pc := types.PerClientConfig{
			ClientID:   types.ClientID(ck.Pub),
			ClientName: clientName,
		}
		// If this controller is also the client, carry its DDNS overrides.
		if clientName == name {
			for afName, chans := range ag.Nodes[clientName] {
				for chName, af := range chans {
					if af.DDNS == "" {
						continue
					}
					if pc.AFSettings == nil {
						pc.AFSettings = make(map[types.AFName]map[types.ChannelName]*types.PerClientChannelConfig)
					}
					inner, ok := pc.AFSettings[types.AFName(afName)]
					if !ok {
						inner = make(map[types.ChannelName]*types.PerClientChannelConfig)
						pc.AFSettings[types.AFName(afName)] = inner
					}
					inner[chName] = &types.PerClientChannelConfig{
						EndpointOverride: af.DDNS,
					}
				}
			}
		}
		cfg.AllowedClients = append(cfg.AllowedClients, pc)
	}

	return cfg
}

func (ag *AutogenConfig) buildClientConfig(name string, keys map[string]*autogenNodeKeys) *ClientConfig {
	k := keys[name]
	cfg := cloneClientConfig(&DefaultClientConfig)

	cfg.PrivateKey = k.Priv
	cfg.BridgeName = ag.BridgeName
	if ag.ClampMSSToMTU != nil {
		cfg.ClampMSSToMTU = *ag.ClampMSSToMTU
	}
	if ag.VxlanFirewall != nil {
		cfg.VxlanFirewall = *ag.VxlanFirewall
	}

	// AF settings from this node's (af, channel) pairs
	cfg.AFSettings = make(map[types.AFName]map[types.ChannelName]*ClientChannelConfig)
	for afName, chans := range ag.Nodes[name] {
		inner := make(map[types.ChannelName]*ClientChannelConfig, len(chans))
		for chName, af := range chans {
			cc := &ClientChannelConfig{
				AF:                types.AFName(afName),
				Channel:           chName,
				Enable:            true,
				ProbePort:         ag.ProbePort,
				VxlanName:         ag.VxlanNamePrefix + afName + "-" + string(chName),
				VxlanVNI:          ag.VxlanVNI,
				VxlanMTU:          ag.VxlanMTU,
				VxlanDstPort:      ag.VxlanDstPort,
				VxlanSrcPortStart: ag.VxlanSrcPortStart,
				VxlanSrcPortEnd:   ag.VxlanSrcPortEnd,
				Priority:          ag.Priority,
				ForwardCost:       ag.ForwardCost,
			}
			if af.IsAutoIP() {
				cc.AutoIPInterface = af.Bind
			} else {
				cc.BindAddr = netip.MustParseAddr(af.Bind)
			}

			// Add controllers that have this (af, channel)
			for _, ctrlName := range ag.Controllers {
				ctrlChans, ok := ag.Nodes[ctrlName][afName]
				if !ok {
					continue
				}
				ctrlAF, ok := ctrlChans[chName]
				if !ok {
					continue
				}
				var addr string
				if ctrlName == name {
					addr = ctrlAF.Bind
				} else {
					addr, _ = ctrlAF.Endpoint() // already validated
				}
				ck := keys[ctrlName]
				ap, _ := netip.ParseAddrPort(formatAddrPort(addr, ag.CommunicationPort))
				cc.Controllers = append(cc.Controllers, ControllerEndpoint{
					PubKey: ck.Pub,
					Addr:   ap,
				})
			}

			inner[chName] = cc
		}
		cfg.AFSettings[types.AFName(afName)] = inner
	}

	return cfg
}

func formatAddrPort(host string, port uint16) string {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
