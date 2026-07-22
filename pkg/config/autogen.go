package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

	// ChannelAdditionalCosts is keyed by client_name and emitted verbatim
	// into that client's channel_additional_costs list. Lets per-node cost
	// overlays live in the topology file instead of hand-edited client configs.
	ChannelAdditionalCosts map[string][]ChannelAdditionalCost `yaml:"channel_additional_costs"`
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
		// Peek keys: if any AutogenAF field is a top-level key, treat as single-channel shorthand.
		isShorthand := false
		for i := 0; i < len(value.Content); i += 2 {
			k := value.Content[i].Value
			if k == "bind" || k == "ddns" || k == "bind_device" {
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
// Supports shorthand "ISP1: 1.2.3.4" or full form
// "ISP1: {bind: eth3, ddns: host.example.com, bind_device: eth-isp1}".
type AutogenAF struct {
	Bind       string `yaml:"bind"`
	DDNS       string `yaml:"ddns,omitempty"`
	BindDevice string `yaml:"bind_device,omitempty"`
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

// controllerSpec is one parsed `controllers:` entry. Selection granularity:
//   "node"             → every (af, channel) of the node
//   "node/channel"     → that channel in every AF that has it
//   "node/af/channel"  → exactly that (af, channel)
// Only the selected channels become controller listeners / client-visible
// endpoints; the node's other channels stay client-only.
type controllerSpec struct {
	Name    string
	AF      types.AFName      // "" = any AF
	Channel types.ChannelName // "" = all channels
}

func parseControllerSpec(s string) (controllerSpec, error) {
	parts := strings.Split(s, "/")
	for _, p := range parts {
		if p == "" {
			return controllerSpec{}, fmt.Errorf("invalid controller %q (want node, node/channel, or node/af/channel)", s)
		}
	}
	switch len(parts) {
	case 1:
		return controllerSpec{Name: parts[0]}, nil
	case 2:
		return controllerSpec{Name: parts[0], Channel: types.ChannelName(parts[1])}, nil
	case 3:
		return controllerSpec{Name: parts[0], AF: types.AFName(parts[1]), Channel: types.ChannelName(parts[2])}, nil
	}
	return controllerSpec{}, fmt.Errorf("invalid controller %q (want node, node/channel, or node/af/channel)", s)
}

func (sp controllerSpec) matches(af types.AFName, ch types.ChannelName) bool {
	return (sp.AF == "" || sp.AF == af) && (sp.Channel == "" || sp.Channel == ch)
}

// controllerSelected reports whether (name, af, ch) is selected by any spec.
func controllerSelected(specs []controllerSpec, name string, af types.AFName, ch types.ChannelName) bool {
	for _, sp := range specs {
		if sp.Name == name && sp.matches(af, ch) {
			return true
		}
	}
	return false
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

	// Parse and validate controller specs
	allRoles := map[string]bool{}
	specs := make([]controllerSpec, 0, len(ag.Controllers))
	var ctrlNames []string // unique node names, first-appearance order
	for _, s := range ag.Controllers {
		sp, err := parseControllerSpec(s)
		if err != nil {
			return err
		}
		if _, ok := ag.Nodes[sp.Name]; !ok {
			return fmt.Errorf("controller %q not found in nodes", sp.Name)
		}
		// The spec must select at least one existing (af, channel).
		found := false
		for afName, chans := range ag.Nodes[sp.Name] {
			for chName := range chans {
				if sp.matches(types.AFName(afName), chName) {
					found = true
				}
			}
		}
		if !found {
			return fmt.Errorf("controller %q selects no (af, channel) on node %q", s, sp.Name)
		}
		if !allRoles[sp.Name] {
			ctrlNames = append(ctrlNames, sp.Name)
		}
		allRoles[sp.Name] = true
		specs = append(specs, sp)
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

	// Validate that selected controller (af, channel) have reachable
	// endpoints. Unselected channels of a controller node stay client-only
	// and need no public endpoint.
	for _, name := range ctrlNames {
		for afName, chans := range ag.Nodes[name] {
			for chName, af := range chans {
				if !controllerSelected(specs, name, types.AFName(afName), chName) {
					continue
				}
				if _, err := af.Endpoint(); err != nil {
					return fmt.Errorf("controller %q AF %s channel %s: %w", name, afName, chName, err)
				}
			}
		}
	}

	outDir := filepath.Dir(path)

	// Generate controller configs
	for _, name := range ctrlNames {
		cfg := ag.buildControllerConfig(name, keys, specs)
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
		cfg := ag.buildClientConfig(name, keys, specs)
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

func (ag *AutogenConfig) buildControllerConfig(name string, keys map[string]*autogenNodeKeys, specs []controllerSpec) *ControllerConfig {
	k := keys[name]
	cfg := cloneControllerConfig(&DefaultControllerConfig)

	cfg.PrivateKey = k.Priv

	// AF settings: only the (af, channel) pairs selected as controller
	// listeners; the node's other channels stay client-only.
	cfg.AFSettings = make(map[types.AFName]map[types.ChannelName]*ControllerChannelConfig)
	for afName, chans := range ag.Nodes[name] {
		inner := make(map[types.ChannelName]*ControllerChannelConfig, len(chans))
		for chName, af := range chans {
			if !controllerSelected(specs, name, types.AFName(afName), chName) {
				continue
			}
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
			cc.BindDevice = af.BindDevice
			inner[chName] = cc
		}
		if len(inner) > 0 {
			cfg.AFSettings[types.AFName(afName)] = inner
		}
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

func (ag *AutogenConfig) buildClientConfig(name string, keys map[string]*autogenNodeKeys, specs []controllerSpec) *ClientConfig {
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

	// Precompute deterministic vxlan_name per (af, channel) for this node.
	vxlanNames := buildVxlanNames(ag.VxlanNamePrefix, ag.Nodes[name])

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
				VxlanName:         vxlanNames[types.AFName(afName)][chName],
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
			cc.BindDevice = af.BindDevice

			// Add controller endpoints selected for this AF. Channel names
			// are per-node uplink labels, so a client channel can reach a
			// controller on any of its selected uplinks in the same AF —
			// list every address; the client keeps one connection per
			// controller and rotates through its addresses on failure.
			// Specs are walked in `controllers:` order, so the listed order
			// doubles as the preference order for rotation.
			seenCtrlEP := make(map[string]bool)
			for _, sp := range specs {
				ctrlChans, ok := ag.Nodes[sp.Name][afName]
				if !ok {
					continue
				}
				ck := keys[sp.Name]
				ctrlChNames := make([]types.ChannelName, 0, len(ctrlChans))
				for ctrlCh := range ctrlChans {
					if sp.matches(types.AFName(afName), ctrlCh) {
						ctrlChNames = append(ctrlChNames, ctrlCh)
					}
				}
				sort.Slice(ctrlChNames, func(i, j int) bool { return ctrlChNames[i] < ctrlChNames[j] })
				for _, ctrlCh := range ctrlChNames {
					epKey := sp.Name + "/" + string(ctrlCh)
					if seenCtrlEP[epKey] {
						continue
					}
					seenCtrlEP[epKey] = true
					ctrlAF := ctrlChans[ctrlCh]
					var addr string
					if sp.Name == name && !ctrlAF.IsAutoIP() {
						addr = ctrlAF.Bind
					} else {
						addr, _ = ctrlAF.Endpoint() // already validated
					}
					ap, _ := netip.ParseAddrPort(formatAddrPort(addr, ag.CommunicationPort))
					cc.Controllers = append(cc.Controllers, ControllerEndpoint{
						PubKey: ck.Pub,
						Addr:   ap,
					})
				}
			}

			inner[chName] = cc
		}
		cfg.AFSettings[types.AFName(afName)] = inner
	}

	if rules, ok := ag.ChannelAdditionalCosts[name]; ok && len(rules) > 0 {
		cfg.ChannelAdditionalCosts = append(cfg.ChannelAdditionalCosts, rules...)
	}

	return cfg
}

func formatAddrPort(host string, port uint16) string {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// MaxIfnameLen is the Linux IFNAMSIZ-1 (15 char limit for interface names).
const MaxIfnameLen = 15

// buildVxlanNames produces a deterministic, IFNAMSIZ-safe vxlan_name for every
// (af, channel) on a single node.
//
// Layout: <prefix><af>-<isp_truncated><suffix>
//   - <prefix><af> joined directly (no separator) so the prefix carries any
//     trailing separator the user wants.
//   - One '-' separator before the ISP segment.
//   - <suffix> is a 1- or 2-digit, 1-based index derived from the alphabetical
//     position of the channel name within its AF on this node. The digit
//     width is determined by the largest ISP count across all AFs on the node
//     (≤10 → 1 digit, ≤100 → 2 digits) so every device on the node has the
//     same suffix width, and the result is stable across regenerations.
//   - <isp_truncated> is the channel name truncated from the right to fit
//     the remaining budget (15 - len(<prefix><af>-) - len(suffix)).
//
// Per-node deterministic indexing means names never silently collide on a
// single host even after aggressive truncation. Returns
// map[af][channel] -> "<vxlan_name>".
func buildVxlanNames(prefix string, afs map[string]AutogenAFChannels) map[types.AFName]map[types.ChannelName]string {
	out := make(map[types.AFName]map[types.ChannelName]string)

	// Sorted channel list per AF (alphabetical) for stable index assignment.
	type ordered struct {
		af    string
		chans []types.ChannelName
	}
	var sortedAFs []ordered
	maxIspsPerAF := 0
	for afName, chans := range afs {
		names := make([]types.ChannelName, 0, len(chans))
		for ch := range chans {
			names = append(names, ch)
		}
		sort.Slice(names, func(i, j int) bool { return string(names[i]) < string(names[j]) })
		sortedAFs = append(sortedAFs, ordered{af: afName, chans: names})
		if len(names) > maxIspsPerAF {
			maxIspsPerAF = len(names)
		}
	}

	// Suffix digit width: minimum needed to represent maxIspsPerAF (1-based).
	suffixWidth := 1
	if maxIspsPerAF > 9 {
		suffixWidth = 2
	}

	for _, e := range sortedAFs {
		inner := make(map[types.ChannelName]string, len(e.chans))
		base := prefix + e.af + "-"
		budget := MaxIfnameLen - len(base) - suffixWidth
		if budget < 1 {
			// Pathological: prefix+af+dash+suffix alone overflows. Fall back
			// to a bare-minimum name so we don't generate something invalid;
			// validateClientUniqueness will reject it loudly.
			budget = 1
		}
		for i, ch := range e.chans {
			idx := i + 1
			isp := string(ch)
			if len(isp) > budget {
				isp = isp[:budget]
			}
			suffix := fmt.Sprintf("%0*d", suffixWidth, idx)
			inner[ch] = base + isp + suffix
		}
		out[types.AFName(e.af)] = inner
	}
	return out
}
