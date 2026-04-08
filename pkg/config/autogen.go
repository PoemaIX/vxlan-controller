package config

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"vxlan-controller/pkg/crypto"

	"gopkg.in/yaml.v3"
)

// AutogenConfig is the topology file for generating controller+client configs.
type AutogenConfig struct {
	VxlanDstPort      uint16 `yaml:"vxlan_dst_port"`
	VxlanSrcPortStart uint16 `yaml:"vxlan_src_port_start"`
	VxlanSrcPortEnd   uint16 `yaml:"vxlan_src_port_end"`
	CommunicationPort uint16 `yaml:"communication_port"`
	VxlanVNI          uint32 `yaml:"vxlan_vni"`
	VxlanMTU          int    `yaml:"vxlan_mtu"`
	ProbePort         uint16 `yaml:"probe_port"`
	Priority          int    `yaml:"priority"`
	AdditionalCost    float64 `yaml:"additional_cost"`

	Nodes       map[string]map[string]AutogenAF `yaml:"nodes"`
	Controllers []string                        `yaml:"controllers"`
	Clients     []string                        `yaml:"clients"`
}

// AutogenAF represents a per-AF bind config.
// Supports shorthand "v4: 1.2.3.4" or full form "v4: {bind: eth3, ddns: host.example.com}".
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

// Autogen loads a topology file and generates controller+client configs.
// Output files are written to the same directory as the input file.
func Autogen(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read topology: %w", err)
	}

	var ag AutogenConfig
	if err := yaml.Unmarshal(data, &ag); err != nil {
		return fmt.Errorf("parse topology: %w", err)
	}

	// Apply defaults
	if ag.VxlanDstPort == 0 {
		ag.VxlanDstPort = 4789
	}
	if ag.VxlanSrcPortStart == 0 {
		ag.VxlanSrcPortStart = 4789
	}
	if ag.VxlanSrcPortEnd == 0 {
		ag.VxlanSrcPortEnd = 4789
	}
	if ag.CommunicationPort == 0 {
		ag.CommunicationPort = 5000
	}
	if ag.VxlanVNI == 0 {
		ag.VxlanVNI = 100
	}
	if ag.VxlanMTU == 0 {
		ag.VxlanMTU = 1400
	}
	if ag.ProbePort == 0 {
		ag.ProbePort = 5010
	}
	if ag.Priority == 0 {
		ag.Priority = 10
	}
	if ag.AdditionalCost == 0 {
		ag.AdditionalCost = 20
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

	// Validate controller AFs have reachable endpoints
	for _, name := range ag.Controllers {
		for afName, af := range ag.Nodes[name] {
			if _, err := af.Endpoint(); err != nil {
				return fmt.Errorf("controller %q AF %s: %w", name, afName, err)
			}
		}
	}

	outDir := filepath.Dir(path)

	// Generate controller configs
	for _, name := range ag.Controllers {
		cfg := ag.buildControllerConfig(name, keys)
		if err := writeYAML(filepath.Join(outDir, name+".controller.yaml"), cfg); err != nil {
			return fmt.Errorf("write controller config for %s: %w", name, err)
		}
		fmt.Printf("  %s.controller.yaml\n", name)
	}

	// Generate client configs
	for _, name := range ag.Clients {
		cfg := ag.buildClientConfig(name, keys)
		if err := writeYAML(filepath.Join(outDir, name+".client.yaml"), cfg); err != nil {
			return fmt.Errorf("write client config for %s: %w", name, err)
		}
		fmt.Printf("  %s.client.yaml\n", name)
	}

	return nil
}

func (ag *AutogenConfig) buildControllerConfig(name string, keys map[string]*autogenNodeKeys) *ControllerConfigFile {
	k := keys[name]
	cfg := DefaultControllerConfig

	cfg.PrivateKey = base64.StdEncoding.EncodeToString(k.Priv[:])
	cfg.PublicKey = base64.StdEncoding.EncodeToString(k.Pub[:])

	// AF settings from this node's AFs
	cfg.AFSettings = make(map[string]*ControllerAFConfigFile)
	for afName, af := range ag.Nodes[name] {
		afCfg := &ControllerAFConfigFile{
			Enable:            true,
			CommunicationPort: ag.CommunicationPort,
			VxlanVNI:          ag.VxlanVNI,
			VxlanDstPort:      ag.VxlanDstPort,
			VxlanSrcPortStart: ag.VxlanSrcPortStart,
			VxlanSrcPortEnd:   ag.VxlanSrcPortEnd,
		}
		if af.IsAutoIP() {
			afCfg.AutoIPInterface = af.Bind
		} else {
			afCfg.BindAddr = af.Bind
		}
		cfg.AFSettings[afName] = afCfg
	}

	// Allowed clients = all client nodes
	cfg.AllowedClients = nil
	for _, clientName := range ag.Clients {
		ck := keys[clientName]
		cfg.AllowedClients = append(cfg.AllowedClients, PerClientConfigFile{
			ClientID:   base64.StdEncoding.EncodeToString(ck.Pub[:]),
			ClientName: clientName,
		})
	}

	return &cfg
}

func (ag *AutogenConfig) buildClientConfig(name string, keys map[string]*autogenNodeKeys) *ClientConfigFile {
	k := keys[name]
	cfg := DefaultClientConfig

	cfg.PrivateKey = base64.StdEncoding.EncodeToString(k.Priv[:])
	cfg.PublicKey = base64.StdEncoding.EncodeToString(k.Pub[:])

	// AF settings from this node's AFs
	cfg.AFSettings = make(map[string]*ClientAFConfigFile)
	for afName, af := range ag.Nodes[name] {
		afCfg := &ClientAFConfigFile{
			Enable:            true,
			ProbePort:         ag.ProbePort,
			VxlanName:         "vxlan-" + afName,
			VxlanVNI:          ag.VxlanVNI,
			VxlanMTU:          ag.VxlanMTU,
			VxlanDstPort:      ag.VxlanDstPort,
			VxlanSrcPortStart: ag.VxlanSrcPortStart,
			VxlanSrcPortEnd:   ag.VxlanSrcPortEnd,
			Priority:          ag.Priority,
			AdditionalCost:    ag.AdditionalCost,
		}
		if af.IsAutoIP() {
			afCfg.AutoIPInterface = af.Bind
		} else {
			afCfg.BindAddr = af.Bind
		}

		// Add controllers that have this AF
		for _, ctrlName := range ag.Controllers {
			ctrlAF, ok := ag.Nodes[ctrlName][afName]
			if !ok {
				continue
			}
			endpoint, _ := ctrlAF.Endpoint() // already validated
			ck := keys[ctrlName]
			afCfg.Controllers = append(afCfg.Controllers, ControllerEndpointFile{
				PubKey: base64.StdEncoding.EncodeToString(ck.Pub[:]),
				Addr:   formatAddrPort(endpoint, ag.CommunicationPort),
			})
		}

		cfg.AFSettings[afName] = afCfg
	}

	return &cfg
}

func formatAddrPort(host string, port uint16) string {
	// If it's an IPv6 address, wrap in brackets
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func writeYAML(path string, v interface{}) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
