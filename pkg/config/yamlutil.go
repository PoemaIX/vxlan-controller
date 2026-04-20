package config

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/types"

	"gopkg.in/yaml.v3"
)

// --- yaml.Node decode helpers ---

// nodeMap converts a yaml.Node (document or mapping) to a key→value map.
func nodeMap(node *yaml.Node) map[string]*yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	m := make(map[string]*yaml.Node, len(node.Content)/2)
	for i := 0; i < len(node.Content)-1; i += 2 {
		m[node.Content[i].Value] = node.Content[i+1]
	}
	return m
}

// nodeString returns (value, found) for a string key.
func nodeString(m map[string]*yaml.Node, key string) (string, bool) {
	n, ok := m[key]
	if !ok {
		return "", false
	}
	return n.Value, true
}

// nodeSet decodes a YAML value into *dst. No-op if key is absent.
func nodeSet[T any](dst *T, m map[string]*yaml.Node, key string) error {
	n, ok := m[key]
	if !ok {
		return nil
	}
	if err := n.Decode(dst); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

// nodeSetDuration decodes an integer × unit into *dst. No-op if key is absent.
func nodeSetDuration(dst *time.Duration, m map[string]*yaml.Node, key string, unit time.Duration) error {
	n, ok := m[key]
	if !ok {
		return nil
	}
	var v int
	if err := n.Decode(&v); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = time.Duration(v) * unit
	return nil
}

// nodeSetBase64Key32 decodes a base64 string into a [32]byte. No-op if key is absent.
func nodeSetBase64Key32(dst *[32]byte, m map[string]*yaml.Node, key string) error {
	n, ok := m[key]
	if !ok {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(n.Value)
	if err != nil {
		return fmt.Errorf("invalid %s base64: %w", key, err)
	}
	if len(b) != 32 {
		return fmt.Errorf("%s must be 32 bytes, got %d", key, len(b))
	}
	copy(dst[:], b)
	return nil
}

// nodeBase64Key32 returns ([32]byte, found, error).
func nodeBase64Key32(m map[string]*yaml.Node, key string) ([32]byte, bool, error) {
	var k [32]byte
	n, ok := m[key]
	if !ok {
		return k, false, nil
	}
	b, err := base64.StdEncoding.DecodeString(n.Value)
	if err != nil {
		return k, true, fmt.Errorf("invalid %s base64: %w", key, err)
	}
	if len(b) != 32 {
		return k, true, fmt.Errorf("%s must be 32 bytes, got %d", key, len(b))
	}
	copy(k[:], b)
	return k, true, nil
}

// nodeAddrPort parses a string YAML value as netip.AddrPort. Returns (value, found, error).
func nodeAddrPort(m map[string]*yaml.Node, key string) (netip.AddrPort, bool, error) {
	n, ok := m[key]
	if !ok {
		return netip.AddrPort{}, false, nil
	}
	ap, err := netip.ParseAddrPort(n.Value)
	if err != nil {
		return netip.AddrPort{}, true, fmt.Errorf("invalid %s: %w", key, err)
	}
	return ap, true, nil
}

// --- Default tracking ---

// DefaultApplied records a config field that used its default value.
type DefaultApplied struct {
	Path  string
	Value string
}

type defaultTracker struct {
	prefix  string
	entries *[]DefaultApplied
}

func newDefaultTracker() *defaultTracker {
	entries := make([]DefaultApplied, 0)
	return &defaultTracker{entries: &entries}
}

func (dt *defaultTracker) sub(prefix string) *defaultTracker {
	p := prefix
	if dt.prefix != "" {
		p = dt.prefix + "." + prefix
	}
	return &defaultTracker{prefix: p, entries: dt.entries}
}

func (dt *defaultTracker) record(key string, value interface{}) {
	path := key
	if dt.prefix != "" {
		path = dt.prefix + "." + key
	}
	var valStr string
	switch v := value.(type) {
	case time.Duration:
		valStr = v.String()
	case netip.Addr:
		valStr = v.String()
	default:
		valStr = fmt.Sprintf("%v", v)
	}
	*dt.entries = append(*dt.entries, DefaultApplied{Path: path, Value: valStr})
}

func (dt *defaultTracker) result() []DefaultApplied {
	return *dt.entries
}

// trackedSet is like nodeSet but records a default when the key is absent.
func trackedSet[T any](dst *T, m map[string]*yaml.Node, key string, dt *defaultTracker) error {
	n, ok := m[key]
	if !ok {
		dt.record(key, *dst)
		return nil
	}
	if err := n.Decode(dst); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

// trackedSetDuration is like nodeSetDuration but records a default when the key is absent.
func trackedSetDuration(dst *time.Duration, m map[string]*yaml.Node, key string, unit time.Duration, dt *defaultTracker) error {
	n, ok := m[key]
	if !ok {
		dt.record(key, *dst)
		return nil
	}
	var v int
	if err := n.Decode(&v); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = time.Duration(v) * unit
	return nil
}

// --- yaml.Node marshal helpers ---

// yamlMap builds a YAML mapping with insertion-order-preserved keys.
type yamlMap struct {
	node *yaml.Node
}

func newYAMLMap() *yamlMap {
	return &yamlMap{node: &yaml.Node{Kind: yaml.MappingNode}}
}

func (ym *yamlMap) Set(key string, value interface{}) {
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	var doc yaml.Node
	data, _ := yaml.Marshal(value)
	_ = yaml.Unmarshal(data, &doc)
	var valNode *yaml.Node
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		valNode = doc.Content[0]
	} else {
		valNode = &doc
	}
	ym.node.Content = append(ym.node.Content, keyNode, valNode)
}

func (ym *yamlMap) SetNode(key string, n *yaml.Node) {
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	ym.node.Content = append(ym.node.Content, keyNode, n)
}

func (ym *yamlMap) Marshal() ([]byte, error) {
	return yaml.Marshal(ym.node)
}

func base64KeyString(key [32]byte) string {
	if key == [32]byte{} {
		return "<base64 key>"
	}
	return base64.StdEncoding.EncodeToString(key[:])
}

// --- Config marshal functions ---

func MarshalClientConfig(cfg *ClientConfig) ([]byte, error) {
	pub := crypto.PublicKey(cfg.PrivateKey)

	m := newYAMLMap()
	m.Set("private_key", base64KeyString(cfg.PrivateKey))
	m.Set("public_key", base64KeyString(pub))
	m.Set("bridge_name", cfg.BridgeName)
	m.Set("clamp_mss_to_mtu", cfg.ClampMSSToMTU)
	m.Set("clamp_mss_table", cfg.ClampMSSTable)
	m.Set("neigh_suppress", cfg.NeighSuppress)
	m.Set("vxlan_firewall", cfg.VxlanFirewall)
	m.Set("vxlan_firewall_table", cfg.VxlanFirewallTable)

	afs := newYAMLMap()
	for _, name := range sortedAFNames(cfg.AFSettings) {
		afs.SetNode(string(name), marshalClientAF(cfg.AFSettings[name]))
	}
	m.SetNode("address_families", afs.node)

	m.Set("init_timeout", int(cfg.InitTimeout/time.Second))
	m.Set("stats_interval_s", int(cfg.StatsInterval/time.Second))
	m.Set("probe_window_size", cfg.ProbeWindowSize)
	m.Set("af_switch_cost", cfg.AFSwitchCost)
	m.Set("ntp_servers", cfg.NTPServers)
	m.Set("ntp_period_h", int(cfg.NTPPeriod/time.Hour))
	m.Set("ntp_rtt_threshold_ms", int(cfg.NTPRTTThreshold/time.Millisecond))
	m.Set("log_level", cfg.LogLevel)
	m.Set("api_socket", cfg.APISocket)
	m.Set("sync_check_interval_s", int(cfg.SyncCheckInterval/time.Second))
	m.Set("sync_check_max_delay", cfg.SyncCheckMaxDelay)

	return m.Marshal()
}

func marshalClientAF(af *ClientAFConfig) *yaml.Node {
	m := newYAMLMap()
	m.Set("enable", af.Enable)
	if af.AutoIPInterface != "" {
		m.Set("autoip_interface", af.AutoIPInterface)
	} else {
		m.Set("bind_addr", af.BindAddr.String())
	}
	m.Set("probe_port", af.ProbePort)
	m.Set("communication_port", af.CommunicationPort)
	m.Set("vxlan_name", af.VxlanName)
	m.Set("vxlan_vni", af.VxlanVNI)
	m.Set("vxlan_mtu", af.VxlanMTU)
	m.Set("vxlan_dst_port", af.VxlanDstPort)
	m.Set("vxlan_src_port_start", af.VxlanSrcPortStart)
	m.Set("vxlan_src_port_end", af.VxlanSrcPortEnd)
	m.Set("priority", af.Priority)
	m.Set("forward_cost", af.ForwardCost)

	if len(af.Controllers) > 0 {
		seq := &yaml.Node{Kind: yaml.SequenceNode}
		for _, ce := range af.Controllers {
			cm := newYAMLMap()
			cm.Set("pubkey", base64KeyString(ce.PubKey))
			cm.Set("addr", ce.Addr.String())
			seq.Content = append(seq.Content, cm.node)
		}
		m.SetNode("controllers", seq)
	}

	return m.node
}

func MarshalControllerConfig(cfg *ControllerConfig) ([]byte, error) {
	pub := crypto.PublicKey(cfg.PrivateKey)

	m := newYAMLMap()
	m.Set("private_key", base64KeyString(cfg.PrivateKey))
	m.Set("public_key", base64KeyString(pub))
	m.Set("cost_mode", cfg.CostMode)
	m.Set("client_offline_timeout", int(cfg.ClientOfflineTimeout/time.Second))
	m.Set("sync_new_client_debounce", int(cfg.SyncNewClientDebounce/time.Second))
	m.Set("sync_new_client_debounce_max", int(cfg.SyncNewClientDebounceMax/time.Second))
	m.Set("topology_update_debounce", int(cfg.TopologyUpdateDebounce/time.Second))
	m.Set("topology_update_debounce_max", int(cfg.TopologyUpdateDebounceMax/time.Second))
	m.Set("probing", cfg.Probing)
	m.Set("log_level", cfg.LogLevel)
	m.Set("api_socket", cfg.APISocket)

	afs := newYAMLMap()
	for _, name := range sortedAFNames(cfg.AFSettings) {
		afs.SetNode(string(name), marshalControllerAF(cfg.AFSettings[name]))
	}
	m.SetNode("address_families", afs.node)

	if len(cfg.AllowedClients) > 0 {
		seq := &yaml.Node{Kind: yaml.SequenceNode}
		for _, pc := range cfg.AllowedClients {
			seq.Content = append(seq.Content, marshalPerClient(&pc))
		}
		m.SetNode("allowed_clients", seq)
	}

	if len(cfg.StaticCosts) > 0 {
		m.Set("static_costs", cfg.StaticCosts)
	}

	if cfg.WebUI != nil {
		m.Set("web_ui", cfg.WebUI)
	}

	return m.Marshal()
}

func marshalControllerAF(af *ControllerAFConfig) *yaml.Node {
	m := newYAMLMap()
	m.Set("enable", af.Enable)
	if af.AutoIPInterface != "" {
		m.Set("autoip_interface", af.AutoIPInterface)
	} else {
		m.Set("bind_addr", af.BindAddr.String())
	}
	m.Set("communication_port", af.CommunicationPort)
	m.Set("vxlan_vni", af.VxlanVNI)
	m.Set("vxlan_dst_port", af.VxlanDstPort)
	m.Set("vxlan_src_port_start", af.VxlanSrcPortStart)
	m.Set("vxlan_src_port_end", af.VxlanSrcPortEnd)
	return m.node
}

func marshalPerClient(pc *types.PerClientConfig) *yaml.Node {
	m := newYAMLMap()
	m.Set("client_id", base64KeyString(pc.ClientID))
	m.Set("client_name", pc.ClientName)
	if len(pc.AFSettings) > 0 {
		m.Set("af_settings", pc.AFSettings)
	}
	return m.node
}

func sortedAFNames[V any](m map[types.AFName]V) []types.AFName {
	names := make([]types.AFName, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	return names
}

// NodeSetField sets or adds a YAML key in a document node's root mapping.
func NodeSetField(doc *yaml.Node, key string, value interface{}) error {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node")
	}

	var valDoc yaml.Node
	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, &valDoc); err != nil {
		return err
	}
	valNode := &valDoc
	if valDoc.Kind == yaml.DocumentNode && len(valDoc.Content) > 0 {
		valNode = valDoc.Content[0]
	}

	for i := 0; i < len(root.Content)-1; i += 2 {
		if root.Content[i].Value == key {
			root.Content[i+1] = valNode
			return nil
		}
	}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key},
		valNode,
	)
	return nil
}
