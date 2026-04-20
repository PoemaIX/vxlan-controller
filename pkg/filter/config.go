package filter

import "gopkg.in/yaml.v3"

// FilterConfig holds the Lua scripts and rate limit settings for one filter set.
type FilterConfig struct {
	InputMcast  string
	OutputMcast string
	InputRoute  string
	OutputRoute string
	RateLimit   RateLimitConfig
	BaseDir     string // working directory for Lua require() and @file paths
}

// RateLimitConfig specifies rate limits for multicast packets.
type RateLimitConfig struct {
	PerMAC    float64 // pps per source MAC, default 64
	PerClient float64 // pps total per client, default 1000
}

// DefaultFilterConfig returns a FilterConfig with default scripts and rate limits.
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		InputMcast:  DefaultInputMcastScript,
		OutputMcast: DefaultOutputMcastScript,
		InputRoute:  DefaultRouteScript,
		OutputRoute: DefaultRouteScript,
		RateLimit: RateLimitConfig{
			PerMAC:    DefaultPerMACRate,
			PerClient: DefaultPerClientRate,
		},
	}
}

// ParseFilterNode converts a YAML node into a FilterConfig, filling defaults.
// Supported YAML keys:
//   - input_mcast / input_mcast_file (inline Lua or file path)
//   - output_mcast / output_mcast_file
//   - input_route / input_route_file
//   - output_route / output_route_file
//   - rate_limit: {per_mac: float, per_client: float}
func ParseFilterNode(node *yaml.Node, baseDir string) *FilterConfig {
	cfg := DefaultFilterConfig()
	cfg.BaseDir = baseDir

	if node == nil {
		return cfg
	}

	m := yamlNodeMap(node)

	resolveFilter := func(dst *string, inlineKey, fileKey string) {
		if n, ok := m[inlineKey]; ok && n.Value != "" {
			*dst = n.Value
		} else if n, ok := m[fileKey]; ok && n.Value != "" {
			*dst = "@" + n.Value
		}
	}

	resolveFilter(&cfg.InputMcast, "input_mcast", "input_mcast_file")
	resolveFilter(&cfg.OutputMcast, "output_mcast", "output_mcast_file")
	resolveFilter(&cfg.InputRoute, "input_route", "input_route_file")
	resolveFilter(&cfg.OutputRoute, "output_route", "output_route_file")

	if rlNode, ok := m["rate_limit"]; ok {
		rlMap := yamlNodeMap(rlNode)
		if n, ok := rlMap["per_mac"]; ok {
			var v float64
			if n.Decode(&v) == nil {
				cfg.RateLimit.PerMAC = v
			}
		}
		if n, ok := rlMap["per_client"]; ok {
			var v float64
			if n.Decode(&v) == nil {
				cfg.RateLimit.PerClient = v
			}
		}
	}

	return cfg
}

func yamlNodeMap(node *yaml.Node) map[string]*yaml.Node {
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

// FilterSet holds the four filter engines for one endpoint (client or per-client on controller).
type FilterSet struct {
	InputMcast  *FilterEngine
	OutputMcast *FilterEngine
	InputRoute  *FilterEngine
	OutputRoute *FilterEngine
}

// NewFilterSet creates a FilterSet from a FilterConfig.
func NewFilterSet(cfg *FilterConfig) (*FilterSet, error) {
	if cfg == nil {
		cfg = DefaultFilterConfig()
	}

	inputMcast, err := NewFilterEngine(cfg.InputMcast, &cfg.RateLimit, cfg.BaseDir)
	if err != nil {
		return nil, err
	}
	outputMcast, err := NewFilterEngine(cfg.OutputMcast, &cfg.RateLimit, cfg.BaseDir)
	if err != nil {
		return nil, err
	}
	inputRoute, err := NewFilterEngine(cfg.InputRoute, nil, cfg.BaseDir)
	if err != nil {
		return nil, err
	}
	outputRoute, err := NewFilterEngine(cfg.OutputRoute, nil, cfg.BaseDir)
	if err != nil {
		return nil, err
	}

	return &FilterSet{
		InputMcast:  inputMcast,
		OutputMcast: outputMcast,
		InputRoute:  inputRoute,
		OutputRoute: outputRoute,
	}, nil
}

// Close releases all Lua VMs.
func (fs *FilterSet) Close() {
	if fs == nil {
		return
	}
	fs.InputMcast.Close()
	fs.OutputMcast.Close()
	fs.InputRoute.Close()
	fs.OutputRoute.Close()
}
