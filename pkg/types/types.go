package types

import (
	"encoding/hex"
	"net"
	"net/netip"
	"time"

	"vxlan-controller/pkg/filter"
)

// ClientID is an X25519 public key, 32 bytes.
type ClientID [32]byte

func (id ClientID) Hex() string {
	return hex.EncodeToString(id[:])
}

func ClientIDFromHex(s string) (ClientID, error) {
	var id ClientID
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, err
	}
	copy(id[:], b)
	return id, nil
}

// ControllerID is the same as ClientID (X25519 public key).
type ControllerID = ClientID

// AFName represents an address family, e.g. "v4", "v6", "asia_v4".
type AFName string

// ChannelName names a channel within an AF (multiple ISPs per AF).
type ChannelName string

// DefaultChannelName is the name assigned to the first/only channel of an AF.
const DefaultChannelName ChannelName = "ISP1"

// Endpoint represents a connection endpoint for a given (AF, channel).
type Endpoint struct {
	IP           netip.Addr
	ProbePort    uint16
	VxlanDstPort uint16
}

// PerClientConfig is the Controller's per-client configuration.
type PerClientConfig struct {
	ClientID   ClientID
	ClientName string
	Filters    *filter.FilterConfig
	AFSettings map[AFName]map[ChannelName]*PerClientChannelConfig
}

// PerClientChannelConfig is per-(AF, channel) settings for a client on the controller.
type PerClientChannelConfig struct {
	EndpointOverride string `yaml:"endpoint_override,omitempty"`
}

// ClientInfo is maintained by the Controller for each connected Client.
type ClientInfo struct {
	ClientID   ClientID
	ClientName string
	Endpoints  map[AFName]map[ChannelName]*Endpoint
	LastSeen   time.Time
	Routes     []Type2Route
}

// Type2Route mimics EVPN Type-2 route.
type Type2Route struct {
	MAC net.HardwareAddr
	IP  netip.Addr
}

// AFLatency stores probe results for a single (AF, channel) between two clients.
type AFLatency struct {
	Mean        float64
	Std         float64
	PacketLoss  float64
	Priority    int
	ForwardCost float64
	SwitchCost  float64
	QualityCost float64 // abstract quality metric (currently = latency_mean)
	FinalCost   float64 // quality_cost + forward_cost + switch_cost
}

// LatencyInfo stores all per-(AF, channel) probe data between a src→dst client pair.
type LatencyInfo struct {
	AFs           map[AFName]map[ChannelName]*AFLatency // debounced (used for routing)
	RawAFs        map[AFName]map[ChannelName]*AFLatency // raw latest probe result
	LastReachable time.Time                             // last time any AF was reachable (packet_loss < 1.0)
}

// BestPath selects the best (AF, channel) and returns (af, channel, cost).
// Selection: lowest priority first, then lowest final_cost.
// Returns ("", "", INF_LATENCY) if nothing is reachable.
func (li *LatencyInfo) BestPath() (AFName, ChannelName, float64) {
	bestAF := AFName("")
	bestCh := ChannelName("")
	bestCost := INF_LATENCY
	bestPriority := int(1<<31 - 1)

	for af, chans := range li.AFs {
		for ch, al := range chans {
			if al.Mean >= INF_LATENCY {
				continue
			}
			cost := al.FinalCost
			if cost == 0 {
				cost = al.QualityCost + al.ForwardCost + al.SwitchCost
			}
			if al.Priority < bestPriority ||
				(al.Priority == bestPriority && cost < bestCost) {
				bestPriority = al.Priority
				bestCost = cost
				bestAF = af
				bestCh = ch
			}
		}
	}
	return bestAF, bestCh, bestCost
}

// BestPathEntry is a precomputed BestPath result.
type BestPathEntry struct {
	AF      AFName
	Channel ChannelName
	Cost    float64    // final_cost for routing (used by Floyd-Warshall)
	Raw     *AFLatency // debounced probe data for the selected (af, channel)
	Latest  *AFLatency // raw latest probe data for the selected (af, channel) (webui display)
}

// lookupLatency returns li.AFs[af][ch] (or li.RawAFs[af][ch]) safely.
func lookupChan(m map[AFName]map[ChannelName]*AFLatency, af AFName, ch ChannelName) *AFLatency {
	if m == nil {
		return nil
	}
	cm, ok := m[af]
	if !ok {
		return nil
	}
	return cm[ch]
}

// ComputeBestPaths precomputes BestPath() for every src→dst pair.
func ComputeBestPaths(m map[ClientID]map[ClientID]*LatencyInfo) map[ClientID]map[ClientID]*BestPathEntry {
	result := make(map[ClientID]map[ClientID]*BestPathEntry, len(m))
	for src, dsts := range m {
		row := make(map[ClientID]*BestPathEntry, len(dsts))
		for dst, li := range dsts {
			af, ch, cost := li.BestPath()
			if af != "" {
				bp := &BestPathEntry{
					AF:      af,
					Channel: ch,
					Cost:    cost,
					Raw:     lookupChan(li.AFs, af, ch),
					Latest:  lookupChan(li.RawAFs, af, ch),
				}
				row[dst] = bp
			}
		}
		result[src] = row
	}
	return result
}

// ComputeBestPathsStatic computes best paths using static costs.
// Probed LatencyMatrix is still used for reachability: if an (af, channel) has
// PacketLoss == 1.0, it is considered unreachable even if a static cost is defined.
// staticCosts is indexed: [src][dst][af][channel] -> cost.
func ComputeBestPathsStatic(
	latencyMatrix map[ClientID]map[ClientID]*LatencyInfo,
	staticCosts map[ClientID]map[ClientID]map[AFName]map[ChannelName]float64,
) map[ClientID]map[ClientID]*BestPathEntry {
	result := make(map[ClientID]map[ClientID]*BestPathEntry)

	for src, dsts := range staticCosts {
		row := make(map[ClientID]*BestPathEntry)
		for dst, afs := range dsts {
			var bestAF AFName
			var bestCh ChannelName
			bestCost := INF_LATENCY

			for af, chans := range afs {
				for ch, cost := range chans {
					// Check reachability from probe data.
					li, srcOK := latencyMatrix[src]
					if !srcOK {
						continue
					}
					info, dstOK := li[dst]
					if !dstOK {
						continue
					}
					al := lookupChan(info.AFs, af, ch)
					if al == nil || al.PacketLoss >= 1.0 {
						continue
					}
					if cost < bestCost {
						bestCost = cost
						bestAF = af
						bestCh = ch
					}
				}
			}

			if bestAF != "" {
				var raw, latest *AFLatency
				if li, ok := latencyMatrix[src]; ok {
					if info, ok := li[dst]; ok {
						raw = lookupChan(info.AFs, bestAF, bestCh)
						latest = lookupChan(info.RawAFs, bestAF, bestCh)
					}
				}
				row[dst] = &BestPathEntry{
					AF:      bestAF,
					Channel: bestCh,
					Cost:    bestCost,
					Raw:     raw,
					Latest:  latest,
				}
			}
		}
		if len(row) > 0 {
			result[src] = row
		}
	}

	return result
}

// RouteEntry is a single cell in RouteMatrix.
type RouteEntry struct {
	NextHop ClientID
	AF      AFName
	Channel ChannelName
}

// RouteTableEntry stores MAC/IP ownership.
type RouteTableEntry struct {
	MAC    net.HardwareAddr
	IP     netip.Addr
	Owners map[ClientID]time.Time // client_id -> ExpireTime
}

// INF_LATENCY represents unreachable.
const INF_LATENCY = 1e18
