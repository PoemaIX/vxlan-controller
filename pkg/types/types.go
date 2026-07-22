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

// ChannelPair identifies one probed link between two nodes: the local node's
// uplink (Local) and the peer node's uplink (Peer). Channel names are per-node
// labels — the two ends of a link may use different names — so both sides are
// needed to identify an edge.
type ChannelPair struct {
	Local ChannelName
	Peer  ChannelName
}

// DefaultChannelName is the name assigned to the first/only channel of an AF.
const DefaultChannelName ChannelName = "ISP1"

// Endpoint represents a connection endpoint for a given (AF, channel).
type Endpoint struct {
	IP           netip.Addr
	ProbePort    uint16
	VxlanDstPort uint16
	// IspName is the operator-assigned label for this uplink (e.g. "hinet").
	// Empty defaults to the channel name. Used by peers to match
	// channel_additional_costs rules.
	IspName string
	// Advertised bandwidth in kbit/s, used by the sender's rate limiter to
	// avoid overwhelming a slow peer. 0 = unset (treated as unlimited).
	UpBwKbps   uint64
	DownBwKbps uint64
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

// LatencyInfo stores all per-(AF, channel pair) probe data between a src→dst client pair.
type LatencyInfo struct {
	AFs           map[AFName]map[ChannelPair]*AFLatency // debounced (used for routing)
	RawAFs        map[AFName]map[ChannelPair]*AFLatency // raw latest probe result
	LastReachable time.Time                             // last time any AF was reachable (packet_loss < 1.0)
}

// BestPath selects the best (AF, channel pair) and returns (af, pair, cost).
// Selection: lowest priority first, then lowest final_cost.
// Returns ("", {}, INF_LATENCY) if nothing is reachable.
func (li *LatencyInfo) BestPath() (AFName, ChannelPair, float64) {
	bestAF := AFName("")
	bestPair := ChannelPair{}
	bestCost := INF_LATENCY
	bestPriority := int(1<<31 - 1)

	for af, pairs := range li.AFs {
		for pair, al := range pairs {
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
				bestPair = pair
			}
		}
	}
	return bestAF, bestPair, bestCost
}

// BestPathEntry is a precomputed BestPath result.
type BestPathEntry struct {
	AF          AFName
	Channel     ChannelName // local (src-side) channel
	PeerChannel ChannelName // channel on the dst side
	Cost        float64     // final_cost for routing (used by Floyd-Warshall)
	Raw         *AFLatency  // debounced probe data for the selected (af, pair)
	Latest      *AFLatency  // raw latest probe data for the selected (af, pair) (webui display)
}

// lookupChan returns m[af][pair] safely.
func lookupChan(m map[AFName]map[ChannelPair]*AFLatency, af AFName, pair ChannelPair) *AFLatency {
	if m == nil {
		return nil
	}
	cm, ok := m[af]
	if !ok {
		return nil
	}
	return cm[pair]
}

// ComputeBestPaths precomputes BestPath() for every src→dst pair.
func ComputeBestPaths(m map[ClientID]map[ClientID]*LatencyInfo) map[ClientID]map[ClientID]*BestPathEntry {
	result := make(map[ClientID]map[ClientID]*BestPathEntry, len(m))
	for src, dsts := range m {
		row := make(map[ClientID]*BestPathEntry, len(dsts))
		for dst, li := range dsts {
			af, pair, cost := li.BestPath()
			if af != "" {
				bp := &BestPathEntry{
					AF:          af,
					Channel:     pair.Local,
					PeerChannel: pair.Peer,
					Cost:        cost,
					Raw:         lookupChan(li.AFs, af, pair),
					Latest:      lookupChan(li.RawAFs, af, pair),
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

			var bestPair ChannelPair

			for af, chans := range afs {
				for ch, cost := range chans {
					// Check reachability from probe data. The static cost's
					// channel names the src node's local uplink; any reachable
					// pair using that local channel qualifies — pick the pair
					// with the best probed quality for the peer side.
					li, srcOK := latencyMatrix[src]
					if !srcOK {
						continue
					}
					info, dstOK := li[dst]
					if !dstOK {
						continue
					}
					pair, ok := bestReachablePair(info.AFs, af, ch)
					if !ok {
						continue
					}
					if cost < bestCost {
						bestCost = cost
						bestAF = af
						bestCh = ch
						bestPair = pair
					}
				}
			}

			if bestAF != "" {
				var raw, latest *AFLatency
				if li, ok := latencyMatrix[src]; ok {
					if info, ok := li[dst]; ok {
						raw = lookupChan(info.AFs, bestAF, bestPair)
						latest = lookupChan(info.RawAFs, bestAF, bestPair)
					}
				}
				row[dst] = &BestPathEntry{
					AF:          bestAF,
					Channel:     bestCh,
					PeerChannel: bestPair.Peer,
					Cost:        bestCost,
					Raw:         raw,
					Latest:      latest,
				}
			}
		}
		if len(row) > 0 {
			result[src] = row
		}
	}

	return result
}

// bestReachablePair scans m[af] for pairs whose Local channel is localCh and
// returns the reachable one (PacketLoss < 1.0) with the lowest latency mean.
func bestReachablePair(m map[AFName]map[ChannelPair]*AFLatency, af AFName, localCh ChannelName) (ChannelPair, bool) {
	best := ChannelPair{}
	bestMean := INF_LATENCY
	found := false
	for pair, al := range m[af] {
		if pair.Local != localCh || al == nil || al.PacketLoss >= 1.0 {
			continue
		}
		if !found || al.Mean < bestMean {
			best = pair
			bestMean = al.Mean
			found = true
		}
	}
	return best, found
}

// RouteEntry is a single cell in RouteMatrix.
type RouteEntry struct {
	NextHop ClientID
	AF      AFName
	Channel ChannelName // local channel on the node this route belongs to
	// PeerChannel is the uplink on the NextHop side; the FDB dst IP comes from
	// the nexthop's endpoint for this channel. Empty falls back to Channel.
	PeerChannel ChannelName
}

// RouteTableEntry stores MAC/IP ownership.
type RouteTableEntry struct {
	MAC    net.HardwareAddr
	IP     netip.Addr
	Owners map[ClientID]time.Time // client_id -> ExpireTime
}

// INF_LATENCY represents unreachable.
const INF_LATENCY = 1e18
