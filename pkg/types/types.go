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

// Endpoint represents a connection endpoint for a given AF.
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
	AFSettings map[AFName]*PerClientAFConfig
}

// PerClientAFConfig is per-AF settings for a client on the controller.
type PerClientAFConfig struct {
	EndpointOverride string `yaml:"endpoint_override,omitempty"`
}

// ClientInfo is maintained by the Controller for each connected Client.
type ClientInfo struct {
	ClientID   ClientID
	ClientName string
	Endpoints  map[AFName]*Endpoint
	LastSeen   time.Time
	Routes     []Type2Route
}

// Type2Route mimics EVPN Type-2 route.
type Type2Route struct {
	MAC net.HardwareAddr
	IP  netip.Addr
}

// AFLatency stores probe results for a single AF between two clients.
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

// LatencyInfo stores all per-AF probe data between a src→dst client pair.
type LatencyInfo struct {
	AFs           map[AFName]*AFLatency // debounced (used for routing)
	RawAFs        map[AFName]*AFLatency // raw latest probe result
	LastReachable time.Time             // last time any AF was reachable (packet_loss < 1.0)
}

// BestPath selects the best AF and returns (af, cost).
// Selection: lowest priority first, then lowest final_cost.
// Returns ("", INF_LATENCY) if no AF is reachable.
func (li *LatencyInfo) BestPath() (AFName, float64) {
	bestAF := AFName("")
	bestCost := INF_LATENCY
	bestPriority := int(1<<31 - 1)

	for af, al := range li.AFs {
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
		}
	}
	return bestAF, bestCost
}

// BestPathEntry is a precomputed BestPath result.
type BestPathEntry struct {
	AF     AFName
	Cost   float64    // final_cost for routing (used by Floyd-Warshall)
	Raw    *AFLatency // debounced probe data for the selected AF
	Latest *AFLatency // raw latest probe data for the selected AF (webui display)
}

// ComputeBestPaths precomputes BestPath() for every src→dst pair.
func ComputeBestPaths(m map[ClientID]map[ClientID]*LatencyInfo) map[ClientID]map[ClientID]*BestPathEntry {
	result := make(map[ClientID]map[ClientID]*BestPathEntry, len(m))
	for src, dsts := range m {
		row := make(map[ClientID]*BestPathEntry, len(dsts))
		for dst, li := range dsts {
			af, cost := li.BestPath()
			if af != "" {
				bp := &BestPathEntry{AF: af, Cost: cost, Raw: li.AFs[af]}
				if li.RawAFs != nil {
					bp.Latest = li.RawAFs[af]
				}
				row[dst] = bp
			}
		}
		result[src] = row
	}
	return result
}

// ComputeBestPathsStatic computes best paths using static costs.
// Probed LatencyMatrix is still used for reachability: if an AF has PacketLoss == 1.0,
// it is considered unreachable even if a static cost is defined.
// staticCosts is indexed by ClientID: [src][dst][af] -> cost.
func ComputeBestPathsStatic(
	latencyMatrix map[ClientID]map[ClientID]*LatencyInfo,
	staticCosts map[ClientID]map[ClientID]map[AFName]float64,
) map[ClientID]map[ClientID]*BestPathEntry {
	result := make(map[ClientID]map[ClientID]*BestPathEntry)

	for src, dsts := range staticCosts {
		row := make(map[ClientID]*BestPathEntry)
		for dst, afs := range dsts {
			var bestAF AFName
			bestCost := INF_LATENCY

			for af, cost := range afs {
				// Check reachability from probe data.
				// Require probe data to confirm the AF is actually usable —
				// if there's no probe data at all (e.g. destination has no
				// endpoint for this AF), treat as unreachable.
				li, srcOK := latencyMatrix[src]
				if !srcOK {
					continue // no probe data from source
				}
				info, dstOK := li[dst]
				if !dstOK {
					continue // no probe data for this pair
				}
				al, afOK := info.AFs[af]
				if !afOK || al.PacketLoss >= 1.0 {
					continue // no probe data for this AF, or unreachable
				}
				if cost < bestCost {
					bestCost = cost
					bestAF = af
				}
			}

			if bestAF != "" {
				var raw, latest *AFLatency
				if li, ok := latencyMatrix[src]; ok {
					if info, ok := li[dst]; ok {
						raw = info.AFs[bestAF]
						if info.RawAFs != nil {
							latest = info.RawAFs[bestAF]
						}
					}
				}
				row[dst] = &BestPathEntry{AF: bestAF, Cost: bestCost, Raw: raw, Latest: latest}
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
}

// RouteTableEntry stores MAC/IP ownership.
type RouteTableEntry struct {
	MAC    net.HardwareAddr
	IP     netip.Addr
	Owners map[ClientID]time.Time // client_id -> ExpireTime
}

// INF_LATENCY represents unreachable.
const INF_LATENCY = 1e18
