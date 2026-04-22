package controller

import (
	"vxlan-controller/pkg/types"
)

// computeRouteMatrix uses Floyd-Warshall on precomputed best paths.
// Each direct edge's (af, channel) comes from the best-path selection between
// the two endpoints.
func computeRouteMatrix(
	bestPaths map[types.ClientID]map[types.ClientID]*types.BestPathEntry,
	clients map[types.ClientID]*ClientInfo,
) map[types.ClientID]map[types.ClientID]*types.RouteEntry {
	// Collect all client IDs
	var nodes []types.ClientID
	nodeIdx := make(map[types.ClientID]int)
	for id := range clients {
		nodeIdx[id] = len(nodes)
		nodes = append(nodes, id)
	}
	n := len(nodes)
	if n == 0 {
		return make(map[types.ClientID]map[types.ClientID]*types.RouteEntry)
	}

	// Initialize cost matrix and next-hop matrix
	cost := make([][]float64, n)
	next := make([][]int, n)
	afMatrix := make([][]types.AFName, n)
	chMatrix := make([][]types.ChannelName, n)

	for i := 0; i < n; i++ {
		cost[i] = make([]float64, n)
		next[i] = make([]int, n)
		afMatrix[i] = make([]types.AFName, n)
		chMatrix[i] = make([]types.ChannelName, n)
		for j := 0; j < n; j++ {
			if i == j {
				cost[i][j] = 0
				next[i][j] = j
			} else {
				cost[i][j] = types.INF_LATENCY
				next[i][j] = -1
			}
		}
	}

	// Fill direct edges from precomputed best paths
	for src, dsts := range bestPaths {
		srcI, ok := nodeIdx[src]
		if !ok {
			continue
		}
		for dst, bp := range dsts {
			dstI, ok := nodeIdx[dst]
			if !ok {
				continue
			}
			if bp.Cost >= types.INF_LATENCY {
				continue
			}
			if bp.Cost < cost[srcI][dstI] {
				cost[srcI][dstI] = bp.Cost
				next[srcI][dstI] = dstI
				afMatrix[srcI][dstI] = bp.AF
				chMatrix[srcI][dstI] = bp.Channel
			}
		}
	}

	// Floyd-Warshall
	for k := 0; k < n; k++ {
		for i := 0; i < n; i++ {
			if cost[i][k] >= types.INF_LATENCY {
				continue
			}
			for j := 0; j < n; j++ {
				if cost[k][j] >= types.INF_LATENCY {
					continue
				}
				newCost := cost[i][k] + cost[k][j]
				if newCost < cost[i][j] {
					cost[i][j] = newCost
					next[i][j] = next[i][k]
					// (af, channel) for i->j is that of the first hop i->next[i][k]
				}
			}
		}
	}

	// Build RouteMatrix from next-hop matrix
	result := make(map[types.ClientID]map[types.ClientID]*types.RouteEntry)
	for i := 0; i < n; i++ {
		src := nodes[i]
		result[src] = make(map[types.ClientID]*types.RouteEntry)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			dst := nodes[j]
			if next[i][j] < 0 {
				continue // unreachable
			}
			nextHopIdx := next[i][j]
			nextHop := nodes[nextHopIdx]
			af := afMatrix[i][nextHopIdx]
			ch := chMatrix[i][nextHopIdx]
			result[src][dst] = &types.RouteEntry{
				NextHop: nextHop,
				AF:      af,
				Channel: ch,
			}
		}
	}

	return result
}
