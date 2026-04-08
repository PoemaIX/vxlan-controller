package controller

import (
	"time"

	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/webui"
)

// buildStateSnapshot creates a JSON-ready snapshot of controller state.
// Called from the webui push loop (every 1s).
func (c *Controller) buildStateSnapshot() *webui.StateSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	snap := &webui.StateSnapshot{}

	// Config (static)
	if c.Config.WebUI != nil {
		snap.Config.MacAliases = c.Config.WebUI.MacAliases
		if c.Config.WebUI.Nodes != nil {
			snap.Config.Nodes = make(map[string]webui.UINodeJSON, len(c.Config.WebUI.Nodes))
			for name, n := range c.Config.WebUI.Nodes {
				snap.Config.Nodes[name] = webui.UINodeJSON{
					Label: n.Label,
					Pos:   n.Pos,
				}
			}
		}
	}

	// Clients
	nameByID := make(map[types.ClientID]string)
	for _, pc := range c.Config.AllowedClients {
		nameByID[pc.ClientID] = pc.ClientName
	}

	now := time.Now()
	for id, ci := range c.State.Clients {
		name := ci.ClientName
		if name == "" {
			name = nameByID[id]
		}

		cj := webui.ClientJSON{
			ID:        id.Hex(),
			Name:      name,
			Online:    now.Sub(ci.LastSeen) < c.Config.ClientOfflineTimeout,
			LastSeen:  ci.LastSeen.UnixMilli(),
			Endpoints: make(map[string]webui.EndpointJSON),
		}

		for _, r := range ci.Routes {
			cr := webui.ClientRouteJSON{MAC: r.MAC.String()}
			if r.IP.IsValid() {
				cr.IP = r.IP.String()
			}
			cj.Routes = append(cj.Routes, cr)
		}

		for af, ep := range ci.Endpoints {
			cj.Endpoints[string(af)] = webui.EndpointJSON{IP: ep.IP.String()}
		}

		snap.Clients = append(snap.Clients, cj)
	}

	// Route table
	for _, entry := range c.State.RouteTable {
		rj := webui.RouteEntryJSON{
			MAC:    entry.MAC.String(),
			Owners: make(map[string]int64),
		}
		if entry.IP.IsValid() {
			rj.IP = entry.IP.String()
		}
		for cid, t := range entry.Owners {
			rj.Owners[cid.Hex()] = t.UnixMilli()
		}
		snap.RouteTable = append(snap.RouteTable, rj)
	}

	// Latency matrix (from precomputed best paths)
	for src, dsts := range c.State.BestPaths {
		row := webui.LatencyRowJSON{Src: src.Hex()}
		for dst, bp := range dsts {
			var latency float64
			if bp.Raw != nil {
				latency = bp.Raw.Mean
			}
			row.Entries = append(row.Entries, webui.LatencyCellJSON{
				Dst:     dst.Hex(),
				Latency: latency,
				AF:      string(bp.AF),
			})
		}
		snap.LatencyMatrix = append(snap.LatencyMatrix, row)
	}

	// Route matrix
	for src, dsts := range c.State.RouteMatrix {
		row := webui.RouteMatrixJSON{Src: src.Hex()}
		for dst, entry := range dsts {
			row.Entries = append(row.Entries, webui.RouteMatrixCellJSON{
				Dst:     dst.Hex(),
				NextHop: entry.NextHop.Hex(),
				AF:      string(entry.AF),
			})
		}
		snap.RouteMatrix = append(snap.RouteMatrix, row)
	}

	// Client-reported mcast stats
	snap.McastStats = make(map[string][]webui.MACStatsJSON)
	for clientID, stats := range c.clientMcastStats {
		clientName := clientID.Hex()[:8]
		if n, ok := nameByID[clientID]; ok {
			clientName = n
		}
		var macStats []webui.MACStatsJSON
		for mac, ms := range stats.MACs {
			entry := webui.MACStatsJSON{
				MAC:        mac,
				TxAccepted: ms.TxAccepted,
				TxRejected: ms.TxRejected,
				RxAccepted: ms.RxAccepted,
				RxRejected: ms.RxRejected,
			}
			for _, rr := range ms.RejectReasons {
				rj := webui.RejectReasonJSON{
					Direction: rr.Direction,
					Reason:    rr.Reason,
					Count:     rr.Count,
				}
				for _, d := range rr.Details {
					rj.Details = append(rj.Details, webui.RejectDetailJSON{
						Detail: d.Detail,
						Count:  d.Count,
					})
				}
				entry.RejectReasons = append(entry.RejectReasons, rj)
			}
			macStats = append(macStats, entry)
		}
		snap.McastStats[clientName] = macStats
	}

	return snap
}

// startWebUI launches the web UI HTTP server if configured.
func (c *Controller) startWebUI() {
	if c.Config.WebUI == nil {
		return
	}

	srv := webui.New(c.Config.WebUI, func() *webui.StateSnapshot {
		return c.buildStateSnapshot()
	})

	go srv.Run(c.ctx)
}
