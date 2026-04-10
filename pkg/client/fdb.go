package client

import (
	"bytes"
	"net"

	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fdbKey struct {
	MAC string
}

type fdbEntry struct {
	DevName string
	DstIP   net.IP
}

// fdbReconcileLoop watches for RouteMatrix/RouteTable changes and updates kernel FDB.
func (c *Client) fdbReconcileLoop() {
	// Wait for init
	select {
	case <-c.initDone:
	case <-c.ctx.Done():
		return
	}

	for {
		select {
		case <-c.fdbNotifyCh:
			c.reconcileFDB()
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) reconcileFDB() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.AuthorityCtrl == nil {
		return
	}

	cc, ok := c.Controllers[*c.AuthorityCtrl]
	if !ok || cc.State == nil {
		return
	}

	view := cc.State

	vlog.Debugf("[Client] FDB reconcile: RouteMatrix=%d rows, RouteTable=%d entries, Clients=%d",
		len(view.RouteMatrix), len(view.RouteTable), len(view.Clients))

	// Helper to resolve client name
	nameOf := func(id types.ClientID) string {
		if ci, ok := view.Clients[id]; ok && ci.ClientName != "" {
			return ci.ClientName
		}
		return id.Hex()[:8]
	}

	// Log all client endpoints for debugging
	for cid, ci := range view.Clients {
		for af, ep := range ci.Endpoints {
			vlog.Verbosef("[Client] FDB debug: client %s(%s) af=%s endpoint=%s", nameOf(cid), cid.Hex()[:8], af, ep.IP)
		}
	}

	// Log my routes for debugging
	if myRoutes, ok := view.RouteMatrix[c.ClientID]; ok {
		for dst, re := range myRoutes {
			vlog.Verbosef("[Client] FDB route: me -> %s nextHop=%s af=%s", nameOf(dst), nameOf(re.NextHop), re.AF)
		}
	} else {
		vlog.Verbosef("[Client] FDB route: no routes for my ID %s in RouteMatrix", c.ClientID.Hex()[:8])
	}

	desiredFDB := make(map[fdbKey]fdbEntry)

	for _, rtEntry := range view.RouteTable {
		macStr := rtEntry.MAC.String()

		// Select owner: the one with lowest latency in LatencyMatrix
		ownerClient := c.selectRouteOwner(rtEntry, view)
		if ownerClient == nil {
			vlog.Verbosef("[Client] FDB skip %s: no reachable owner", macStr)
			continue
		}

		// Lookup route from me to the owner
		myRoutes, ok := view.RouteMatrix[c.ClientID]
		if !ok {
			vlog.Verbosef("[Client] FDB skip %s: my ID %s not in RouteMatrix", macStr, c.ClientID.Hex()[:8])
			continue
		}
		routeEntry, ok := myRoutes[*ownerClient]
		if !ok {
			vlog.Verbosef("[Client] FDB skip %s: no route to owner %s", macStr, nameOf(*ownerClient))
			continue
		}

		// Find the nexthop's endpoint for the chosen AF
		nextHopInfo, ok := view.Clients[routeEntry.NextHop]
		if !ok {
			vlog.Verbosef("[Client] FDB skip %s: nexthop %s not in Clients", macStr, nameOf(routeEntry.NextHop))
			continue
		}
		ep, ok := nextHopInfo.Endpoints[routeEntry.AF]
		if !ok {
			vlog.Verbosef("[Client] FDB skip %s: nexthop %s has no endpoint for AF %s", macStr, nameOf(routeEntry.NextHop), routeEntry.AF)
			continue
		}

		// Find the vxlan device for this AF
		vxlanDev, ok := c.VxlanDevs[routeEntry.AF]
		if !ok {
			vlog.Verbosef("[Client] FDB skip %s: no local vxlan device for AF %s", macStr, routeEntry.AF)
			continue
		}

		key := fdbKey{MAC: macStr}
		desiredFDB[key] = fdbEntry{
			DevName: vxlanDev.Name,
			DstIP:   ep.IP.AsSlice(),
		}
	}

	// Build set of locally-owned MACs so we never install remote FDB entries
	// for addresses that belong to this node (e.g. the bridge device MAC).
	// Without this, a remote site announcing the same MAC would overwrite the
	// bridge's native local FDB entry, and withdrawal would then delete it.
	c.macMu.RLock()
	localMACSet := make(map[string]struct{}, len(c.LocalMACs))
	for _, lm := range c.LocalMACs {
		localMACSet[net.HardwareAddr(lm.MAC).String()] = struct{}{}
	}
	c.macMu.RUnlock()

	// Also add FDB entries for routes from RouteMatrix that have direct MAC entries
	// from remote clients
	for clientID, ci := range view.Clients {
		if clientID == c.ClientID {
			continue
		}
		myRoutes, ok := view.RouteMatrix[c.ClientID]
		if !ok {
			continue
		}
		routeEntry, ok := myRoutes[clientID]
		if !ok {
			continue
		}

		nextHopInfo, ok := view.Clients[routeEntry.NextHop]
		if !ok {
			continue
		}
		ep, ok := nextHopInfo.Endpoints[routeEntry.AF]
		if !ok {
			continue
		}

		vxlanDev, ok := c.VxlanDevs[routeEntry.AF]
		if !ok {
			continue
		}

		for _, route := range ci.Routes {
			key := fdbKey{MAC: route.MAC.String()}
			if _, local := localMACSet[key.MAC]; local {
				continue // never overwrite locally-owned MACs
			}
			if _, exists := desiredFDB[key]; !exists {
				desiredFDB[key] = fdbEntry{
					DevName: vxlanDev.Name,
					DstIP:   ep.IP.AsSlice(),
				}
			}
		}
	}

	// Diff and apply
	// Delete entries no longer needed
	for key, entry := range c.CurrentFDB {
		desired, ok := desiredFDB[key]
		if !ok || desired.DevName != entry.DevName || !desired.DstIP.Equal(entry.DstIP) {
			c.deleteFDBEntry(key, entry)
		}
	}

	// Add/update entries
	for key, entry := range desiredFDB {
		current, ok := c.CurrentFDB[key]
		if !ok || current.DevName != entry.DevName || !current.DstIP.Equal(entry.DstIP) {
			if ok {
				c.deleteFDBEntry(key, current)
			}
			c.addFDBEntry(key, entry)
		}
	}

	c.CurrentFDB = desiredFDB
}

func (c *Client) selectRouteOwner(rtEntry *types.RouteTableEntry, view *ControllerView) *types.ClientID {
	var bestClient *types.ClientID
	bestHops := -1

	for clientID := range rtEntry.Owners {
		if clientID == c.ClientID {
			// Local owner — highest priority
			id := clientID
			return &id
		}

		hops := countHops(view.RouteMatrix, c.ClientID, clientID, len(view.Clients))
		if hops < 0 {
			continue // unreachable
		}

		if bestClient == nil || hops < bestHops ||
			(hops == bestHops && bytes.Compare(clientID[:], (*bestClient)[:]) < 0) {
			id := clientID
			bestClient = &id
			bestHops = hops
		}
	}

	return bestClient
}

// countHops traces the NextHop chain in RouteMatrix from src to dst.
// Returns hop count, or -1 if unreachable.
func countHops(rm map[types.ClientID]map[types.ClientID]*types.RouteEntry, src, dst types.ClientID, maxNodes int) int {
	current := src
	for hops := 0; hops <= maxNodes; hops++ {
		if current == dst {
			return hops
		}
		dsts, ok := rm[current]
		if !ok {
			return -1
		}
		entry, ok := dsts[dst]
		if !ok {
			return -1
		}
		current = entry.NextHop
	}
	return -1 // loop detected
}

func (c *Client) addFDBEntry(key fdbKey, entry fdbEntry) {
	mac, err := net.ParseMAC(key.MAC)
	if err != nil {
		return
	}

	link, err := netlink.LinkByName(entry.DevName)
	if err != nil {
		vlog.Errorf("[Client] FDB add: link %s not found: %v", entry.DevName, err)
		return
	}
	linkIdx := link.Attrs().Index

	// self: tells vxlan device to encapsulate to dst IP (NUD_PERMANENT)
	selfNeigh := &netlink.Neigh{
		LinkIndex:    linkIdx,
		Family:       unix.AF_BRIDGE,
		State:        netlink.NUD_PERMANENT,
		Flags:        netlink.NTF_SELF,
		HardwareAddr: mac,
		IP:           entry.DstIP,
	}
	if err := netlink.NeighAppend(selfNeigh); err != nil {
		vlog.Errorf("[Client] FDB self append %s -> %s via %s: %v", key.MAC, entry.DstIP, entry.DevName, err)
	}

	// master: tells bridge to forward to vxlan port (avoids unknown unicast flooding).
	// Must use NUD_NOARP ("static") — NUD_PERMANENT master entries on vxlan bridge
	// ports silently break the bridge→vxlan TX path on this kernel.
	masterNeigh := &netlink.Neigh{
		LinkIndex:    linkIdx,
		Family:       unix.AF_BRIDGE,
		State:        netlink.NUD_NOARP,
		Flags:        netlink.NTF_MASTER,
		HardwareAddr: mac,
	}
	if err := netlink.NeighAppend(masterNeigh); err != nil {
		vlog.Errorf("[Client] FDB master append %s via %s: %v", key.MAC, entry.DevName, err)
	}

	vlog.Debugf("[Client] FDB added %s -> %s via %s", key.MAC, entry.DstIP, entry.DevName)
}

func (c *Client) deleteFDBEntry(key fdbKey, entry fdbEntry) {
	mac, err := net.ParseMAC(key.MAC)
	if err != nil {
		return
	}

	link, err := netlink.LinkByName(entry.DevName)
	if err != nil {
		return
	}
	linkIdx := link.Attrs().Index

	// Delete self and master entries
	netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    linkIdx,
		Family:       unix.AF_BRIDGE,
		State:        netlink.NUD_PERMANENT,
		Flags:        netlink.NTF_SELF,
		HardwareAddr: mac,
		IP:           entry.DstIP,
	})
	netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    linkIdx,
		Family:       unix.AF_BRIDGE,
		State:        netlink.NUD_NOARP,
		Flags:        netlink.NTF_MASTER,
		HardwareAddr: mac,
	})
}

func (c *Client) cleanupFDB() {
	for key, entry := range c.CurrentFDB {
		c.deleteFDBEntry(key, entry)
	}
	c.CurrentFDB = make(map[fdbKey]fdbEntry)
}

func (c *Client) notifyFDB() {
	select {
	case c.fdbNotifyCh <- struct{}{}:
	default:
	}
}
