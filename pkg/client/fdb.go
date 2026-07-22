package client

import (
	"bytes"
	"net"
	"os/exec"
	"strconv"
	"strings"

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
	// DstPort overrides the local vxlan device's default dstport for this
	// entry. Non-zero when the nexthop's channel advertises a different
	// vxlan_dst_port than our local device (cross-channel pairs).
	DstPort uint16
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

	// A freshly restarted controller pushes a state whose RouteMatrix hasn't
	// been computed yet (the first probe cycle takes a few seconds). Wiping
	// the FDB against that transient empty matrix would turn a seamless
	// controller restart into a data-plane outage — keep the last known
	// entries until a computed matrix arrives.
	if len(view.RouteMatrix) == 0 && len(c.CurrentFDB) > 0 {
		vlog.Debugf("[Client] FDB reconcile: route matrix empty (controller warming up), keeping %d existing entries", len(c.CurrentFDB))
		return
	}

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
		for af, chans := range ci.Endpoints {
			for ch, ep := range chans {
				vlog.Verbosef("[Client] FDB debug: client %s(%s) af=%s channel=%s endpoint=%s", nameOf(cid), cid.Hex()[:8], af, ch, ep.IP)
			}
		}
	}

	// Log my routes for debugging
	if myRoutes, ok := view.RouteMatrix[c.ClientID]; ok {
		for dst, re := range myRoutes {
			vlog.Verbosef("[Client] FDB route: me -> %s nextHop=%s af=%s channel=%s>%s", nameOf(dst), nameOf(re.NextHop), re.AF, re.Channel, re.PeerChannel)
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

		// Find the nexthop's endpoint for the chosen (af, channel)
		nextHopInfo, ok := view.Clients[routeEntry.NextHop]
		if !ok {
			vlog.Verbosef("[Client] FDB skip %s: nexthop %s not in Clients", macStr, nameOf(routeEntry.NextHop))
			continue
		}
		epChans, ok := nextHopInfo.Endpoints[routeEntry.AF]
		if !ok {
			vlog.Verbosef("[Client] FDB skip %s: nexthop %s has no endpoint for AF %s", macStr, nameOf(routeEntry.NextHop), routeEntry.AF)
			continue
		}
		ep, ok := epChans[peerChannelOf(routeEntry)]
		if !ok {
			vlog.Verbosef("[Client] FDB skip %s: nexthop %s has no endpoint for AF=%s channel=%s", macStr, nameOf(routeEntry.NextHop), routeEntry.AF, peerChannelOf(routeEntry))
			continue
		}

		// Find the vxlan device for this (af, channel)
		vdChans, ok := c.VxlanDevs[routeEntry.AF]
		if !ok {
			vlog.Verbosef("[Client] FDB skip %s: no local vxlan device for AF %s", macStr, routeEntry.AF)
			continue
		}
		vxlanDev, ok := vdChans[routeEntry.Channel]
		if !ok {
			vlog.Verbosef("[Client] FDB skip %s: no local vxlan device for AF=%s channel=%s", macStr, routeEntry.AF, routeEntry.Channel)
			continue
		}

		key := fdbKey{MAC: macStr}
		desiredFDB[key] = fdbEntry{
			DevName: vxlanDev.Name,
			DstIP:   ep.IP.AsSlice(),
			DstPort: c.fdbDstPort(routeEntry, ep),
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
		epChans, ok := nextHopInfo.Endpoints[routeEntry.AF]
		if !ok {
			continue
		}
		ep, ok := epChans[peerChannelOf(routeEntry)]
		if !ok {
			continue
		}

		vdChans, ok := c.VxlanDevs[routeEntry.AF]
		if !ok {
			continue
		}
		vxlanDev, ok := vdChans[routeEntry.Channel]
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
					DstPort: c.fdbDstPort(routeEntry, ep),
				}
			}
		}
	}

	// Diff and apply
	// Delete entries no longer needed
	for key, entry := range c.CurrentFDB {
		desired, ok := desiredFDB[key]
		if !ok || desired.DevName != entry.DevName || !desired.DstIP.Equal(entry.DstIP) || desired.DstPort != entry.DstPort {
			c.deleteFDBEntry(key, entry)
		}
	}

	// Add/update entries
	for key, entry := range desiredFDB {
		current, ok := c.CurrentFDB[key]
		if !ok || current.DevName != entry.DevName || !current.DstIP.Equal(entry.DstIP) || current.DstPort != entry.DstPort {
			if ok {
				c.deleteFDBEntry(key, current)
			}
			c.addFDBEntry(key, entry)
		}
	}

	c.CurrentFDB = desiredFDB
}

// fdbDstPort returns the per-entry dstport override for an FDB entry toward
// ep, or 0 when the nexthop channel's vxlan_dst_port matches our local
// device's default (no override needed). Must be called with c.mu held.
func (c *Client) fdbDstPort(re *types.RouteEntry, ep *types.Endpoint) uint16 {
	if ep.VxlanDstPort == 0 {
		return 0
	}
	if chans, ok := c.Config.AFSettings[re.AF]; ok {
		if cc, ok := chans[re.Channel]; ok && cc.VxlanDstPort == ep.VxlanDstPort {
			return 0
		}
	}
	return ep.VxlanDstPort
}

// peerChannelOf returns the channel to look up on the nexthop's endpoints.
// Local device selection keeps using RouteEntry.Channel; the dst IP must come
// from the nexthop side of the pair. Empty PeerChannel (old controller) falls
// back to the local channel name.
func peerChannelOf(re *types.RouteEntry) types.ChannelName {
	if re.PeerChannel != "" {
		return re.PeerChannel
	}
	return re.Channel
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

	c.deleteFDBEntriesForMACOnManagedLinks(mac)

	link, err := netlink.LinkByName(entry.DevName)
	if err != nil {
		vlog.Errorf("[Client] FDB add: link %s not found: %v", entry.DevName, err)
		return
	}
	linkIdx := link.Attrs().Index

	// self: tells vxlan device to encapsulate to dst IP (NUD_PERMANENT)
	if entry.DstPort != 0 {
		// Per-entry dstport override (nexthop channel listens on a different
		// vxlan port). netlink.Neigh can't carry NDA_PORT — use iproute2.
		out, err := exec.Command("bridge", "fdb", "append", key.MAC, "dev", entry.DevName,
			"self", "permanent", "dst", entry.DstIP.String(), "port", strconv.Itoa(int(entry.DstPort))).CombinedOutput()
		if err != nil {
			vlog.Errorf("[Client] FDB self append %s -> %s port %d via %s: %v: %s", key.MAC, entry.DstIP, entry.DstPort, entry.DevName, err, strings.TrimSpace(string(out)))
		}
	} else {
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

	c.deleteFDBEntriesForMACOnLink(entry.DevName, mac)
}

func (c *Client) deleteFDBEntriesForMACOnManagedLinks(mac net.HardwareAddr) {
	for _, chans := range c.VxlanDevs {
		for _, vd := range chans {
			c.deleteFDBEntriesForMACOnLink(vd.Name, mac)
		}
	}
}

func (c *Client) deleteFDBEntriesForMACOnLink(devName string, mac net.HardwareAddr) {
	if devName == "" {
		return
	}

	link, err := netlink.LinkByName(devName)
	if err != nil {
		return
	}
	linkIdx := link.Attrs().Index

	neighs, err := netlink.NeighList(linkIdx, unix.AF_BRIDGE)
	if err != nil {
		vlog.Warnf("[Client] FDB delete %s on %s: NeighList: %v", mac, devName, err)
		return
	}

	for i := range neighs {
		n := neighs[i]
		if n.LinkIndex != linkIdx || !bytes.Equal(n.HardwareAddr, mac) {
			continue
		}
		if err := netlink.NeighDel(&n); err != nil {
			vlog.Warnf("[Client] FDB delete %s on %s: %v", mac, devName, err)
		}
	}

	c.purgeFDBPortedRemotes(devName, mac)
}

// purgeFDBPortedRemotes removes vxlan fdb remotes for mac on devName that
// carry a per-entry dstport override. The kernel only deletes a remote when
// (dst, port) match exactly, and netlink.Neigh can't express NDA_PORT, so
// NeighDel silently misses these — parse `bridge fdb show` and delete with
// the full (dst, port) tuple via iproute2.
func (c *Client) purgeFDBPortedRemotes(devName string, mac net.HardwareAddr) {
	out, err := exec.Command("bridge", "fdb", "show", "dev", devName).Output()
	if err != nil {
		return
	}
	macStr := mac.String()
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != macStr {
			continue
		}
		var dst, port string
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "dst":
				dst = fields[i+1]
			case "port":
				port = fields[i+1]
			}
		}
		if dst == "" || port == "" {
			continue // portless entries are handled by NeighDel
		}
		delOut, err := exec.Command("bridge", "fdb", "del", macStr, "dev", devName,
			"self", "dst", dst, "port", port).CombinedOutput()
		if err != nil {
			vlog.Warnf("[Client] FDB ported delete %s dst %s port %s on %s: %v: %s", macStr, dst, port, devName, err, strings.TrimSpace(string(delOut)))
		}
	}
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
