package client

import (
	"vxlan-controller/pkg/vlog"
	"net"
	"net/netip"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	pb "vxlan-controller/proto"
)

// neighborWatchLoop monitors netlink neighbor events and sends incremental updates.
func (c *Client) neighborWatchLoop() {
	// Subscribe FIRST, then dump — so no events are lost between dump and subscribe.
	// Duplicate events from the overlap are harmless (addLocalRoute is idempotent).
	neighCh := make(chan netlink.NeighUpdate)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.NeighSubscribe(neighCh, done); err != nil {
		vlog.Errorf("[Client] netlink neighbor subscribe error: %v", err)
		return
	}

	// Initial full dump (events arriving during dump queue in neighCh)
	c.dumpLocalState()

	for {
		select {
		case update, ok := <-neighCh:
			if !ok {
				return
			}
			if !c.isRelevantNeighEvent(update.Neigh) {
				continue
			}
			c.handleNeighEvent(update)
		case <-c.ctx.Done():
			return
		}
	}
}

// handleNeighEvent processes a single netlink neighbor event and sends an incremental update.
func (c *Client) handleNeighEvent(update netlink.NeighUpdate) {
	n := update.Neigh

	// Determine if this is an add or delete
	isDelete := false
	if update.Type == unix.RTM_DELNEIGH {
		isDelete = true
	} else if n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT|netlink.NUD_NOARP) == 0 {
		// Not a usable state (e.g. NUD_FAILED, NUD_INCOMPLETE)
		isDelete = true
	}

	// Build route from event
	var rt *pb.Type2Route

	// Only process bridge FDB entries; skip ARP/NDP neighbor entries
	// (neighbor table contains both local and remote IP-MAC pairs,
	// making it unreliable for determining IP ownership)
	if n.Family != unix.AF_BRIDGE {
		return
	}
	if !c.isLocalFDBEntry(n) {
		return
	}
	rt = &pb.Type2Route{
		Mac:      n.HardwareAddr,
		IsDelete: isDelete,
	}

	// Filter outbound route
	macStr := net.HardwareAddr(rt.Mac).String()
	ipStr := ""
	if len(rt.Ip) > 0 {
		if len(rt.Ip) == 4 {
			ipStr = netip.AddrFrom4([4]byte(rt.Ip)).String()
		} else if len(rt.Ip) == 16 {
			ipStr = netip.AddrFrom16([16]byte(rt.Ip)).String()
		}
	}
	if !c.Filters.OutputRoute.FilterRoute(macStr, ipStr, isDelete) {
		return
	}

	// Update local state
	c.mu.Lock()
	localRT := types.Type2Route{MAC: rt.Mac}
	if ipStr != "" {
		localRT.IP, _ = netip.ParseAddr(ipStr)
	}
	if isDelete {
		c.LocalMACs = removeLocalRoute(c.LocalMACs, localRT)
	} else {
		c.LocalMACs = addLocalRoute(c.LocalMACs, localRT)
	}
	c.mu.Unlock()

	// Send incremental update via sendqueue
	macUpdate := &pb.MACUpdate{
		IsFull: false,
		Routes: []*pb.Type2Route{rt},
	}
	data, err := proto.Marshal(macUpdate)
	if err != nil {
		vlog.Errorf("[Client] marshal MACUpdate error: %v", err)
		return
	}

	msg := clientEncodeMessage(protocol.MsgMACUpdate, data)
	c.mu.Lock()
	for _, cc := range c.Controllers {
		if !cc.MACsSynced {
			// Not synced — send full snapshot instead of incremental.
			c.triggerFullMACs(cc)
			continue
		}
		select {
		case cc.SendQueue <- ClientQueueItem{State: msg}:
		default:
			// Queue full — incremental lost. Send full to recover.
			cc.MACsSynced = false
			c.triggerFullMACs(cc)
		}
	}
	c.mu.Unlock()
}

func (c *Client) isRelevantNeighEvent(neigh netlink.Neigh) bool {
	link, err := netlink.LinkByIndex(neigh.LinkIndex)
	if err != nil {
		return false
	}

	if link.Attrs().Name == c.Config.BridgeName {
		return true
	}

	if link.Attrs().MasterIndex > 0 {
		master, err := netlink.LinkByIndex(link.Attrs().MasterIndex)
		if err == nil && master.Attrs().Name == c.Config.BridgeName {
			return true
		}
	}

	return false
}

func (c *Client) dumpLocalState() {
	bridge, err := netlink.LinkByName(c.Config.BridgeName)
	if err != nil {
		vlog.Errorf("[Client] bridge %s not found: %v", c.Config.BridgeName, err)
		return
	}
	bridgeIndex := bridge.Attrs().Index

	neighs, err := netlink.NeighList(0, unix.AF_BRIDGE)
	if err != nil {
		vlog.Errorf("[Client] FDB dump error: %v", err)
		return
	}

	var routes []types.Type2Route
	for _, n := range neighs {
		if !c.entryBelongsToBridge(n, bridgeIndex) {
			continue
		}
		if !c.isLocalFDBEntry(n) {
			continue
		}
		rt := types.Type2Route{
			MAC: n.HardwareAddr,
		}
		routes = append(routes, rt)
	}

	// NOTE: ARP/NDP neighbor table IP learning is disabled.
	// The bridge neighbor table contains both local and remote IP-MAC pairs,
	// making it unreliable for determining IP ownership. Leaf IPs behind the
	// bridge also don't appear in the neighbor table. Kept as a placeholder
	// for future reimplementation.

	// Filter outbound routes
	total := len(routes)
	var filtered []types.Type2Route
	for _, rt := range routes {
		ipStr := ""
		if rt.IP.IsValid() {
			ipStr = rt.IP.String()
		}
		if c.Filters.OutputRoute.FilterRoute(rt.MAC.String(), ipStr, false) {
			filtered = append(filtered, rt)
		}
	}
	routes = filtered

	vlog.Infof("[Client] local state dump: found %d local routes (%d after filter)", total, len(routes))

	c.mu.Lock()
	c.LocalMACs = routes
	// Push full MACs to all connected controllers.
	// If a controller connected before this dump completed, it may have
	// received an empty full update — this corrects it.
	for _, cc := range c.Controllers {
		c.triggerFullMACs(cc)
	}
	c.mu.Unlock()
}

func (c *Client) entryBelongsToBridge(n netlink.Neigh, bridgeIndex int) bool {
	if n.LinkIndex == bridgeIndex {
		return true
	}
	link, err := netlink.LinkByIndex(n.LinkIndex)
	if err != nil {
		return false
	}
	return link.Attrs().MasterIndex == bridgeIndex
}

func (c *Client) isLocalFDBEntry(n netlink.Neigh) bool {
	if len(n.HardwareAddr) == 0 {
		return false
	}
	if n.HardwareAddr[0]&0x01 != 0 {
		return false
	}
	if len(n.IP) > 0 {
		return false
	}

	link, err := netlink.LinkByIndex(n.LinkIndex)
	if err != nil {
		return false
	}
	name := link.Attrs().Name

	for _, vd := range c.VxlanDevs {
		if name == vd.Name {
			return false
		}
	}
	if name == "tap-inject" {
		return false
	}

	return true
}

func addLocalRoute(routes []types.Type2Route, rt types.Type2Route) []types.Type2Route {
	for i, r := range routes {
		if macEqual(r.MAC, rt.MAC) && r.IP == rt.IP {
			routes[i] = rt
			return routes
		}
	}
	return append(routes, rt)
}

func removeLocalRoute(routes []types.Type2Route, rt types.Type2Route) []types.Type2Route {
	for i, r := range routes {
		if macEqual(r.MAC, rt.MAC) && r.IP == rt.IP {
			return append(routes[:i], routes[i+1:]...)
		}
	}
	return routes
}

func addrToBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
