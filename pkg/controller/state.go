package controller

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/filter"
	"vxlan-controller/pkg/types"

	pb "vxlan-controller/proto"
)

// DNS resolution cache for endpoint overrides (DDNS support).
var (
	dnsCache   = make(map[string]dnsCacheEntry)
	dnsCacheMu sync.Mutex
	dnsCacheTTL = 60 * time.Second
)

type dnsCacheEntry struct {
	addr    netip.Addr
	expires time.Time
}

func cachedResolve(s string) (netip.Addr, error) {
	// Direct IP: no cache needed
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr, nil
	}

	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()

	if entry, ok := dnsCache[s]; ok && time.Now().Before(entry.expires) {
		return entry.addr, nil
	}

	ips, err := net.LookupHost(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("no addresses for %s", s)
	}
	addr, err := netip.ParseAddr(ips[0])
	if err != nil {
		return netip.Addr{}, err
	}
	dnsCache[s] = dnsCacheEntry{addr: addr, expires: time.Now().Add(dnsCacheTTL)}
	return addr, nil
}

// ControllerState is the global state protected by Controller.mu.
type ControllerState struct {
	Clients          map[types.ClientID]*ClientInfo
	LatencyMatrix    map[types.ClientID]map[types.ClientID]*types.LatencyInfo
	BestPaths        map[types.ClientID]map[types.ClientID]*types.BestPathEntry
	RouteMatrix      map[types.ClientID]map[types.ClientID]*types.RouteEntry
	RouteTable       []*types.RouteTableEntry
	LastClientChange time.Time
}

// ClientInfo is maintained for each connected client.
type ClientInfo struct {
	ClientID   types.ClientID
	ClientName string
	Endpoints  map[types.AFName]*types.Endpoint
	LastSeen   time.Time
	Routes     []types.Type2Route
}

// QueueItem is the sendqueue element. State and Message are independent;
// if both are set, the receiver processes them as two separate messages.
type QueueItem struct {
	State   []byte // encoded state update (full or inc), nil if none
	Message []byte // encoded non-state message (probe req, etc.), nil if none
}

// ClientConn represents the Controller's connection state with a single Client.
type ClientConn struct {
	ClientID  types.ClientID
	AFConns   map[types.AFName]*AFConn
	ActiveAF  types.AFName
	Synced    bool
	SendQueue chan QueueItem
	Filters   *filter.FilterSet
}

// AFConn represents a single AF TCP connection to a client.
type AFConn struct {
	AF          types.AFName
	TCPConn     net.Conn
	Session     *crypto.Session
	ConnectedAt time.Time
	Done        chan struct{} // closed when this conn should stop
	Cleaned     chan struct{} // closed after handleDisconnect completes cleanup
	doneOnce    sync.Once
}

// CloseDone safely closes the Done channel (idempotent).
func (afc *AFConn) CloseDone() {
	afc.doneOnce.Do(func() { close(afc.Done) })
}

func newControllerState() *ControllerState {
	return &ControllerState{
		Clients:       make(map[types.ClientID]*ClientInfo),
		LatencyMatrix: make(map[types.ClientID]map[types.ClientID]*types.LatencyInfo),
		RouteMatrix:   make(map[types.ClientID]map[types.ClientID]*types.RouteEntry),
	}
}

// Snapshot serializes the full ControllerState to protobuf.
// overrideFn returns per-AF endpoint overrides for a given client (nil if none).
func (cs *ControllerState) Snapshot(controllerID types.ClientID, overrideFn func(types.ClientID) map[types.AFName]string) *pb.ControllerState {
	state := &pb.ControllerState{
		ClientCount:              uint32(len(cs.Clients)),
		LastClientChangeTimestamp: cs.LastClientChange.UnixNano(),
		Clients:                  make(map[string]*pb.ClientInfoProto),
		ControllerId:             controllerID[:],
	}

	for id, ci := range cs.Clients {
		state.Clients[id.Hex()] = clientInfoToProto(ci, overrideFn(id))
	}

	state.RouteMatrix = routeMatrixToProto(cs.RouteMatrix)
	state.RouteTable = routeTableToProto(cs.RouteTable)

	return state
}

func addrToBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

func clientInfoToProto(ci *ClientInfo, overrides map[types.AFName]string) *pb.ClientInfoProto {
	p := &pb.ClientInfoProto{
		ClientId:   ci.ClientID[:],
		ClientName: ci.ClientName,
		Endpoints:  make(map[string]*pb.EndpointProto),
		LastSeen:   ci.LastSeen.UnixNano(),
	}

	for af, ep := range ci.Endpoints {
		epProto := &pb.EndpointProto{
			ProbePort:    uint32(ep.ProbePort),
			VxlanDstPort: uint32(ep.VxlanDstPort),
		}
		ip := ep.IP
		if override, ok := overrides[af]; ok && override != "" {
			if resolved, err := cachedResolve(override); err == nil {
				ip = resolved
			}
		}
		epProto.Ip = addrToBytes(ip)
		p.Endpoints[string(af)] = epProto
	}

	for _, r := range ci.Routes {
		rt := &pb.Type2Route{Mac: r.MAC}
		if r.IP.IsValid() {
			rt.Ip = addrToBytes(r.IP)
		}
		p.Routes = append(p.Routes, rt)
	}

	return p
}

func routeMatrixToProto(rm map[types.ClientID]map[types.ClientID]*types.RouteEntry) *pb.RouteMatrixProto {
	p := &pb.RouteMatrixProto{}
	for src, dsts := range rm {
		row := &pb.RouteMatrixRow{SrcClientId: src[:]}
		for dst, entry := range dsts {
			cell := &pb.RouteMatrixCell{
				DstClientId: dst[:],
				NexthopId:   entry.NextHop[:],
				AfName:      string(entry.AF),
			}
			row.Cells = append(row.Cells, cell)
		}
		p.Rows = append(p.Rows, row)
	}
	return p
}

func routeTableToProto(rt []*types.RouteTableEntry) []*pb.RouteTableEntryProto {
	var result []*pb.RouteTableEntryProto
	for _, entry := range rt {
		p := &pb.RouteTableEntryProto{
			Mac:    entry.MAC,
			Owners: make(map[string]int64),
		}
		if entry.IP.IsValid() {
			p.Ip = addrToBytes(entry.IP)
		}
		for cid, t := range entry.Owners {
			p.Owners[cid.Hex()] = t.UnixNano()
		}
		result = append(result, p)
	}
	return result
}

// Proto deserialization helpers

func ProtoToClientInfo(p *pb.ClientInfoProto) *ClientInfo {
	ci := &ClientInfo{
		ClientName: p.ClientName,
		Endpoints:  make(map[types.AFName]*types.Endpoint),
		LastSeen:   time.Unix(0, p.LastSeen),
	}
	copy(ci.ClientID[:], p.ClientId)

	for af, ep := range p.Endpoints {
		e := &types.Endpoint{
			ProbePort:    uint16(ep.ProbePort),
			VxlanDstPort: uint16(ep.VxlanDstPort),
		}
		if len(ep.Ip) == 4 {
			e.IP = netip.AddrFrom4([4]byte(ep.Ip))
		} else if len(ep.Ip) == 16 {
			e.IP = netip.AddrFrom16([16]byte(ep.Ip))
		}
		ci.Endpoints[types.AFName(af)] = e
	}

	for _, r := range p.Routes {
		rt := types.Type2Route{MAC: r.Mac}
		if len(r.Ip) == 4 {
			rt.IP = netip.AddrFrom4([4]byte(r.Ip))
		} else if len(r.Ip) == 16 {
			rt.IP = netip.AddrFrom16([16]byte(r.Ip))
		}
		ci.Routes = append(ci.Routes, rt)
	}

	return ci
}

func ProtoToRouteMatrix(p *pb.RouteMatrixProto) map[types.ClientID]map[types.ClientID]*types.RouteEntry {
	rm := make(map[types.ClientID]map[types.ClientID]*types.RouteEntry)
	if p == nil {
		return rm
	}
	for _, row := range p.Rows {
		var src types.ClientID
		copy(src[:], row.SrcClientId)
		rm[src] = make(map[types.ClientID]*types.RouteEntry)
		for _, cell := range row.Cells {
			var dst, nexthop types.ClientID
			copy(dst[:], cell.DstClientId)
			copy(nexthop[:], cell.NexthopId)
			rm[src][dst] = &types.RouteEntry{
				NextHop: nexthop,
				AF:      types.AFName(cell.AfName),
			}
		}
	}
	return rm
}

func ProtoToRouteTable(entries []*pb.RouteTableEntryProto) []*types.RouteTableEntry {
	var rt []*types.RouteTableEntry
	for _, p := range entries {
		entry := &types.RouteTableEntry{
			MAC:    p.Mac,
			Owners: make(map[types.ClientID]time.Time),
		}
		if len(p.Ip) == 4 {
			entry.IP = netip.AddrFrom4([4]byte(p.Ip))
		} else if len(p.Ip) == 16 {
			entry.IP = netip.AddrFrom16([16]byte(p.Ip))
		}
		for cidHex, t := range p.Owners {
			cid, err := types.ClientIDFromHex(cidHex)
			if err != nil {
				continue
			}
			entry.Owners[cid] = time.Unix(0, t)
		}
		rt = append(rt, entry)
	}
	return rt
}
