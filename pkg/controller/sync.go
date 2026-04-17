package controller

import (
	"net"
	"net/netip"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/vlog"

	pb "vxlan-controller/proto"
)

// pushDelta sends an incremental update to all synced clients.
// Must be called with c.mu held.
func (c *Controller) pushDelta(update *pb.ControllerStateUpdate) {
	// Check if this is a RouteTableUpdate that needs per-client filtering
	rtUpdate, isRouteTable := update.Update.(*pb.ControllerStateUpdate_RouteTableUpdate)

	// Pre-marshal the unfiltered version for clients without route filters
	data, err := proto.Marshal(update)
	if err != nil {
		vlog.Errorf("[Controller] failed to marshal ControllerStateUpdate: %v", err)
		return
	}
	defaultMsg := encodeMessage(protocol.MsgControllerStateUpdate, data)

	for _, cc := range c.clients {
		if !cc.Synced {
			continue
		}

		msg := defaultMsg

		// Per-client route filtering for RouteTableUpdate. Carry the source
		// fields through so the sync_check daemon on the source client can
		// still observe its own echo even after filtering.
		if isRouteTable && cc.Filters != nil {
			filtered := c.filterRouteTableForClient(rtUpdate.RouteTableUpdate.Entries, cc)
			if len(filtered) != len(rtUpdate.RouteTableUpdate.Entries) {
				filteredUpdate := &pb.ControllerStateUpdate{
					Update: &pb.ControllerStateUpdate_RouteTableUpdate{
						RouteTableUpdate: &pb.RouteTableUpdateProto{
							Entries: filtered,
						},
					},
					SourceClientId:  update.SourceClientId,
					SourceSessionId: update.SourceSessionId,
					SourceSeqid:     update.SourceSeqid,
				}
				if d, err := proto.Marshal(filteredUpdate); err == nil {
					msg = encodeMessage(protocol.MsgControllerStateUpdate, d)
				}
			}
		}

		select {
		case cc.SendQueue <- QueueItem{State: msg}:
		default:
			vlog.Warnf("[Controller] send queue full for client %s, marking unsynced", cc.ClientID.Hex())
			cc.Synced = false
		}
	}
}

// filterRouteTableForClient filters route table entries through a client's output_route filter.
func (c *Controller) filterRouteTableForClient(entries []*pb.RouteTableEntryProto, cc *ClientConn) []*pb.RouteTableEntryProto {
	if cc.Filters == nil {
		return entries
	}
	var filtered []*pb.RouteTableEntryProto
	for _, e := range entries {
		mac := net.HardwareAddr(e.Mac).String()
		ip := ""
		if len(e.Ip) == 4 {
			ip = netip.AddrFrom4([4]byte(e.Ip)).String()
		} else if len(e.Ip) == 16 {
			ip = netip.AddrFrom16([16]byte(e.Ip)).String()
		}
		if cc.Filters.OutputRoute.FilterRoute(mac, ip, false) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// encodeMessage prepends the msg_type byte to payload.
func encodeMessage(msgType protocol.MsgType, payload []byte) []byte {
	msg := make([]byte, 1+len(payload))
	msg[0] = byte(msgType)
	copy(msg[1:], payload)
	return msg
}

// getFullStateEncodedForClient returns the full state snapshot, filtered for the given client.
// Must be called with c.mu held (at least RLock).
func (c *Controller) getFullStateEncodedForClient(cc *ClientConn) []byte {
	snapshot := c.State.Snapshot(c.ControllerID, c.endpointOverrides)

	// Filter RouteTable for this client
	if cc.Filters != nil {
		snapshot.RouteTable = c.filterRouteTableForClient(snapshot.RouteTable, cc)
	}

	data, err := proto.Marshal(snapshot)
	if err != nil {
		vlog.Errorf("[Controller] failed to marshal ControllerState: %v", err)
		return nil
	}
	return encodeMessage(protocol.MsgControllerState, data)
}
