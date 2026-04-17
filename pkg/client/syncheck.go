package client

import (
	"net/netip"
	"time"

	"vxlan-controller/pkg/vlog"
)

// syncCheckLoop periodically verifies, for every ControllerConn, that the
// controller's view of this client's routes matches LocalMACs. The check uses
// the per-cc session_id/seqid round-trip:
//
//   - localSeqid:  monotonically incremented for each MAC delta we send
//   - remoteSeqid: highest seqid the controller has echoed back to us in a
//     ControllerStateUpdate stamped with our session_id
//
// When local catches remote and the sessions match, the controller's
// route table (as visible to us via cc.State.RouteTable) should contain
// exactly the entries owned by us in LocalMACs. If it doesn't, we trigger
// a fresh full re-sync on that connection.
//
// All interesting cases are handled by checkOneController; this loop just
// drives it on a timer.
func (c *Client) syncCheckLoop() {
	interval := c.Config.SyncCheckInterval
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.runSyncCheck()
		}
	}
}

func (c *Client) runSyncCheck() {
	// Snapshot the controller list under c.mu so we can iterate without
	// holding it across the per-cc check (which itself takes locks).
	c.mu.Lock()
	ccs := make([]*ControllerConn, 0, len(c.Controllers))
	for _, cc := range c.Controllers {
		ccs = append(ccs, cc)
	}
	c.mu.Unlock()

	for _, cc := range ccs {
		if !c.checkOneController(cc) {
			c.triggerFullResync(cc)
		}
	}
}

// checkOneController returns true if the controller's view of self routes is
// consistent with LocalMACs (or if it's too early to tell). Returns false
// when a re-sync is warranted.
//
// The function holds c.macMu.RLock + cc.syncMu + c.mu for the comparison so
// neither netlink nor the controller can mutate either side mid-check.
func (c *Client) checkOneController(cc *ControllerConn) bool {
	maxDelay := c.Config.SyncCheckMaxDelay
	if maxDelay == 0 {
		maxDelay = 10
	}

	c.macMu.RLock()
	defer c.macMu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	cc.syncMu.Lock()
	defer cc.syncMu.Unlock()

	// Connection not ready — nothing to check.
	if cc.ActiveAF == "" || !cc.MACsSynced || cc.State == nil {
		return true
	}
	// No full sync has gone out yet on this connection.
	if cc.localSessionID == "" {
		return true
	}

	localSess := cc.localSessionID
	localSeq := cc.localSeqid
	remoteSess := cc.remoteSessionID
	remoteSeq := cc.remoteSeqid

	// Too early — local seqid still small, give the round-trip more time.
	if localSeq <= maxDelay {
		return true
	}

	// Local has been active long enough that the controller should have
	// echoed back our current session by now. If not, we're out of sync.
	if remoteSess != localSess {
		vlog.Warnf("[Client] sync check: ctrl=%s session mismatch local=%s remote=%s (local_seq=%d)",
			cc.ControllerID.Hex()[:8], localSess, remoteSess, localSeq)
		return false
	}

	// Sessions agree. Compare seqids.
	if remoteSeq > localSeq {
		// Should not happen — controller can't have processed more than we've
		// sent. Treat as protocol confusion and force a clean resync.
		vlog.Warnf("[Client] sync check: ctrl=%s remote_seq=%d > local_seq=%d, forcing resync",
			cc.ControllerID.Hex()[:8], remoteSeq, localSeq)
		return false
	}

	gap := localSeq - remoteSeq
	if gap == 0 {
		// Fully synchronized — compare route sets.
		return c.compareSelfRoutes(cc)
	}
	if gap <= maxDelay {
		// Still in flight, wait for the next tick.
		return true
	}

	// Gap is too large — the controller is missing updates we sent long ago.
	vlog.Warnf("[Client] sync check: ctrl=%s seqid gap=%d exceeds max_delay=%d, forcing resync",
		cc.ControllerID.Hex()[:8], gap, maxDelay)
	return false
}

// compareSelfRoutes compares LocalMACs against the controller's route table
// view (filtered for entries the controller marks us as owner of). Caller
// must hold c.macMu (R or W) and c.mu.
func (c *Client) compareSelfRoutes(cc *ControllerConn) bool {
	type rkey struct {
		mac string
		ip  netip.Addr
	}

	local := make(map[rkey]struct{}, len(c.LocalMACs))
	for _, r := range c.LocalMACs {
		ip := r.IP
		if ip.IsValid() && ip.IsUnspecified() {
			ip = netip.Addr{}
		}
		local[rkey{mac: r.MAC.String(), ip: ip}] = struct{}{}
	}

	remote := make(map[rkey]struct{})
	for _, entry := range cc.State.RouteTable {
		if _, owned := entry.Owners[c.ClientID]; !owned {
			continue
		}
		ip := entry.IP
		if ip.IsValid() && ip.IsUnspecified() {
			ip = netip.Addr{}
		}
		remote[rkey{mac: entry.MAC.String(), ip: ip}] = struct{}{}
	}

	if len(local) != len(remote) {
		vlog.Warnf("[Client] sync check: ctrl=%s self route count mismatch local=%d remote=%d",
			cc.ControllerID.Hex()[:8], len(local), len(remote))
		return false
	}
	for k := range local {
		if _, ok := remote[k]; !ok {
			vlog.Warnf("[Client] sync check: ctrl=%s missing remote entry %s/%s",
				cc.ControllerID.Hex()[:8], k.mac, k.ip)
			return false
		}
	}
	return true
}

// triggerFullResync forces the sendloop on cc to emit a fresh full MACUpdate
// (which will allocate a new session_id and reset seqid to 0). Safe to call
// without any locks held.
func (c *Client) triggerFullResync(cc *ControllerConn) {
	c.mu.Lock()
	cc.MACsSynced = false
	c.mu.Unlock()

	select {
	case cc.SendQueue <- ClientQueueItem{Trigger: true}:
	default:
		// Queue full — sendloop will eventually catch up and re-evaluate
		// MACsSynced; nothing more we can do without blocking.
	}
}
