package client

import (
	"time"

	"vxlan-controller/pkg/vlog"
)

// syncCheckLoop periodically verifies, for every ControllerConn, that the
// controller has acknowledged our latest MAC session via the session_id/seqid
// round-trip:
//
//   - localSeqid:  monotonically incremented for each MAC delta we send
//   - remoteSeqid: highest seqid the controller has echoed back to us in a
//     ControllerStateUpdate stamped with our session_id
//
// When sessions match and the seqid gap is zero, the controller has processed
// all our updates. A persistent mismatch triggers a fresh full re-sync.
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

// checkOneController returns true if the controller has acknowledged our
// current session (or if it's too early to tell). Returns false when a
// re-sync is warranted.
func (c *Client) checkOneController(cc *ControllerConn) bool {
	maxDelay := c.Config.SyncCheckMaxDelay
	if maxDelay == 0 {
		maxDelay = 10
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	cc.syncMu.Lock()
	defer cc.syncMu.Unlock()

	if cc.ActiveAF == "" || !cc.MACsSynced || cc.State == nil {
		return true
	}
	if cc.localSessionID == "" {
		return true
	}

	localSess := cc.localSessionID
	localSeq := cc.localSeqid
	remoteSess := cc.remoteSessionID
	remoteSeq := cc.remoteSeqid

	if localSeq <= maxDelay {
		return true
	}

	if remoteSess != localSess {
		vlog.Warnf("[Client] sync check: ctrl=%s session mismatch local=%s remote=%s (local_seq=%d)",
			cc.ControllerID.Hex()[:8], localSess, remoteSess, localSeq)
		return false
	}

	// uint64 subtraction handles natural overflow correctly: if local just
	// wrapped past 0 while remote is still near maxUint64, the unsigned
	// difference equals the true lag (e.g. 11 - (2^64-2) wraps to 13).
	gap := localSeq - remoteSeq
	if gap <= maxDelay {
		return true
	}

	vlog.Warnf("[Client] sync check: ctrl=%s seqid gap=%d exceeds max_delay=%d, forcing resync",
		cc.ControllerID.Hex()[:8], gap, maxDelay)
	return false
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
	}
}
