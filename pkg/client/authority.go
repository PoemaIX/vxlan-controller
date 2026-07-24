package client

import (
	"bytes"

	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"

	pb "vxlan-controller/proto"
)

// selectAuthority picks the best Controller from the synced ones.
// Criteria (in order):
// 1. ClientCount DESC
// 2. LastClientChange ASC (older = more stable)
// 3. ControllerID ASC (deterministic tiebreak)
func (c *Client) selectAuthority() *types.ControllerID {
	type candidate struct {
		id   types.ControllerID
		view *ControllerView
	}

	var candidates []candidate
	for id, cc := range c.Controllers {
		if cc.Synced {
			candidates = append(candidates, candidate{id: id, view: cc.State})
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	best := candidates[0]
	for _, cand := range candidates[1:] {
		if cand.view.ClientCount > best.view.ClientCount {
			best = cand
			continue
		}
		if cand.view.ClientCount == best.view.ClientCount {
			if cand.view.LastClientChange.Before(best.view.LastClientChange) {
				best = cand
				continue
			}
			if cand.view.LastClientChange.Equal(best.view.LastClientChange) {
				if bytes.Compare(cand.id[:], best.id[:]) < 0 {
					best = cand
				}
			}
		}
	}

	id := best.id
	return &id
}

// authoritySelectLoop waits for init_timeout then selects authority,
// and continues to re-evaluate when synced state changes.
func (c *Client) authoritySelectLoop() {
	// Wait for init_timeout
	select {
	case <-c.initDone:
	case <-c.ctx.Done():
		return
	}

	vlog.Infof("[Client] init_timeout elapsed, selecting authority controller")

	c.mu.Lock()
	auth := c.selectAuthority()
	if auth != nil {
		c.AuthorityCtrl = auth
		vlog.Infof("[Client] selected authority controller: %s", auth.Hex()[:8])
	} else {
		vlog.Infof("[Client] no synced controller available for authority selection")
	}
	c.mu.Unlock()

	// Notify FDB reconciler, firewall and rate limiter. The rate limiter in
	// particular may have last been notified before an authority existed (all
	// peer state can arrive before init_timeout) — without a kick here it
	// would never compute caps.
	c.notifyFDB()
	c.notifyFirewall()
	c.notifyRateLimit()

	// Run initial probe now that authority is selected.
	// The controller's sync_new_client_debounce probe fires before init_timeout,
	// so it gets dropped. We need to probe immediately after init.
	if auth != nil {
		go c.executeProbe(&pb.ControllerProbeRequest{
			ProbeId:           1,
			ProbeTimeoutMs:    2000,
			ProbeTimes:        3,
			InProbeIntervalMs: 100,
		})
	}

	// Event-driven authority selection — no polling. The only periodic event
	// in the system is the controller's probe-request broadcast; a dead or
	// partitioned authority stops delivering it, so the client's read idle
	// timeout (or a stalled control write) trips a TCP error, tears the
	// connection down, and handleClientDisconnect kicks authorityChangeCh when
	// the controller goes fully disconnected. Which live controller we then
	// pick doesn't matter — the model keeps every controller's state identical
	// (if they ever diverge, that's a bug to debug, not to route around).
	for {
		select {
		case <-c.authorityChangeCh:
		case <-c.ctx.Done():
			return
		}

		c.mu.Lock()
		newAuth := c.selectAuthority()
		changed := false
		if newAuth == nil && c.AuthorityCtrl != nil {
			changed = true
			c.AuthorityCtrl = nil
			vlog.Infof("[Client] authority controller lost")
		} else if newAuth != nil && (c.AuthorityCtrl == nil || *newAuth != *c.AuthorityCtrl) {
			changed = true
			c.AuthorityCtrl = newAuth
			vlog.Infof("[Client] authority controller changed to %s", newAuth.Hex()[:8])
		}
		c.mu.Unlock()

		if changed {
			c.notifyFDB()
			c.notifyFirewall()
			c.notifyRateLimit()
		}
	}
}
