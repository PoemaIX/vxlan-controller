package client

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"
)

// rateLimitState tracks the rate currently applied to each vxlan device so
// the loop can no-op when nothing has changed.
type rateLimitState struct {
	mu      sync.Mutex
	current map[afChKey]uint64 // applied rate (kbps); 0 = no qdisc installed
}

type afChKey struct {
	AF      types.AFName
	Channel types.ChannelName
}

func newRateLimitState() *rateLimitState {
	return &rateLimitState{current: make(map[afChKey]uint64)}
}

// rateLimitLoop watches fdbNotifyCh (which already fires on RouteMatrix /
// RouteTable / Clients changes) and reapplies tc qdisc tbf on each vxlan
// device when the computed cap changes.
//
// Cap per (af, channel) = min(my_up_kbps_for_this_channel,
//                             min over reachable peers' down_kbps_for_this_channel).
//
// A 0 on either side is treated as "unset" and skipped from the min. If the
// result is 0 (e.g. nothing configured) the qdisc is removed so the device
// runs unrestricted.
func (c *Client) rateLimitLoop() {
	if !c.Config.VxlanRateLimit {
		return
	}
	// Defensive: wait for init like fdbReconcileLoop so we have an authority
	// controller view before computing caps.
	select {
	case <-c.initDone:
	case <-c.ctx.Done():
		return
	}

	for {
		select {
		case <-c.rlNotifyCh:
			c.reconcileRateLimits()
		case <-c.ctx.Done():
			return
		}
	}
}

// reconcileRateLimits computes the per-(af, channel) cap from current
// authority view and applies tc tbf to each enabled vxlan device.
func (c *Client) reconcileRateLimits() {
	c.mu.Lock()
	caps := c.computeRateLimitCaps()
	c.mu.Unlock()

	c.rlState.mu.Lock()
	defer c.rlState.mu.Unlock()

	for af, chans := range c.VxlanDevs {
		for ch, vd := range chans {
			k := afChKey{AF: af, Channel: ch}
			desired := caps[k]
			cur := c.rlState.current[k]
			if desired == cur {
				continue
			}
			if err := applyTBF(vd.Name, desired); err != nil {
				vlog.Warnf("[RateLimit] %s: %v", vd.Name, err)
				continue
			}
			c.rlState.current[k] = desired
			if desired == 0 {
				vlog.Infof("[RateLimit] %s: removed cap", vd.Name)
			} else {
				vlog.Infof("[RateLimit] %s: capped at %d kbit/s", vd.Name, desired)
			}
		}
	}
}

// computeRateLimitCaps returns the desired rate (kbps; 0 = unlimited) per
// (af, channel). Must be called with c.mu held.
func (c *Client) computeRateLimitCaps() map[afChKey]uint64 {
	caps := make(map[afChKey]uint64)

	if c.AuthorityCtrl == nil {
		return caps
	}
	cc, ok := c.Controllers[*c.AuthorityCtrl]
	if !ok || cc.State == nil {
		return caps
	}

	// For each of MY enabled (af, channel), collect peers reachable on it
	// and take min(my_up, min(peer.down)).
	for af, chans := range c.Config.AFSettings {
		for ch, mine := range chans {
			if !mine.Enable {
				continue
			}
			k := afChKey{AF: af, Channel: ch}
			myUp := mine.UpBwKbps

			minPeerDown := uint64(0)
			havePeer := false
			for peerID, ci := range cc.State.Clients {
				if peerID == c.ClientID {
					continue
				}
				peerChans, ok := ci.Endpoints[af]
				if !ok {
					continue
				}
				ep, ok := peerChans[ch]
				if !ok {
					continue
				}
				if ep.DownBwKbps == 0 {
					continue
				}
				if !havePeer || ep.DownBwKbps < minPeerDown {
					minPeerDown = ep.DownBwKbps
					havePeer = true
				}
			}

			cap := uint64(0)
			switch {
			case myUp != 0 && havePeer:
				cap = myUp
				if minPeerDown < cap {
					cap = minPeerDown
				}
			case myUp != 0:
				cap = myUp
			case havePeer:
				cap = minPeerDown
			}
			caps[k] = cap
		}
	}
	return caps
}

// applyTBF installs (or removes when rateKbps==0) a root tbf qdisc on dev.
// We use `tc qdisc replace` so the call is idempotent for changes; for
// removal we use `tc qdisc del`.
func applyTBF(dev string, rateKbps uint64) error {
	if rateKbps == 0 {
		// Remove. Ignore "not found" errors.
		cmd := exec.Command("tc", "qdisc", "del", "dev", dev, "root")
		out, err := cmd.CombinedOutput()
		if err != nil && !strings.Contains(string(out), "No such file") &&
			!strings.Contains(string(out), "Cannot find") {
			return fmt.Errorf("tc qdisc del: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	// burst: tbf needs at least one MTU per HZ; 32kbit as a safe floor.
	// latency: bound queue size so a slow link doesn't bufferbloat.
	burst := "32kbit"
	if rateKbps > 100_000 {
		burst = "256kbit"
	}
	args := []string{
		"qdisc", "replace", "dev", dev, "root", "tbf",
		"rate", fmt.Sprintf("%dkbit", rateKbps),
		"burst", burst,
		"latency", "50ms",
	}
	cmd := exec.Command("tc", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tc qdisc replace: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// notifyRateLimit schedules a reconcile. Non-blocking.
func (c *Client) notifyRateLimit() {
	if !c.Config.VxlanRateLimit {
		return
	}
	select {
	case c.rlNotifyCh <- struct{}{}:
	default:
	}
}

// cleanupRateLimits removes any qdiscs we installed. Called from Stop().
func (c *Client) cleanupRateLimits() {
	if !c.Config.VxlanRateLimit {
		return
	}
	c.rlState.mu.Lock()
	defer c.rlState.mu.Unlock()
	for k, rate := range c.rlState.current {
		if rate == 0 {
			continue
		}
		// Best-effort: find the device name and remove.
		c.mu.Lock()
		var dev string
		if chans, ok := c.VxlanDevs[k.AF]; ok {
			if vd, ok2 := chans[k.Channel]; ok2 {
				dev = vd.Name
			}
		}
		c.mu.Unlock()
		if dev == "" {
			continue
		}
		_ = applyTBF(dev, 0)
		c.rlState.current[k] = 0
	}
}
