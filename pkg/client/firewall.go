package client

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"
)

// setName returns a sanitized nftables set name for a given AF.
// e.g. "asia_v4" → "af_asia_v4", "v6" → "af_v6"
func setName(af types.AFName) string {
	s := strings.ReplaceAll(string(af), "-", "_")
	return "af_" + s
}

// fwTable returns the configured nftables table name.
func (c *Client) fwTable() string {
	return c.Config.VxlanFirewallTable
}

// initFirewall creates the nftables table, per-AF sets, and chain for VXLAN source filtering.
func (c *Client) initFirewall() error {
	if !c.Config.VxlanFirewall {
		return nil
	}

	nft := c.buildFirewallRuleset(nil)
	if err := applyNft(nft); err != nil {
		return fmt.Errorf("init vxlan firewall: %w", err)
	}

	vlog.Infof("[Firewall] VXLAN firewall initialized")
	return nil
}

// syncFirewallPeers extracts per-AF peer endpoint IPs from the authority controller view
// and updates the nftables allowed sets. Must be called WITHOUT c.mu held.
func (c *Client) syncFirewallPeers() {
	if !c.Config.VxlanFirewall {
		return
	}

	c.mu.Lock()
	perAF := c.collectPeerIPsPerAF()
	c.mu.Unlock()

	tbl := c.fwTable()
	var cmds []string
	for af, afCfg := range c.Config.AFSettings {
		if !afCfg.Enable {
			continue
		}
		sn := setName(af)
		cmds = append(cmds, fmt.Sprintf("flush set inet %s %s", tbl, sn))
		if ips, ok := perAF[af]; ok && len(ips) > 0 {
			cmds = append(cmds, fmt.Sprintf("add element inet %s %s { %s }", tbl, sn, strings.Join(ips, ", ")))
		}
	}

	if len(cmds) == 0 {
		return
	}

	nft := strings.Join(cmds, "\n") + "\n"
	if err := applyNft(nft); err != nil {
		vlog.Errorf("[Firewall] update peer sets: %v", err)
		return
	}

	vlog.Debugf("[Firewall] updated allowed peers: %v", perAF)
}

// rebuildFirewallRules rebuilds the entire table (sets + chain rules) to reflect
// new bind addresses. Called on bind addr change. Must be called WITHOUT c.mu held.
func (c *Client) rebuildFirewallRules() {
	if !c.Config.VxlanFirewall {
		return
	}

	c.mu.Lock()
	perAF := c.collectPeerIPsPerAF()
	c.mu.Unlock()

	nft := c.buildFirewallRuleset(perAF)
	if err := applyNft(nft); err != nil {
		vlog.Errorf("[Firewall] rebuild rules: %v", err)
		return
	}

	vlog.Infof("[Firewall] rebuilt rules after bind addr change")
}

// cleanupFirewall removes the nftables table.
func (c *Client) cleanupFirewall() {
	if !c.Config.VxlanFirewall {
		return
	}
	// Use "delete" (not "destroy") for nftables <1.0 compat; ignore error if table doesn't exist.
	exec.Command("nft", "delete", "table", "inet", c.fwTable()).Run()
	vlog.Infof("[Firewall] VXLAN firewall cleaned up")
}

// collectPeerIPsPerAF returns per-AF sorted lists of peer endpoint IPs.
// Must be called with c.mu held.
func (c *Client) collectPeerIPsPerAF() map[types.AFName][]string {
	result := make(map[types.AFName][]string)

	if c.AuthorityCtrl == nil {
		return result
	}
	cc, ok := c.Controllers[*c.AuthorityCtrl]
	if !ok || cc.State == nil {
		return result
	}

	for clientID, ci := range cc.State.Clients {
		if clientID == c.ClientID {
			continue
		}
		for af, ep := range ci.Endpoints {
			if !ep.IP.IsValid() {
				continue
			}
			result[af] = append(result[af], ep.IP.String())
		}
	}

	// Deduplicate and sort
	for af, ips := range result {
		sort.Strings(ips)
		deduped := ips[:0]
		for i, ip := range ips {
			if i == 0 || ip != ips[i-1] {
				deduped = append(deduped, ip)
			}
		}
		result[af] = deduped
	}

	return result
}

// buildFirewallRuleset generates a complete nftables ruleset for VXLAN source filtering.
// Each AF gets its own set, so multi-AF configs with different peers are isolated.
func (c *Client) buildFirewallRuleset(perAF map[types.AFName][]string) string {
	var sb strings.Builder

	tbl := c.fwTable()
	// Delete existing table first (ignore error if it doesn't exist).
	// Using separate command instead of "destroy" for nftables <1.0 compat.
	exec.Command("nft", "delete", "table", "inet", tbl).Run()
	sb.WriteString(fmt.Sprintf("table inet %s {\n", tbl))

	// Per-AF sets
	for af, afCfg := range c.Config.AFSettings {
		if !afCfg.Enable {
			continue
		}
		sn := setName(af)
		addrType := "ipv4_addr"
		if afCfg.BindAddr.IsValid() && afCfg.BindAddr.Is6() {
			addrType = "ipv6_addr"
		} else if !afCfg.BindAddr.IsValid() {
			// Not yet resolved; guess from AF name
			low := strings.ToLower(string(af))
			if strings.Contains(low, "v6") || strings.Contains(low, "ipv6") {
				addrType = "ipv6_addr"
			}
		}

		sb.WriteString(fmt.Sprintf("    set %s {\n", sn))
		sb.WriteString(fmt.Sprintf("        type %s\n", addrType))
		if ips, ok := perAF[af]; ok && len(ips) > 0 {
			sb.WriteString(fmt.Sprintf("        elements = { %s }\n", strings.Join(ips, ", ")))
		}
		sb.WriteString("    }\n")
	}

	// INPUT chain
	sb.WriteString("    chain input {\n")
	sb.WriteString("        type filter hook input priority filter; policy accept;\n")

	for af, afCfg := range c.Config.AFSettings {
		if !afCfg.Enable || !afCfg.BindAddr.IsValid() {
			continue
		}
		sn := setName(af)
		port := afCfg.VxlanDstPort
		addr := afCfg.BindAddr

		if addr.Is4() {
			sb.WriteString(fmt.Sprintf("        udp dport %d ip daddr %s ip saddr != @%s counter drop\n", port, addr, sn))
		} else {
			sb.WriteString(fmt.Sprintf("        udp dport %d ip6 daddr %s ip6 saddr != @%s counter drop\n", port, addr, sn))
		}
	}

	sb.WriteString("    }\n")
	sb.WriteString("}\n")

	return sb.String()
}

func applyNft(ruleset string) error {
	cmd := exec.Command("nft", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// notifyFirewall signals the firewall loop to sync peer IPs.
func (c *Client) notifyFirewall() {
	if !c.Config.VxlanFirewall {
		return
	}
	select {
	case c.fwNotifyCh <- struct{}{}:
	default:
	}
}

// firewallLoop coalesces firewall update notifications.
// No initDone gate — firewall sets must be populated before FDB entries
// trigger VXLAN traffic. Control plane traffic is unaffected (different port).
func (c *Client) firewallLoop() {
	for {
		select {
		case <-c.fwNotifyCh:
			c.syncFirewallPeers()
		case <-c.ctx.Done():
			return
		}
	}
}

// fwBindAddrChanged rebuilds firewall rules when bind addr changes.
func (c *Client) fwBindAddrChanged() {
	if !c.Config.VxlanFirewall {
		return
	}
	c.rebuildFirewallRules()
}
