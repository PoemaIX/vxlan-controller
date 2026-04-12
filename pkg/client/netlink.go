package client

import (
	"fmt"
	"io"
	"os/exec"
	"strings"

	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// VxlanDev represents a VXLAN device.
type VxlanDev struct {
	AF       types.AFName
	Name     string
	VNI      uint32
	MTU      int
	BindAddr string
}

// initDevices creates/configures bridge, vxlan devices, and tap-inject.
func (c *Client) initDevices() error {
	// Step 1: Ensure bridge exists
	if err := c.ensureBridge(); err != nil {
		return fmt.Errorf("ensure bridge: %w", err)
	}

	// Step 2: Create VXLAN devices per AF
	for afName, afCfg := range c.Config.AFSettings {
		if !afCfg.Enable {
			continue
		}

		bindAddr := afCfg.BindAddr.String()
		if !afCfg.BindAddr.IsValid() {
			// autoip_interface with no IP resolved yet; use unspecified addr
			if strings.Contains(strings.ToLower(string(afName)), "v6") || strings.Contains(strings.ToLower(string(afName)), "ipv6") {
				bindAddr = "::"
			} else {
				bindAddr = "0.0.0.0"
			}
		}
		vd := &VxlanDev{
			AF:       afName,
			Name:     afCfg.VxlanName,
			VNI:      afCfg.VxlanVNI,
			MTU:      afCfg.VxlanMTU,
			BindAddr: bindAddr,
		}

		if err := c.createVxlanDevice(vd, afCfg); err != nil {
			return fmt.Errorf("create vxlan %s: %w", afName, err)
		}

		c.VxlanDevs[afName] = vd
	}

	// Step 3: Create tap-inject
	if err := c.createTapInject(); err != nil {
		return fmt.Errorf("create tap-inject: %w", err)
	}

	// Step 4: Setup nftables if clamp_mss_to_mtu (non-fatal; may fail in LXC without br_netfilter)
	if c.Config.ClampMSSToMTU {
		if err := c.setupNftables(); err != nil {
			vlog.Warnf("[Client] MSS clamping failed (bridge nftables may not be available): %v", err)
		}
	}

	// Step 5: Open tap-inject fd
	tapFD, err := openTapDevice(tapDeviceName)
	if err != nil {
		return fmt.Errorf("open tap device: %w", err)
	}
	c.TapFD = tapFD

	// Step 6: Flush bridge FDB on every configured vxlan device (enabled or
	// not). Enabled AFs were just recreated above so this is a no-op for
	// them; the real purpose is to drop stale entries on disabled AFs whose
	// device persists from a previous run — without this, isLocalFDBEntry
	// would treat those entries as local MACs and announce them upstream.
	c.flushVxlanFDB()

	return nil
}

// flushDeviceFDB removes every bridge FDB entry on a single link by name. The
// expectedType (e.g. "vxlan", "tun") is checked defensively so a name collision
// with an unrelated link the user owns won't cause us to wipe its FDB. Pass an
// empty string to skip the type check.
func (c *Client) flushDeviceFDB(name, expectedType string) {
	if name == "" {
		return
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}
	if expectedType != "" && link.Type() != expectedType {
		vlog.Warnf("[Client] flush %s: type=%s (expected %s), skipping", name, link.Type(), expectedType)
		return
	}
	linkIdx := link.Attrs().Index
	neighs, err := netlink.NeighList(linkIdx, unix.AF_BRIDGE)
	if err != nil {
		vlog.Warnf("[Client] flush %s: NeighList: %v", name, err)
		return
	}
	removed := 0
	for i := range neighs {
		n := neighs[i]
		if n.LinkIndex != linkIdx {
			continue
		}
		if err := netlink.NeighDel(&n); err == nil {
			removed++
		}
	}
	if removed > 0 {
		vlog.Infof("[Client] flushed %d FDB entries on %s", removed, name)
	}
}

// flushVxlanFDB clears bridge FDB on every vxlan device named in the config
// (enabled or not). For enabled AFs the device was just recreated above so this
// is a no-op; the real purpose is to drop stale entries on disabled AFs whose
// device persists from a previous run.
func (c *Client) flushVxlanFDB() {
	for _, afCfg := range c.Config.AFSettings {
		c.flushDeviceFDB(afCfg.VxlanName, "vxlan")
	}
}

// deleteManagedDevices removes every device this client currently manages
// (enabled vxlans + tap-inject). Called from Stop() — symmetric counterpart to
// createVxlanDevice / createTapInject. Disabled-AF vxlans are intentionally
// left alone (the user may keep them around for receive-only use).
func (c *Client) deleteManagedDevices() {
	for _, vd := range c.VxlanDevs {
		c.deleteDeviceByName(vd.Name, "vxlan")
	}
	c.deleteDeviceByName(tapDeviceName, "")
}

// deleteDeviceByName looks up a link and LinkDels it. The expectedType check
// is defensive against name collision with an unrelated link the user owns.
// Pass an empty string to skip the type check.
func (c *Client) deleteDeviceByName(name, expectedType string) {
	if name == "" {
		return
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}
	if expectedType != "" && link.Type() != expectedType {
		vlog.Warnf("[Client] delete %s: type=%s (expected %s), skipping", name, link.Type(), expectedType)
		return
	}
	if err := netlink.LinkDel(link); err != nil {
		vlog.Warnf("[Client] delete %s: %v", name, err)
		return
	}
	vlog.Infof("[Client] removed device %s", name)
}

func (c *Client) ensureBridge() error {
	_, err := netlink.LinkByName(c.Config.BridgeName)
	if err != nil {
		// Create bridge
		bridge := &netlink.Bridge{
			LinkAttrs: netlink.LinkAttrs{
				Name: c.Config.BridgeName,
			},
		}
		if err := netlink.LinkAdd(bridge); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(bridge); err != nil {
			return err
		}
		vlog.Infof("[Client] created bridge %s", c.Config.BridgeName)
	}
	return nil
}

func (c *Client) createVxlanDevice(vd *VxlanDev, afCfg *config.ClientAFConfig) error {
	// Remove existing device if present
	if existing, err := netlink.LinkByName(vd.Name); err == nil {
		netlink.LinkDel(existing)
	}

	// Use ip command for vxlan creation with all options
	args := []string{
		"link", "add", vd.Name, "type", "vxlan",
		"id", fmt.Sprintf("%d", vd.VNI),
		"local", vd.BindAddr,
		"ttl", "255",
		"dstport", fmt.Sprintf("%d", afCfg.VxlanDstPort),
		"nolearning",
		"udp6zerocsumrx",
	}
	if afCfg.VxlanSrcPortStart > 0 && afCfg.VxlanSrcPortEnd > 0 {
		args = append(args, "srcport",
			fmt.Sprintf("%d", afCfg.VxlanSrcPortStart),
			fmt.Sprintf("%d", afCfg.VxlanSrcPortEnd))
	}

	cmd := exec.Command("ip", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link add vxlan: %v: %s", err, out)
	}

	// Set MTU
	link, err := netlink.LinkByName(vd.Name)
	if err != nil {
		return fmt.Errorf("find vxlan link: %w", err)
	}

	if vd.MTU > 0 {
		if err := netlink.LinkSetMTU(link, vd.MTU); err != nil {
			return fmt.Errorf("set MTU: %w", err)
		}
	}

	// Set master bridge
	bridge, err := netlink.LinkByName(c.Config.BridgeName)
	if err != nil {
		return fmt.Errorf("find bridge: %w", err)
	}
	if err := netlink.LinkSetMaster(link, bridge); err != nil {
		return fmt.Errorf("set master: %w", err)
	}

	// Set bridge_slave options: hairpin on, learning off, neigh_suppress
	neighSuppressFlag := "off"
	if c.Config.NeighSuppress {
		neighSuppressFlag = "on"
	}

	cmd = exec.Command("ip", "link", "set", vd.Name, "type", "bridge_slave",
		"hairpin", "on", "learning", "off", "neigh_suppress", neighSuppressFlag)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set bridge_slave options: %v: %s", err, out)
	}

	// Bring up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}

	vlog.Infof("[Client] created vxlan device %s (VNI=%d, local=%s)", vd.Name, vd.VNI, vd.BindAddr)
	return nil
}

func (c *Client) createTapInject() error {
	// Remove existing
	if existing, err := netlink.LinkByName(tapDeviceName); err == nil {
		netlink.LinkDel(existing)
	}

	cmd := exec.Command("ip", "tuntap", "add", "dev", tapDeviceName, "mode", "tap")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create tap: %v: %s", err, out)
	}

	link, err := netlink.LinkByName(tapDeviceName)
	if err != nil {
		return fmt.Errorf("find tap link: %w", err)
	}
	bridge, err := netlink.LinkByName(c.Config.BridgeName)
	if err != nil {
		return fmt.Errorf("find bridge: %w", err)
	}
	if err := netlink.LinkSetMaster(link, bridge); err != nil {
		return fmt.Errorf("set tap master: %w", err)
	}

	neighSuppressFlag := "off"
	if c.Config.NeighSuppress {
		neighSuppressFlag = "on"
	}

	cmd = exec.Command("ip", "link", "set", tapDeviceName, "type", "bridge_slave",
		"learning", "off", "neigh_suppress", neighSuppressFlag)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set tap bridge_slave options: %v: %s", err, out)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("tap link up: %w", err)
	}

	vlog.Infof("[Client] created tap-inject")
	return nil
}

func (c *Client) buildMSSRuleset() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("table bridge %s {\n", c.Config.ClampMSSTable))
	sb.WriteString("    chain forward {\n")
	sb.WriteString("        type filter hook forward priority filter; policy accept;\n")
	for _, vd := range c.VxlanDevs {
		mtu := vd.MTU
		if mtu <= 0 {
			mtu = 1400
		}
		mss4 := mtu - 40 // IPv4: 20 IP + 20 TCP
		mss6 := mtu - 60 // IPv6: 40 IP + 20 TCP
		fmt.Fprintf(&sb, "        oifname \"%s\" ether type ip tcp flags syn tcp option maxseg size set %d\n", vd.Name, mss4)
		fmt.Fprintf(&sb, "        iifname \"%s\" ether type ip tcp flags syn tcp option maxseg size set %d\n", vd.Name, mss4)
		fmt.Fprintf(&sb, "        oifname \"%s\" ether type ip6 tcp flags syn tcp option maxseg size set %d\n", vd.Name, mss6)
		fmt.Fprintf(&sb, "        iifname \"%s\" ether type ip6 tcp flags syn tcp option maxseg size set %d\n", vd.Name, mss6)
	}
	sb.WriteString("    }\n")
	sb.WriteString("}\n")
	return sb.String()
}

func (c *Client) setupNftables() error {
	// Delete existing table first to avoid duplicate rules on restart
	c.cleanupNftables()

	ruleset := c.buildMSSRuleset()
	cmd := exec.Command("nft", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	vlog.Infof("[Client] nftables MSS clamping configured")
	return nil
}

func (c *Client) cleanupNftables() {
	// Use "delete" (not "destroy") for nftables <1.0 compat; ignore error if table doesn't exist.
	exec.Command("nft", "delete", "table", "bridge", c.Config.ClampMSSTable).Run()
}

func (c *Client) updateVxlanBindAddr(af types.AFName, newAddr string) error {
	vd, ok := c.VxlanDevs[af]
	if !ok {
		return fmt.Errorf("no vxlan device for AF %s", af)
	}

	cmd := exec.Command("ip", "link", "set", vd.Name, "type", "vxlan", "local", newAddr)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("update vxlan local addr: %v: %s", err, out)
	}

	vd.BindAddr = newAddr
	vlog.Infof("[Client] updated vxlan %s local addr to %s", vd.Name, newAddr)
	return nil
}

// Ensure io import is used
var _ = io.EOF
