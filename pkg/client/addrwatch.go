package client

import (
	"net/netip"
	"time"

	"vxlan-controller/pkg/filter"
	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"

	"github.com/vishvananda/netlink"
)

// resolveInitialBindAddr runs addr selection once for an (af, channel) and sets BindAddr if found.
func (c *Client) resolveInitialBindAddr(af types.AFName, ch types.ChannelName) {
	chans, ok := c.Config.AFSettings[af]
	if !ok {
		return
	}
	cc, ok := chans[ch]
	if !ok {
		return
	}
	var engine *filter.AddrSelectEngine
	if eChans, ok := c.addrEngines[af]; ok {
		engine = eChans[ch]
	}
	if engine == nil {
		return
	}

	addrs := filter.GetInterfaceAddrs(cc.AutoIPInterface, string(af))
	selected := engine.Select(addrs, "", cc.AutoIPInterface)
	if selected == "" {
		vlog.Warnf("[AddrWatch] AF=%s channel=%s: no IP found on interface %s at startup, will retry on events", af, ch, cc.AutoIPInterface)
		return
	}

	addr, err := netip.ParseAddr(selected)
	if err != nil {
		vlog.Errorf("[AddrWatch] AF=%s channel=%s: Lua returned invalid IP %q: %v", af, ch, selected, err)
		return
	}

	cc.BindAddr = addr
	vlog.Infof("[AddrWatch] AF=%s channel=%s: initial bind_addr resolved to %s from interface %s", af, ch, addr, cc.AutoIPInterface)
}

// ifaceAFChannel identifies an (af, channel) tuple watched on an interface.
type ifaceAFChannel struct {
	AF      types.AFName
	Channel types.ChannelName
}

// addrWatchLoop monitors netlink address and link events for all (af, channel) pairs with AutoIPInterface.
func (c *Client) addrWatchLoop() {
	ifaceMap := make(map[string][]ifaceAFChannel)
	for afName, chans := range c.Config.AFSettings {
		for chName, cc := range chans {
			if cc.AutoIPInterface != "" {
				ifaceMap[cc.AutoIPInterface] = append(ifaceMap[cc.AutoIPInterface], ifaceAFChannel{AF: afName, Channel: chName})
			}
		}
	}
	if len(ifaceMap) == 0 {
		return
	}

	for iface, pairs := range ifaceMap {
		vlog.Infof("[AddrWatch] monitoring interface %s for (af, channel) pairs: %v", iface, pairs)
	}

	addrCh := make(chan netlink.AddrUpdate)
	addrDone := make(chan struct{})
	defer close(addrDone)

	if err := netlink.AddrSubscribe(addrCh, addrDone); err != nil {
		vlog.Errorf("[AddrWatch] netlink addr subscribe error: %v", err)
		return
	}

	linkCh := make(chan netlink.LinkUpdate)
	linkDone := make(chan struct{})
	defer close(linkDone)

	if err := netlink.LinkSubscribe(linkCh, linkDone); err != nil {
		vlog.Errorf("[AddrWatch] netlink link subscribe error: %v", err)
		return
	}

	debounceTimers := make(map[string]*time.Timer)
	debounceCh := make(chan string, 16)

	triggerDebounce := func(ifaceName string) {
		if t, ok := debounceTimers[ifaceName]; ok {
			t.Reset(time.Second)
		} else {
			debounceTimers[ifaceName] = time.AfterFunc(time.Second, func() {
				select {
				case debounceCh <- ifaceName:
				default:
				}
			})
		}
	}

	linkIndexToName := make(map[int]string)
	for ifaceName := range ifaceMap {
		if link, err := netlink.LinkByName(ifaceName); err == nil {
			linkIndexToName[link.Attrs().Index] = ifaceName
		}
	}

	for {
		select {
		case update, ok := <-addrCh:
			if !ok {
				return
			}
			vlog.Debugf("[AddrWatch] addr event: linkIndex=%d newAddr=%v ip=%v", update.LinkIndex, update.NewAddr, update.LinkAddress.IP)
			ifaceName, found := linkIndexToName[update.LinkIndex]
			if !found {
				for name := range ifaceMap {
					if link, err := netlink.LinkByName(name); err == nil {
						linkIndexToName[link.Attrs().Index] = name
						if link.Attrs().Index == update.LinkIndex {
							ifaceName = name
							found = true
						}
					}
				}
			}
			if found {
				triggerDebounce(ifaceName)
			}

		case update, ok := <-linkCh:
			if !ok {
				return
			}
			name := update.Attrs().Name
			if _, monitored := ifaceMap[name]; monitored {
				linkIndexToName[update.Attrs().Index] = name
				triggerDebounce(name)
			}

		case ifaceName := <-debounceCh:
			c.handleAddrChange(ifaceName, ifaceMap[ifaceName])

		case <-c.ctx.Done():
			for _, t := range debounceTimers {
				t.Stop()
			}
			return
		}
	}
}

// handleAddrChange processes an address change on an interface for the given (af, channel) pairs.
func (c *Client) handleAddrChange(ifaceName string, pairs []ifaceAFChannel) {
	for _, p := range pairs {
		af := p.AF
		ch := p.Channel

		var engine *filter.AddrSelectEngine
		if eChans, ok := c.addrEngines[af]; ok {
			engine = eChans[ch]
		}
		if engine == nil {
			continue
		}

		chans, ok := c.Config.AFSettings[af]
		if !ok {
			continue
		}
		cc, ok := chans[ch]
		if !ok {
			continue
		}

		addrs := filter.GetInterfaceAddrs(ifaceName, string(af))

		c.mu.Lock()
		prevIP := cc.BindAddr.String()
		if !cc.BindAddr.IsValid() {
			prevIP = ""
		}
		c.mu.Unlock()

		selected := engine.Select(addrs, prevIP, ifaceName)
		if selected == "" {
			vlog.Debugf("[AddrWatch] AF=%s channel=%s: no valid IP on %s, ignoring", af, ch, ifaceName)
			continue
		}

		newAddr, err := netip.ParseAddr(selected)
		if err != nil {
			vlog.Errorf("[AddrWatch] AF=%s channel=%s: Lua returned invalid IP %q: %v", af, ch, selected, err)
			continue
		}

		c.mu.Lock()
		changed := cc.BindAddr != newAddr
		c.mu.Unlock()

		if !changed {
			continue
		}

		vlog.Infof("[AddrWatch] AF=%s channel=%s: detected IP change on %s: %s -> %s", af, ch, ifaceName, prevIP, newAddr)
		if err := c.updateBindAddr(af, ch, newAddr); err != nil {
			vlog.Errorf("[AddrWatch] AF=%s channel=%s: updateBindAddr failed: %v", af, ch, err)
		}
	}
}
