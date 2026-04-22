package controller

import (
	"net"
	"net/netip"
	"time"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/filter"
	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"

	"github.com/vishvananda/netlink"
)

// ifaceAFChannel identifies one (af, channel) monitored under an interface.
type ifaceAFChannel struct {
	AF      types.AFName
	Channel types.ChannelName
}

// resolveInitialBindAddr runs addr selection once for a controller (af, channel).
func (c *Controller) resolveInitialBindAddr(af types.AFName, ch types.ChannelName) {
	chans, ok := c.Config.AFSettings[af]
	if !ok {
		return
	}
	cc, ok := chans[ch]
	if !ok {
		return
	}
	engine := c.addrEngines[af][ch]
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

// addrWatchLoop monitors netlink address and link events for all (af, channel) with AutoIPInterface.
func (c *Controller) addrWatchLoop() {
	ifaceMap := make(map[string][]ifaceAFChannel)
	for af, chans := range c.Config.AFSettings {
		for ch, cc := range chans {
			if cc.AutoIPInterface != "" {
				ifaceMap[cc.AutoIPInterface] = append(ifaceMap[cc.AutoIPInterface], ifaceAFChannel{AF: af, Channel: ch})
			}
		}
	}
	if len(ifaceMap) == 0 {
		return
	}

	for iface, pairs := range ifaceMap {
		vlog.Infof("[AddrWatch] monitoring interface %s for (af,channel): %v", iface, pairs)
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

// handleAddrChange processes an address change on an interface for the given (af, channel)s.
func (c *Controller) handleAddrChange(ifaceName string, pairs []ifaceAFChannel) {
	for _, p := range pairs {
		af, ch := p.AF, p.Channel
		engine := c.addrEngines[af][ch]
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

		prevIP := cc.BindAddr.String()
		if !cc.BindAddr.IsValid() {
			prevIP = ""
		}

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

		if cc.BindAddr == newAddr {
			continue
		}

		oldAddr := cc.BindAddr
		vlog.Infof("[AddrWatch] AF=%s channel=%s: detected IP change on %s: %s -> %s", af, ch, ifaceName, prevIP, newAddr)

		// Update config
		cc.BindAddr = newAddr

		// Rebind listeners
		c.rebindAFListener(af, ch, oldAddr, newAddr)
	}
}

// rebindAFListener closes the old listener and starts a new one on the new address.
func (c *Controller) rebindAFListener(af types.AFName, ch types.ChannelName, oldAddr, newAddr netip.Addr) {
	chans, ok := c.Config.AFSettings[af]
	if !ok {
		return
	}
	cc, ok := chans[ch]
	if !ok {
		return
	}

	// Close old listener
	c.mu.Lock()
	if oldChans, ok := c.afListeners[af]; ok {
		if oldAL, ok2 := oldChans[ch]; ok2 {
			oldAL.TCPListener.Close()
			oldAL.UDPConn.Close()
			delete(oldChans, ch)
			if len(oldChans) == 0 {
				delete(c.afListeners, af)
			}
		}
	}
	c.mu.Unlock()

	// Retry bind with backoff (IPv6 DAD may delay address availability)
	bindStr := netip.AddrPortFrom(newAddr, cc.CommunicationPort).String()
	var tcpListener net.Listener
	var udpConn *net.UDPConn
	var err error

	for attempt := 0; attempt < 10; attempt++ {
		tcpListener, err = net.Listen("tcp", bindStr)
		if err == nil {
			udpAddr, _ := net.ResolveUDPAddr("udp", bindStr)
			udpConn, err = net.ListenUDP("udp", udpAddr)
			if err == nil {
				break
			}
			tcpListener.Close()
		}
		select {
		case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
		case <-c.ctx.Done():
			return
		}
	}
	if err != nil {
		vlog.Errorf("[AddrWatch] AF=%s channel=%s: failed to rebind on %s after retries: %v", af, ch, bindStr, err)
		return
	}

	al := &AFListener{
		AF:          af,
		Channel:     ch,
		BindAddr:    newAddr,
		Port:        cc.CommunicationPort,
		TCPListener: tcpListener,
		UDPConn:     udpConn,
		UDPSessions: crypto.NewSessionManager(),
	}

	c.mu.Lock()
	if _, ok := c.afListeners[af]; !ok {
		c.afListeners[af] = make(map[types.ChannelName]*AFListener)
	}
	c.afListeners[af][ch] = al
	c.mu.Unlock()

	vlog.Infof("[AddrWatch] AF=%s channel=%s: rebound listeners on %s", af, ch, bindStr)

	go c.tcpAcceptLoop(al)
	go c.udpReadLoop(al)

	// All existing client connections on this (af, channel) will fail on their own
	// (TCP reads/writes will error out). Clients will reconnect via tcpConnLoop.
	_ = oldAddr
}
