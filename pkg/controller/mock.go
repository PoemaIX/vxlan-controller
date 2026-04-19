package controller

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"
	"vxlan-controller/pkg/webui"
)

// mockSiteConfig holds per-site generation parameters.
type mockSiteConfig struct {
	id        types.ClientID
	name      string
	v4Addr    netip.Addr
	routeMACs []net.HardwareAddr
	routeIPs  []netip.Addr
}

// RunMock starts the controller in mock mode: no listeners, fake data, WebUI only.
// It populates a real Controller's State and clientMcastStats, then reuses
// buildStateSnapshot() — the same code path as production.
func RunMock(cfg *config.ControllerConfig) error {
	if cfg.WebUI == nil {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sites := buildMockSites(cfg)
	if len(sites) == 0 {
		return nil
	}

	// Build a real Controller (no listeners, just state + config)
	c := &Controller{
		Config:           cfg,
		ControllerID:     types.ClientID{}, // dummy, not used
		State:            newControllerState(),
		clients:          make(map[types.ClientID]*ClientConn),
		clientMcastStats: make(map[types.ClientID]*ClientMcastStats),
		ctx:              ctx,
		cancel:           cancel,
	}

	// Populate State with mock data
	populateMockState(c, sites)
	populateMockMcastStats(c, sites)

	// StateProvider reuses the real buildStateSnapshot
	srv := webui.New(cfg.WebUI, func() *webui.StateSnapshot {
		return c.buildStateSnapshot()
	})

	// Periodically jitter
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				jitterState(c, sites)
				c.mu.Unlock()
				jitterMcastStats(c, sites)
			case <-ctx.Done():
				return
			}
		}
	}()

	vlog.Infof("[Mock] starting WebUI on %s with %d sites", cfg.WebUI.BindAddr, len(sites))
	srv.Run(ctx)
	return nil
}

func buildMockSites(cfg *config.ControllerConfig) []mockSiteConfig {
	rng := rand.New(rand.NewSource(42))
	var sites []mockSiteConfig

	for i, pc := range cfg.AllowedClients {
		s := mockSiteConfig{
			id:   pc.ClientID,
			name: pc.ClientName,
			v4Addr: netip.AddrFrom4([4]byte{
				10, byte(i + 1), 0, 1,
			}),
		}

		numRoutes := 3 + rng.Intn(4)
		for j := 0; j < numRoutes; j++ {
			mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, byte(i + 1), byte(j + 1)}
			ip := netip.AddrFrom4([4]byte{10, byte(i + 1), 1, byte(j + 10)})
			s.routeMACs = append(s.routeMACs, mac)
			s.routeIPs = append(s.routeIPs, ip)
		}

		sites = append(sites, s)
	}

	return sites
}

// --- Latency base data ---

var siteLatencyBase = map[[2]string]float64{
	{"taiwan", "tokyo"}:   30,
	{"taiwan", "us-west"}: 150,
	{"taiwan", "europe"}:  200,
	{"tokyo", "us-west"}:  120,
	{"tokyo", "europe"}:   230,
	{"us-west", "europe"}: 90,
}

func getBaseLatency(a, b string) float64 {
	if v, ok := siteLatencyBase[[2]string{a, b}]; ok {
		return v
	}
	if v, ok := siteLatencyBase[[2]string{b, a}]; ok {
		return v
	}
	return 50
}

// --- Populate real ControllerState ---

func populateMockState(c *Controller, sites []mockSiteConfig) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Clients
	for _, s := range sites {
		ci := &ClientInfo{
			ClientID:   s.id,
			ClientName: s.name,
			Endpoints: map[types.AFName]*types.Endpoint{
				"v4": {IP: s.v4Addr, ProbePort: 5010, VxlanDstPort: 4789},
			},
			LastSeen: now.Add(-time.Duration(rng.Intn(10)) * time.Second),
		}
		for j, mac := range s.routeMACs {
			ci.Routes = append(ci.Routes, types.Type2Route{MAC: mac, IP: s.routeIPs[j]})
		}
		c.State.Clients[s.id] = ci
	}

	// BestPaths
	c.State.BestPaths = make(map[types.ClientID]map[types.ClientID]*types.BestPathEntry)
	for _, src := range sites {
		c.State.BestPaths[src.id] = make(map[types.ClientID]*types.BestPathEntry)
		for _, dst := range sites {
			if src.id == dst.id {
				continue
			}
			base := getBaseLatency(src.name, dst.name)
			jitter := base * 0.1 * (rng.Float64() - 0.5)
			latency := base + jitter
			c.State.BestPaths[src.id][dst.id] = &types.BestPathEntry{
				AF:   "v4",
				Cost: latency + 20,
				Raw: &types.AFLatency{
					Mean:        latency,
					Std:         latency * 0.05,
					PacketLoss:  0,
					Priority:    10,
					ForwardCost: 20,
					QualityCost: latency,
				},
			}
		}
	}

	// RouteMatrix (direct for all pairs)
	for _, src := range sites {
		c.State.RouteMatrix[src.id] = make(map[types.ClientID]*types.RouteEntry)
		for _, dst := range sites {
			if src.id == dst.id {
				continue
			}
			c.State.RouteMatrix[src.id][dst.id] = &types.RouteEntry{
				NextHop: dst.id,
				AF:      "v4",
			}
		}
	}

	// RouteTable
	for _, s := range sites {
		for j, mac := range s.routeMACs {
			c.State.RouteTable = append(c.State.RouteTable, &types.RouteTableEntry{
				MAC: mac,
				IP:  s.routeIPs[j],
				Owners: map[types.ClientID]time.Time{
					s.id: now.Add(5 * time.Minute),
				},
			})
		}
	}

	c.State.LastClientChange = now
}

func populateMockMcastStats(c *Controller, sites []mockSiteConfig) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	type mockReason struct {
		reason  string
		details []string
	}
	reasonPool := []mockReason{
		{"ipv4:udp:5353", []string{"10.1.0.5 -> 224.0.0.251", "10.1.0.8 -> 224.0.0.251"}},
		{"ipv4:udp:1900", []string{"10.1.0.5 -> 239.255.255.250", "10.1.0.12 -> 239.255.255.250"}},
		{"igmp", []string{"10.1.0.5 -> 224.0.0.22", "10.1.0.8 -> 224.0.0.1"}},
		{"ipv6:udp:5353", []string{"fe80::1 -> ff02::fb", "fe80::a -> ff02::fb"}},
		{"rate_limited", nil},
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, s := range sites {
		cs := &ClientMcastStats{MACs: make(map[string]*MACMcastStats)}
		for _, mac := range s.routeMACs {
			ms := &MACMcastStats{
				TxAccepted: uint64(50 + rng.Intn(200)),
			}
			if rng.Float64() < 0.4 {
				mr := reasonPool[rng.Intn(len(reasonPool))]
				rejCount := uint64(5 + rng.Intn(30))
				ms.TxRejected = rejCount
				rr := RejectReason{Direction: "tx", Reason: mr.reason, Count: rejCount}
				for _, d := range mr.details {
					dc := uint64(1 + rng.Intn(int(rejCount)/2+1))
					rr.Details = append(rr.Details, RejectDetail{Detail: d, Count: dc})
				}
				ms.RejectReasons = []RejectReason{rr}
			}
			cs.MACs[mac.String()] = ms
		}
		c.clientMcastStats[s.id] = cs
	}
}

// --- Jitter ---

func jitterState(c *Controller, sites []mockSiteConfig) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	now := time.Now()

	for _, src := range sites {
		for _, dst := range sites {
			if src.id == dst.id {
				continue
			}
			bp := c.State.BestPaths[src.id][dst.id]
			if bp == nil || bp.Raw == nil {
				continue
			}
			base := getBaseLatency(src.name, dst.name)
			jitter := base * 0.15 * (rng.Float64() - 0.5)
			bp.Raw.Mean = base + jitter
			bp.Raw.Std = base * 0.05 * (1 + rng.Float64())
			bp.Raw.QualityCost = bp.Raw.Mean
			bp.Cost = bp.Raw.QualityCost + bp.Raw.ForwardCost
			if rng.Float64() < 0.05 {
				bp.Raw.PacketLoss = rng.Float64() * 0.1
			} else {
				bp.Raw.PacketLoss = 0
			}
		}
	}

	for _, ci := range c.State.Clients {
		ci.LastSeen = now.Add(-time.Duration(rng.Intn(5)) * time.Second)
	}
}

func jitterMcastStats(c *Controller, sites []mockSiteConfig) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, s := range sites {
		cs := c.clientMcastStats[s.id]
		if cs == nil {
			continue
		}
		for _, ms := range cs.MACs {
			ms.TxAccepted += uint64(rng.Intn(30))
			if rng.Float64() < 0.2 {
				inc := uint64(rng.Intn(5))
				ms.TxRejected += inc
				if len(ms.RejectReasons) > 0 {
					ms.RejectReasons[0].Count += inc
					// Also increment a random detail if present
					if len(ms.RejectReasons[0].Details) > 0 {
						di := rng.Intn(len(ms.RejectReasons[0].Details))
						ms.RejectReasons[0].Details[di].Count += inc
					}
				}
			}
		}
	}
}
