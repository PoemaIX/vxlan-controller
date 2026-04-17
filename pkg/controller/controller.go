package controller

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/filter"
	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"

	pb "vxlan-controller/proto"
)

const (
	sendQueueSize     = 256
	keepAlivePeriod   = 30 * time.Second
	offlineCheckEvery = 30 * time.Second
)

// Controller implements the VXLAN controller.
type Controller struct {
	Config       *config.ControllerConfig
	PrivateKey   [32]byte
	ControllerID types.ControllerID

	mu    sync.Mutex
	State *ControllerState

	// Per-AF listeners
	afListeners map[types.AFName]*AFListener

	// Per-Client connection management
	clients map[types.ClientID]*ClientConn

	// Session manager for UDP
	udpSessions *crypto.SessionManager
	// Track client UDP addresses per AF (from handshake source addr)
	udpAddrs map[udpAddrKey]*net.UDPAddr

	// Debounce timers
	newClientTimer    *time.Timer
	newClientMaxTimer *time.Timer
	newClientFirst    time.Time
	topoTimer         *time.Timer
	topoMaxTimer      *time.Timer
	topoFirst         time.Time

	// Probe counter
	probeCounter uint64

	// Periodic probe ticker
	probeTicker *time.Ticker

	ctx    context.Context
	cancel context.CancelFunc

	// Allowed public keys for handshake verification
	allowedKeys [][32]byte

	// Client-reported multicast stats for WebUI
	clientMcastStats map[types.ClientID]*ClientMcastStats

	// Addr watch engines for autoip_interface
	addrEngines map[types.AFName]*filter.AddrSelectEngine

	// Cost mode: "probe" or "static"
	CostMode        string
	staticCostsByID map[types.ClientID]map[types.ClientID]map[types.AFName]float64
}

type udpAddrKey struct {
	ClientID types.ClientID
	AF       types.AFName
}

// AFListener manages TCP + UDP on a single AF.
type AFListener struct {
	AF          types.AFName
	BindAddr    netip.Addr
	Port        uint16
	TCPListener net.Listener
	UDPConn     net.PacketConn
	UDPSessions *crypto.SessionManager
}

func New(cfg *config.ControllerConfig) *Controller {
	pubKey := crypto.PublicKey(cfg.PrivateKey)
	ctx, cancel := context.WithCancel(context.Background())

	c := &Controller{
		Config:           cfg,
		PrivateKey:       cfg.PrivateKey,
		ControllerID:     pubKey,
		State:            newControllerState(),
		afListeners:      make(map[types.AFName]*AFListener),
		clients:          make(map[types.ClientID]*ClientConn),
		udpSessions:      crypto.NewSessionManager(),
		udpAddrs:         make(map[udpAddrKey]*net.UDPAddr),
		clientMcastStats: make(map[types.ClientID]*ClientMcastStats),
		ctx:              ctx,
		cancel:           cancel,
	}

	// Build allowed keys list
	for _, pc := range cfg.AllowedClients {
		c.allowedKeys = append(c.allowedKeys, pc.ClientID)
	}

	// Init cost mode
	c.CostMode = cfg.CostMode
	if c.CostMode == "" {
		c.CostMode = "probe"
	}
	if cfg.StaticCosts != nil {
		c.staticCostsByID = c.resolveStaticCosts(cfg.StaticCosts)
	}

	// Init addr select engines for AFs with AutoIPInterface
	c.addrEngines = make(map[types.AFName]*filter.AddrSelectEngine)
	for afName, afCfg := range cfg.AFSettings {
		if afCfg.AutoIPInterface == "" {
			continue
		}
		engine, err := filter.NewAddrSelectEngine(afCfg.AddrSelectScript)
		if err != nil {
			vlog.Fatalf("[Controller] AF=%s: failed to init addr select engine: %v", afName, err)
		}
		c.addrEngines[afName] = engine
	}

	return c
}

func (c *Controller) Run() error {
	vlog.Infof("[Controller] starting, ID=%s", c.ControllerID.Hex())

	// Resolve initial bind addrs for AFs with autoip_interface
	for afName, afCfg := range c.Config.AFSettings {
		if afCfg.AutoIPInterface != "" {
			c.resolveInitialBindAddr(afName)
		}
	}

	// Start AF listeners
	for afName, afCfg := range c.Config.AFSettings {
		if !afCfg.Enable {
			continue
		}
		if !afCfg.BindAddr.IsValid() {
			vlog.Warnf("[Controller] AF=%s: no bind_addr resolved yet, skipping listener start (will start on addr change)", afName)
			continue
		}
		if err := c.startAFListener(afName, afCfg); err != nil {
			return fmt.Errorf("start AF listener %s: %w", afName, err)
		}
	}

	// Start offline checker
	go c.offlineChecker()

	// Start periodic probe timer
	go c.periodicProbeLoop()

	// Start web UI if configured
	c.startWebUI()

	// Start addr watch loop for autoip_interface
	go c.addrWatchLoop()

	// Start API server
	go c.apiServer()

	<-c.ctx.Done()
	return nil
}

func (c *Controller) Stop() {
	c.cancel()

	// Close addr select engines
	for _, engine := range c.addrEngines {
		engine.Close()
	}

	// Close all listeners
	for _, al := range c.afListeners {
		if al.TCPListener != nil {
			al.TCPListener.Close()
		}
		if al.UDPConn != nil {
			al.UDPConn.Close()
		}
	}

	// Close all client connections
	c.mu.Lock()
	for _, cc := range c.clients {
		close(cc.SendQueue)
		for _, afc := range cc.AFConns {
			if afc.TCPConn != nil {
				afc.TCPConn.Close()
			}
			afc.CloseDone()
		}
	}
	c.mu.Unlock()
}

func (c *Controller) startAFListener(afName types.AFName, afCfg *config.ControllerAFConfig) error {
	bindStr := netip.AddrPortFrom(afCfg.BindAddr, afCfg.CommunicationPort).String()

	// TCP listener
	tcpListener, err := net.Listen("tcp", bindStr)
	if err != nil {
		return fmt.Errorf("tcp listen: %w", err)
	}

	// UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", bindStr)
	if err != nil {
		return fmt.Errorf("resolve udp: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		tcpListener.Close()
		return fmt.Errorf("udp listen: %w", err)
	}

	al := &AFListener{
		AF:          afName,
		BindAddr:    afCfg.BindAddr,
		Port:        afCfg.CommunicationPort,
		TCPListener: tcpListener,
		UDPConn:     udpConn,
		UDPSessions: crypto.NewSessionManager(),
	}
	c.afListeners[afName] = al

	vlog.Infof("[Controller] listening on %s (AF=%s)", bindStr, afName)

	go c.tcpAcceptLoop(al)
	go c.udpReadLoop(al)

	return nil
}

func (c *Controller) tcpAcceptLoop(al *AFListener) {
	for {
		conn, err := al.TCPListener.Accept()
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				vlog.Errorf("[Controller] TCP accept error on %s: %v", al.AF, err)
				continue
			}
		}

		// Enable TCP keepalive
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(keepAlivePeriod)
		}

		go c.handleTCPConn(al.AF, conn)
	}
}

func (c *Controller) handleTCPConn(af types.AFName, conn net.Conn) {
	defer conn.Close()

	remoteIP := addrFromConn(conn)
	vlog.Infof("[Controller] new TCP connection from %s on AF=%s", conn.RemoteAddr(), af)

	// Step 1: Noise IK handshake
	localIndex := c.udpSessions.AllocateIndex()

	// Read HandshakeInit
	initMsg, err := protocol.ReadTCPRaw(conn)
	if err != nil {
		vlog.Errorf("[Controller] handshake read error: %v", err)
		return
	}

	respMsg, session, err := crypto.HandshakeRespond(c.PrivateKey, initMsg, c.allowedKeys, localIndex)
	if err != nil {
		vlog.Warnf("[Controller] handshake failed: %v", err)
		return
	}

	// Send HandshakeResp
	if err := protocol.WriteTCPRaw(conn, respMsg); err != nil {
		vlog.Errorf("[Controller] handshake resp write error: %v", err)
		return
	}

	session.IsUDP = false
	clientID := types.ClientID(session.PeerID)
	vlog.Debugf("[Controller] handshake completed with client %s on AF=%s", clientID.Hex()[:8], af)

	// Step 2: Read ClientRegister
	msgType, payload, err := protocol.ReadTCPMessage(conn, session)
	if err != nil {
		vlog.Errorf("[Controller] read ClientRegister error: %v", err)
		return
	}
	if msgType != protocol.MsgClientRegister {
		vlog.Warnf("[Controller] expected ClientRegister, got %d", msgType)
		return
	}

	var reg pb.ClientRegister
	if err := proto.Unmarshal(payload, &reg); err != nil {
		vlog.Errorf("[Controller] unmarshal ClientRegister error: %v", err)
		return
	}

	// Step 3: Update state
	c.mu.Lock()

	// Find or create ClientInfo
	ci, exists := c.State.Clients[clientID]
	if !exists {
		ci = &ClientInfo{
			ClientID:  clientID,
			Endpoints: make(map[types.AFName]*types.Endpoint),
		}
		// Look up ClientName from config
		for _, pc := range c.Config.AllowedClients {
			if pc.ClientID == clientID {
				ci.ClientName = pc.ClientName
				break
			}
		}
		c.State.Clients[clientID] = ci
	}

	ci.LastSeen = time.Now()

	// Check if endpoint IP changed (before overwriting)
	var ipChanged bool
	if oldEp, had := ci.Endpoints[af]; had && oldEp.IP != remoteIP {
		ipChanged = true
		vlog.Debugf("[Controller] client %s AF=%s IP changed %s -> %s",
			clientID.Hex()[:8], af, oldEp.IP, remoteIP)
	}

	// Update endpoint for this AF
	ep := &types.Endpoint{
		IP: remoteIP,
	}
	if afep, ok := reg.AfEndpoints[string(af)]; ok {
		ep.ProbePort = uint16(afep.ProbePort)
		ep.VxlanDstPort = uint16(afep.VxlanDstPort)
	}
	ci.Endpoints[af] = ep

	// Find or create ClientConn
	cc, ccExists := c.clients[clientID]
	if !ccExists {
		// Look up per-client filter config
		var filterCfg *filter.FilterConfig
		for _, pc := range c.Config.AllowedClients {
			if pc.ClientID == clientID {
				filterCfg = pc.Filters
				break
			}
		}
		filters, err := filter.NewFilterSet(filterCfg)
		if err != nil {
			vlog.Errorf("[Controller] failed to init filters for client %s: %v", clientID.Hex()[:8], err)
			c.mu.Unlock()
			conn.Close()
			return
		}
		cc = &ClientConn{
			ClientID:  clientID,
			AFConns:   make(map[types.AFName]*AFConn),
			SendQueue: make(chan QueueItem, sendQueueSize),
			Filters:   filters,
		}
		c.clients[clientID] = cc
		go c.clientSendLoop(cc)
	}

	// Create AFConn
	afc := &AFConn{
		AF:          af,
		TCPConn:     conn,
		Session:     session,
		ConnectedAt: time.Now(),
		Done:        make(chan struct{}),
		Cleaned:     make(chan struct{}),
	}

	// Replace previous AF connection if exists:
	// Close old conn → old goroutine's handleDisconnect does cleanup → then we continue
	var oldAfc *AFConn
	if old, ok := cc.AFConns[af]; ok {
		oldAfc = old
		old.CloseDone()
	}

	if oldAfc != nil {
		c.mu.Unlock()
		oldAfc.TCPConn.Close()
		<-oldAfc.Cleaned // wait for old goroutine's handleDisconnect to finish
		c.mu.Lock()
	}

	cc.AFConns[af] = afc
	c.trySyncClient(cc)

	// Update last client change and trigger debounce
	if !exists {
		c.State.LastClientChange = time.Now()
		c.resetNewClientDebounce()

		// Notify other clients about the new client
		c.pushDelta(&pb.ControllerStateUpdate{
			Update: &pb.ControllerStateUpdate_ClientJoined{
				ClientJoined: &pb.ClientJoined{
					ClientInfo: clientInfoToProto(ci, c.endpointOverrides(clientID)),
				},
			},
		})
	} else {
		// Client reconnected - push updated info
		c.pushDelta(&pb.ControllerStateUpdate{
			Update: &pb.ControllerStateUpdate_ClientInfoUpdate{
				ClientInfoUpdate: &pb.ClientInfoUpdateProto{
					ClientInfo: clientInfoToProto(ci, c.endpointOverrides(clientID)),
				},
			},
		})

		// If the endpoint IP changed, trigger a new probe+topology cycle
		// so all clients get updated FDB entries
		if ipChanged {
			c.State.LastClientChange = time.Now()
			c.resetNewClientDebounce()
		}
	}

	c.mu.Unlock()

	// Register UDP session for this client
	udpSession := &crypto.Session{
		LocalIndex:  session.LocalIndex,
		RemoteIndex: session.RemoteIndex,
		SendKey:     session.SendKey,
		RecvKey:     session.RecvKey,
		PeerID:      session.PeerID,
		IsUDP:       true,
	}
	c.udpSessions.AddSession(udpSession)

	// Step 4: Message read loop
	c.tcpRecvLoop(cc, afc, session)

	// Cleanup on disconnect
	c.handleDisconnect(cc, af, afc)
}

func (c *Controller) tcpRecvLoop(cc *ClientConn, afc *AFConn, session *crypto.Session) {
	for {
		select {
		case <-afc.Done:
			return
		case <-c.ctx.Done():
			return
		default:
		}

		msgType, payload, err := protocol.ReadTCPMessage(afc.TCPConn, session)
		if err != nil {
			vlog.Errorf("[Controller] TCP recv error from %s: %v", cc.ClientID.Hex()[:8], err)
			return
		}

		// Update LastSeen
		c.mu.Lock()
		if ci, ok := c.State.Clients[cc.ClientID]; ok {
			ci.LastSeen = time.Now()
		}
		c.mu.Unlock()

		switch msgType {
		case protocol.MsgMACUpdate:
			c.handleMACUpdate(cc, payload)
		case protocol.MsgProbeResults:
			c.handleProbeResults(cc, payload)
		case protocol.MsgMcastStatsReport:
			c.handleMcastStatsReport(cc, payload)
		default:
			vlog.Infof("[Controller] unknown msg_type %d from %s", msgType, cc.ClientID.Hex()[:8])
		}
	}
}

func (c *Controller) handleMACUpdate(cc *ClientConn, payload []byte) {
	var update pb.MACUpdate
	if err := proto.Unmarshal(payload, &update); err != nil {
		vlog.Infof("[Controller] unmarshal MACUpdate error: %v", err)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ci, ok := c.State.Clients[cc.ClientID]
	if !ok {
		return
	}

	// Record the latest (session_id, seqid) from this client so we can echo
	// it back in the broadcast triggered by this update. A full sync resets
	// the source's seqid to 0, so we always trust the incoming values.
	if update.SessionId != "" {
		cc.LastClientSessionID = update.SessionId
		cc.LastClientSeqid = update.Seqid
	}

	if update.IsFull {
		// Full replacement (deduplicate by MAC+IP)
		type routeKey struct {
			mac string
			ip  netip.Addr
		}
		seen := make(map[routeKey]struct{})
		var routes []types.Type2Route
		for _, r := range update.Routes {
			rt := types.Type2Route{MAC: r.Mac}
			if len(r.Ip) == 4 {
				rt.IP = netip.AddrFrom4([4]byte(r.Ip))
			} else if len(r.Ip) == 16 {
				rt.IP = netip.AddrFrom16([16]byte(r.Ip))
			}
			// Normalize unspecified IPs
			if rt.IP.IsValid() && rt.IP.IsUnspecified() {
				rt.IP = netip.Addr{}
			}
			// Filter inbound route
			if cc.Filters != nil {
				ipStr := ""
				if rt.IP.IsValid() {
					ipStr = rt.IP.String()
				}
				if !cc.Filters.InputRoute.FilterRoute(rt.MAC.String(), ipStr, false) {
					continue
				}
			}
			key := routeKey{mac: rt.MAC.String(), ip: rt.IP}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			routes = append(routes, rt)
		}
		ci.Routes = routes
		vlog.Debugf("[Controller] MACUpdate from %s: %d routes (full)", cc.ClientID.Hex()[:8], len(routes))
	} else {
		// Incremental: apply add/delete per route
		for _, r := range update.Routes {
			rt := types.Type2Route{MAC: r.Mac}
			if len(r.Ip) == 4 {
				rt.IP = netip.AddrFrom4([4]byte(r.Ip))
			} else if len(r.Ip) == 16 {
				rt.IP = netip.AddrFrom16([16]byte(r.Ip))
			}
			// Normalize unspecified IPs
			if rt.IP.IsValid() && rt.IP.IsUnspecified() {
				rt.IP = netip.Addr{}
			}
			// Filter inbound route
			if cc.Filters != nil {
				ipStr := ""
				if rt.IP.IsValid() {
					ipStr = rt.IP.String()
				}
				if !cc.Filters.InputRoute.FilterRoute(rt.MAC.String(), ipStr, r.IsDelete) {
					continue
				}
			}
			if r.IsDelete {
				ci.Routes = removeRoute(ci.Routes, rt)
			} else {
				ci.Routes = addRoute(ci.Routes, rt)
			}
		}
		vlog.Debugf("[Controller] MACUpdate from %s: %d changes (inc)", cc.ClientID.Hex()[:8], len(update.Routes))
	}

	// Update RouteTable
	c.updateRouteTable()

	// Push RouteTable update, stamped with the source client's (session_id,
	// seqid) so the source can confirm round-trip completion via syncCheckLoop.
	c.pushDelta(&pb.ControllerStateUpdate{
		Update: &pb.ControllerStateUpdate_RouteTableUpdate{
			RouteTableUpdate: &pb.RouteTableUpdateProto{
				Entries: routeTableToProto(c.State.RouteTable),
			},
		},
		SourceClientId:  cc.ClientID[:],
		SourceSessionId: cc.LastClientSessionID,
		SourceSeqid:     cc.LastClientSeqid,
	})
}

func (c *Controller) handleProbeResults(cc *ClientConn, payload []byte) {
	var results pb.ProbeResults
	if err := proto.Unmarshal(payload, &results); err != nil {
		vlog.Errorf("[Controller] unmarshal ProbeResults error: %v", err)
		return
	}

	c.mu.Lock()

	var srcID types.ClientID
	copy(srcID[:], results.SourceClientId)

	// Ensure src row exists
	if c.State.LatencyMatrix[srcID] == nil {
		c.State.LatencyMatrix[srcID] = make(map[types.ClientID]*types.LatencyInfo)
	}

	now := time.Now()

	for dstHex, entry := range results.Results {
		dstID, err := types.ClientIDFromHex(dstHex)
		if err != nil {
			continue
		}

		li := &types.LatencyInfo{
			AFs: make(map[types.AFName]*types.AFLatency),
		}
		newReachable := false
		for afStr, afResult := range entry.AfResults {
			li.AFs[types.AFName(afStr)] = &types.AFLatency{
				Mean:           afResult.LatencyMean,
				Std:            afResult.LatencyStd,
				PacketLoss:     afResult.PacketLoss,
				Priority:       int(afResult.Priority),
				AdditionalCost: afResult.AdditionalCost,
			}
			if afResult.PacketLoss < 1.0 {
				newReachable = true
			}
		}

		if newReachable {
			li.LastReachable = now
			c.State.LatencyMatrix[srcID][dstID] = li
		} else if old := c.State.LatencyMatrix[srcID][dstID]; old != nil {
			// New result is fully unreachable — only overwrite if old data
			// has been unreachable for longer than client_offline_timeout
			if now.Sub(old.LastReachable) > c.Config.ClientOfflineTimeout {
				li.LastReachable = old.LastReachable
				c.State.LatencyMatrix[srcID][dstID] = li
			}
			// Otherwise keep old reachable data (transient failure)
		} else {
			// No old data — store the unreachable result
			c.State.LatencyMatrix[srcID][dstID] = li
		}
	}

	// Reset topology update debounce
	c.resetTopoDebounce()

	c.mu.Unlock()
}

func (c *Controller) resetNewClientDebounce() {
	now := time.Now()

	if c.newClientTimer != nil {
		c.newClientTimer.Stop()
	}
	if c.newClientMaxTimer == nil {
		c.newClientFirst = now
		c.newClientMaxTimer = time.AfterFunc(c.Config.SyncNewClientDebounceMax, func() {
			c.triggerSyncNewClient()
		})
	}
	c.newClientTimer = time.AfterFunc(c.Config.SyncNewClientDebounce, func() {
		c.triggerSyncNewClient()
	})
}

func (c *Controller) triggerSyncNewClient() {
	c.mu.Lock()
	if c.newClientMaxTimer != nil {
		c.newClientMaxTimer.Stop()
		c.newClientMaxTimer = nil
	}
	if c.newClientTimer != nil {
		c.newClientTimer.Stop()
		c.newClientTimer = nil
	}

	c.probeCounter++
	probeID := c.probeCounter

	req := &pb.ControllerProbeRequest{
		ProbeId:           probeID,
		ProbeTimeoutMs:    uint32(c.Config.Probing.ProbeTimeoutMs),
		ProbeTimes:        uint32(c.Config.Probing.ProbeTimes),
		InProbeIntervalMs: uint32(c.Config.Probing.InProbeIntervalMs),
	}

	data, err := proto.Marshal(req)
	if err != nil {
		c.mu.Unlock()
		vlog.Errorf("[Controller] failed to marshal ControllerProbeRequest: %v", err)
		return
	}

	msg := encodeMessage(protocol.MsgControllerProbeRequest, data)
	for _, cc := range c.clients {
		if !cc.Synced {
			continue
		}
		select {
		case cc.SendQueue <- QueueItem{Message: msg}:
		default:
		}
	}
	c.mu.Unlock()

	vlog.Debugf("[Controller] sent ControllerProbeRequest (probe_id=%d) to all clients", probeID)
}

func (c *Controller) resetTopoDebounce() {
	now := time.Now()

	if c.topoTimer != nil {
		c.topoTimer.Stop()
	}
	if c.topoMaxTimer == nil {
		c.topoFirst = now
		c.topoMaxTimer = time.AfterFunc(c.Config.TopologyUpdateDebounceMax, func() {
			c.triggerTopologyUpdate()
		})
	}
	c.topoTimer = time.AfterFunc(c.Config.TopologyUpdateDebounce, func() {
		c.triggerTopologyUpdate()
	})
}

func (c *Controller) triggerTopologyUpdate() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.topoMaxTimer != nil {
		c.topoMaxTimer.Stop()
		c.topoMaxTimer = nil
	}
	if c.topoTimer != nil {
		c.topoTimer.Stop()
		c.topoTimer = nil
	}

	// Precompute best paths, then run Floyd-Warshall
	c.State.BestPaths = c.computeCurrentBestPaths()
	newRM := computeRouteMatrix(c.State.BestPaths, c.State.Clients)
	c.State.RouteMatrix = newRM

	vlog.Debugf("[Controller] topology update: RouteMatrix recomputed (%d clients, %d latency sources)", len(c.State.Clients), len(c.State.LatencyMatrix))

	// Log best paths and RouteMatrix for debugging
	for src, dsts := range c.State.BestPaths {
		for dst, bp := range dsts {
			vlog.Verbosef("[Controller] BestPath: %s -> %s: cost=%.2f af=%s", src.Hex()[:8], dst.Hex()[:8], bp.Cost, bp.AF)
		}
	}
	for src, dsts := range newRM {
		for dst, re := range dsts {
			vlog.Verbosef("[Controller] RouteMatrix: %s -> %s: nextHop=%s af=%s", src.Hex()[:8], dst.Hex()[:8], re.NextHop.Hex()[:8], re.AF)
		}
	}

	// Push full RouteMatrix update
	c.pushDelta(&pb.ControllerStateUpdate{
		Update: &pb.ControllerStateUpdate_RouteMatrixUpdate{
			RouteMatrixUpdate: &pb.RouteMatrixUpdateProto{
				RouteMatrix: routeMatrixToProto(newRM),
			},
		},
	})
}

func (c *Controller) periodicProbeLoop() {
	interval := time.Duration(c.Config.Probing.ProbeIntervalS) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.triggerSyncNewClient()
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Controller) clientSendLoop(cc *ClientConn) {
	for item := range cc.SendQueue {
		c.mu.Lock()

		// Pick activeAF if nil
		if cc.ActiveAF == "" {
			cc.ActiveAF = c.pickActiveAF(cc)
		}
		if cc.ActiveAF == "" {
			c.mu.Unlock()
			continue // no AF available, discard
		}

		afc := cc.AFConns[cc.ActiveAF]

		// If not synced, overwrite State with full state (filtered for this client)
		// and mark Synced immediately so subsequent pushDelta calls will queue
		// deltas behind this full state rather than skipping this client.
		if !cc.Synced {
			item.State = c.getFullStateEncodedForClient(cc)
			cc.Synced = true
		}

		c.mu.Unlock()

		// Send State
		if item.State != nil {
			msgType := protocol.MsgType(item.State[0])
			payload := item.State[1:]
			if err := protocol.WriteTCPMessage(afc.TCPConn, afc.Session, msgType, payload); err != nil {
				select {
				case <-afc.Done:
					continue
				default:
				}
				vlog.Errorf("[Controller] send error to %s: %v", cc.ClientID.Hex()[:8], err)
				continue
			}
		}

		// Send Message
		if item.Message != nil {
			msgType := protocol.MsgType(item.Message[0])
			payload := item.Message[1:]
			if err := protocol.WriteTCPMessage(afc.TCPConn, afc.Session, msgType, payload); err != nil {
				select {
				case <-afc.Done:
					continue
				default:
				}
				vlog.Errorf("[Controller] send error to %s: %v", cc.ClientID.Hex()[:8], err)
			}
		}
	}
}

// pickActiveAF selects the AF with the earliest connection time.
// Must be called with c.mu held.
func (c *Controller) pickActiveAF(cc *ClientConn) types.AFName {
	var earliest types.AFName
	var earliestTime time.Time
	first := true
	for af, afc := range cc.AFConns {
		if first || afc.ConnectedAt.Before(earliestTime) {
			earliest = af
			earliestTime = afc.ConnectedAt
			first = false
		}
	}
	return earliest
}

func (c *Controller) offlineChecker() {
	ticker := time.NewTicker(offlineCheckEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.checkOfflineClients()
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Controller) checkOfflineClients() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var removed []types.ClientID

	for id, ci := range c.State.Clients {
		if now.Sub(ci.LastSeen) > c.Config.ClientOfflineTimeout {
			// Don't remove if client has active TCP connections
			if cc, ok := c.clients[id]; ok && len(cc.AFConns) > 0 {
				ci.LastSeen = now // refresh
				continue
			}
			vlog.Debugf("[Controller] client %s offline (last seen %v ago)", id.Hex()[:8], now.Sub(ci.LastSeen))
			removed = append(removed, id)
		}
	}

	for _, id := range removed {
		delete(c.State.Clients, id)
		delete(c.State.LatencyMatrix, id)
		// Remove from other clients' latency matrix
		for _, dsts := range c.State.LatencyMatrix {
			delete(dsts, id)
		}
		// Close connection
		if cc, ok := c.clients[id]; ok {
			close(cc.SendQueue)
			for _, afc := range cc.AFConns {
				afc.CloseDone()
				afc.TCPConn.Close()
			}
			cc.Filters.Close()
			delete(c.clients, id)
		}

		c.pushDelta(&pb.ControllerStateUpdate{
			Update: &pb.ControllerStateUpdate_ClientLeft{
				ClientLeft: &pb.ClientLeft{
					ClientId: id[:],
				},
			},
		})
	}

	if len(removed) > 0 {
		c.State.LastClientChange = now
		c.updateRouteTable()

		// Recompute routes
		c.State.BestPaths = c.computeCurrentBestPaths()
		newRM := computeRouteMatrix(c.State.BestPaths, c.State.Clients)
		c.State.RouteMatrix = newRM

		c.pushDelta(&pb.ControllerStateUpdate{
			Update: &pb.ControllerStateUpdate_RouteMatrixUpdate{
				RouteMatrixUpdate: &pb.RouteMatrixUpdateProto{
					RouteMatrix: routeMatrixToProto(newRM),
				},
			},
		})
		c.pushDelta(&pb.ControllerStateUpdate{
			Update: &pb.ControllerStateUpdate_RouteTableUpdate{
				RouteTableUpdate: &pb.RouteTableUpdateProto{
					Entries: routeTableToProto(c.State.RouteTable),
				},
			},
		})
	}
}

func (c *Controller) handleDisconnect(cc *ClientConn, af types.AFName, afc *AFConn) {
	defer close(afc.Cleaned) // always signal completion

	c.mu.Lock()
	defer c.mu.Unlock()

	// Only cleanup if it's still our connection (not already replaced)
	if current, ok := cc.AFConns[af]; !ok || current != afc {
		return
	}
	delete(cc.AFConns, af)

	if af == cc.ActiveAF {
		cc.ActiveAF = ""
		cc.Synced = false
		// No drain — sendloop will overwrite State with full on next dequeue.
		// Message items in queue survive (probe requests etc).
	}
	// Non-activeAF disconnect: just cleared the handle, nothing else.
}

// trySyncClient enqueues a trigger item so sendloop wakes up and sends full state.
// Must be called with c.mu held.
func (c *Controller) trySyncClient(cc *ClientConn) {
	if len(cc.AFConns) > 0 && !cc.Synced {
		select {
		case cc.SendQueue <- QueueItem{}:
		default:
		}
	}
}

func (c *Controller) updateRouteTable() {
	// Rebuild route table from all clients' routes
	type rtKey struct {
		mac string
		ip  netip.Addr
	}

	entries := make(map[rtKey]*types.RouteTableEntry)

	for clientID, ci := range c.State.Clients {
		for _, route := range ci.Routes {
			// Normalize IP: treat invalid Addr (Addr{}) and 0.0.0.0 as the same
			// to avoid duplicate entries from different zero representations.
			ip := route.IP
			if ip.IsValid() && ip.IsUnspecified() {
				ip = netip.Addr{}
			}
			key := rtKey{mac: route.MAC.String(), ip: ip}
			entry, ok := entries[key]
			if !ok {
				entry = &types.RouteTableEntry{
					MAC:    route.MAC,
					IP:     ip,
					Owners: make(map[types.ClientID]time.Time),
				}
				entries[key] = entry
			}
			entry.Owners[clientID] = ci.LastSeen
		}
	}

	c.State.RouteTable = nil
	for _, entry := range entries {
		c.State.RouteTable = append(c.State.RouteTable, entry)
	}
}

func (c *Controller) udpReadLoop(al *AFListener) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := al.UDPConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				vlog.Errorf("[Controller] UDP read error on %s: %v", al.AF, err)
				continue
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		// Check if it's a handshake message
		if n > 0 && data[0] == byte(protocol.MsgHandshakeInit) {
			go c.handleUDPHandshake(al, data, remoteAddr)
			continue
		}

		msgType, payload, peerID, err := protocol.ReadUDPPacket(data, al.UDPSessions.FindByIndex)
		if err != nil {
			vlog.Warnf("[Controller] UDP ReadUDPPacket error on %s from %s: %v (len=%d, first_byte=0x%02x)", al.AF, remoteAddr, err, n, data[0])
			continue
		}

		if msgType == protocol.MsgMulticastForward {
			vlog.Debugf("[Controller] received MsgMulticastForward on %s from %s (%d bytes payload)", al.AF, remoteAddr, len(payload))
			c.handleMulticastForward(al, peerID, payload, remoteAddr)
		} else {
			vlog.Verbosef("[Controller] UDP msg type=0x%02x on %s from %s", byte(msgType), al.AF, remoteAddr)
		}
	}
}

func (c *Controller) handleUDPHandshake(al *AFListener, data []byte, remoteAddr net.Addr) {
	localIndex := al.UDPSessions.AllocateIndex()
	respMsg, session, err := crypto.HandshakeRespond(c.PrivateKey, data, c.allowedKeys, localIndex)
	if err != nil {
		return
	}
	session.IsUDP = true
	al.UDPSessions.AddSession(session)

	// Store client's UDP address for sending MulticastDeliver
	if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		key := udpAddrKey{ClientID: types.ClientID(session.PeerID), AF: al.AF}
		c.mu.Lock()
		c.udpAddrs[key] = udpAddr
		c.mu.Unlock()
		vlog.Debugf("[Controller] UDP handshake from client %s at %s (AF=%s)", types.ClientID(session.PeerID).Hex()[:8], udpAddr, al.AF)
	}

	al.UDPConn.WriteTo(respMsg, remoteAddr)
}

func (c *Controller) handleMulticastForward(al *AFListener, sourceClientID [32]byte, payload []byte, fromAddr net.Addr) {
	var fwd pb.MulticastForward
	if err := proto.Unmarshal(payload, &fwd); err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	srcID := types.ClientID(sourceClientID)

	// Input filter: check source client's filter
	if srcCC, ok := c.clients[srcID]; ok && srcCC.Filters != nil {
		if accepted, _, _ := srcCC.Filters.InputMcast.FilterMcast(fwd.Payload); !accepted {
			return
		}
	}

	deliver := &pb.MulticastDeliver{
		SourceClientId: fwd.SourceClientId,
		Payload:        fwd.Payload,
	}
	deliverData, err := proto.Marshal(deliver)
	if err != nil {
		return
	}

	deliveredTo := 0

	// Send on ALL AF listeners, not just the one that received the forward
	for _, listener := range c.afListeners {
		for clientID, cc := range c.clients {
			if clientID == srcID {
				continue // skip source
			}
			if !cc.Synced {
				continue
			}

			// Output filter: check destination client's filter
			if cc.Filters != nil {
				if accepted, _, _ := cc.Filters.OutputMcast.FilterMcast(fwd.Payload); !accepted {
					continue
				}
			}

			session := listener.UDPSessions.FindByPeer(clientID)
			if session == nil {
				continue
			}

			key := udpAddrKey{ClientID: clientID, AF: listener.AF}
			addr, ok := c.udpAddrs[key]
			if !ok {
				continue
			}

			if err := protocol.WriteUDPPacket(listener.UDPConn, addr, session, protocol.MsgMulticastDeliver, deliverData); err != nil {
				vlog.Errorf("[Controller] multicast deliver to %s via %s error: %v", clientID.Hex()[:8], listener.AF, err)
			} else {
				deliveredTo++
			}
		}
	}
	vlog.Debugf("[Controller] multicast from %s: delivered to %d clients", srcID.Hex()[:8], deliveredTo)
}

// addRoute adds a route, replacing any existing route with the same MAC.
func addRoute(routes []types.Type2Route, rt types.Type2Route) []types.Type2Route {
	for i, r := range routes {
		if macEqual(r.MAC, rt.MAC) && r.IP == rt.IP {
			routes[i] = rt
			return routes
		}
	}
	return append(routes, rt)
}

// removeRoute removes a route matching MAC and IP.
func removeRoute(routes []types.Type2Route, rt types.Type2Route) []types.Type2Route {
	for i, r := range routes {
		if macEqual(r.MAC, rt.MAC) && r.IP == rt.IP {
			return append(routes[:i], routes[i+1:]...)
		}
	}
	return routes // not found, idempotent
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// endpointOverrides returns per-AF endpoint overrides for a given client.
func (c *Controller) endpointOverrides(clientID types.ClientID) map[types.AFName]string {
	for _, pc := range c.Config.AllowedClients {
		if pc.ClientID == clientID {
			if len(pc.AFSettings) == 0 {
				return nil
			}
			m := make(map[types.AFName]string, len(pc.AFSettings))
			for af, afCfg := range pc.AFSettings {
				if afCfg.EndpointOverride != "" {
					m[af] = afCfg.EndpointOverride
				}
			}
			return m
		}
	}
	return nil
}

func addrFromConn(conn net.Conn) netip.Addr {
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		addr, _ := netip.AddrFromSlice(tcpAddr.IP)
		return addr
	}
	return netip.Addr{}
}

// computeCurrentBestPaths selects between probe and static cost computation.
// Must be called with c.mu held.
func (c *Controller) computeCurrentBestPaths() map[types.ClientID]map[types.ClientID]*types.BestPathEntry {
	if c.CostMode == "static" && c.staticCostsByID != nil {
		return types.ComputeBestPathsStatic(c.State.LatencyMatrix, c.staticCostsByID)
	}
	return types.ComputeBestPaths(c.State.LatencyMatrix)
}

// resolveStaticCosts converts name-indexed static costs to ClientID-indexed.
func (c *Controller) resolveStaticCosts(nameCosts map[string]map[string]map[types.AFName]float64) map[types.ClientID]map[types.ClientID]map[types.AFName]float64 {
	nameToID := make(map[string]types.ClientID)
	for _, pc := range c.Config.AllowedClients {
		nameToID[pc.ClientName] = pc.ClientID
	}

	result := make(map[types.ClientID]map[types.ClientID]map[types.AFName]float64)
	for srcName, dsts := range nameCosts {
		srcID, ok := nameToID[srcName]
		if !ok {
			continue
		}
		result[srcID] = make(map[types.ClientID]map[types.AFName]float64)
		for dstName, afs := range dsts {
			dstID, ok := nameToID[dstName]
			if !ok {
				continue
			}
			result[srcID][dstID] = make(map[types.AFName]float64)
			for af, cost := range afs {
				result[srcID][dstID][af] = cost
			}
		}
	}
	return result
}

// clientNameByID returns the human-readable name for a ClientID.
func (c *Controller) clientNameByID(id types.ClientID) string {
	for _, pc := range c.Config.AllowedClients {
		if pc.ClientID == id {
			return pc.ClientName
		}
	}
	return id.Hex()[:8]
}
