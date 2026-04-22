package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"
	"vxlan-controller/pkg/vlog"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/apisock"
	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/controller"
	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/filter"
	"vxlan-controller/pkg/ntp"
	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"

	pb "vxlan-controller/proto"
)

// AFChannel identifies one (AF, Channel) tuple.
type AFChannel struct {
	AF      types.AFName
	Channel types.ChannelName
}

// Client implements the VXLAN client.
type Client struct {
	Config     *config.ClientConfig
	PrivateKey [32]byte
	ClientID   types.ClientID

	mu            sync.Mutex
	Controllers   map[types.ControllerID]*ControllerConn
	AuthorityCtrl *types.ControllerID

	// Network devices (per AF, per channel)
	VxlanDevs map[types.AFName]map[types.ChannelName]*VxlanDev
	TapFD     *os.File

	// Local MAC state — protected by macMu (RWMutex), independent of c.mu.
	macMu     sync.RWMutex
	LocalMACs []types.Type2Route
	bridgeMAC net.HardwareAddr

	// FDB state
	CurrentFDB map[fdbKey]fdbEntry

	// Filters
	Filters *filter.FilterSet

	// Multicast stats
	mcastStats *McastStats

	// NTP
	ntp *ntp.TimeSync

	// Addr watch (per af, channel)
	addrEngines map[types.AFName]map[types.ChannelName]*filter.AddrSelectEngine

	// Probe (per af, channel)
	probeConns          map[types.AFName]map[types.ChannelName]*net.UDPConn
	probeSessions       *crypto.SessionManager
	pendingHandshakes   map[types.ClientID]*crypto.HandshakeState
	pendingHandshakesMu sync.Mutex
	probeResultsMu      sync.Mutex
	probeResponseChs    map[uint64]chan probeResponseData
	lastProbeTime        time.Time
	lastProbeResults     map[types.ClientID]*LocalProbeResult
	lastDebouncedResults map[types.ClientID]*LocalProbeResult
	probeHistory         map[probeHistoryKey][]*LocalAFProbeResult
	// preferred (af, channel) per peer
	preferredAFChannel map[types.ClientID]AFChannel

	// Channels
	fdbNotifyCh       chan struct{}
	fwNotifyCh        chan struct{}
	authorityChangeCh chan struct{}
	tapInjectCh       chan []byte
	initDone          chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
}

// ClientQueueItem is the sendqueue element for client→controller messages.
type ClientQueueItem struct {
	MACDelta []*pb.Type2Route
	Message  []byte
	Trigger  bool
}

// ControllerConn represents Client's connection to a single Controller.
type ControllerConn struct {
	ControllerID  types.ControllerID
	AFConns       map[types.AFName]map[types.ChannelName]*ClientAFConn
	ActiveAF      types.AFName
	ActiveChannel types.ChannelName
	State         *ControllerView
	Synced        bool
	MACsSynced    bool
	SendQueue     chan ClientQueueItem

	syncMu          sync.Mutex
	localSessionID  string
	localSeqid      uint64
	remoteSessionID string
	remoteSeqid     uint64
}

// ClientAFConn represents a single (AF, channel) connection to a controller.
type ClientAFConn struct {
	AF          types.AFName
	Channel     types.ChannelName
	TCPConn     net.Conn
	Session     *crypto.Session
	CommUDPConn net.PacketConn
	UDPSession  *crypto.Session
	Cancel      context.CancelFunc
	Connected   bool
	Done        chan struct{}
	Cleaned     chan struct{}
	doneOnce    sync.Once
}

// CloseDone safely closes the Done channel (idempotent).
func (afc *ClientAFConn) CloseDone() {
	afc.doneOnce.Do(func() { close(afc.Done) })
}

// ControllerView is the Client's view of a Controller's state.
type ControllerView struct {
	ClientCount      int
	LastClientChange time.Time
	Clients          map[types.ClientID]*ClientInfoView
	RouteMatrix      map[types.ClientID]map[types.ClientID]*types.RouteEntry
	RouteTable       []*types.RouteTableEntry
}

// LocalProbeResult stores the last probe result for a peer (client-side).
type LocalProbeResult struct {
	AFResults map[types.AFName]map[types.ChannelName]*LocalAFProbeResult
}

// LocalAFProbeResult stores per-(af, channel) probe result.
type LocalAFProbeResult struct {
	LatencyMean float64
	LatencyStd  float64
	PacketLoss  float64
}

type probeHistoryKey struct {
	ClientID types.ClientID
	AF       types.AFName
	Channel  types.ChannelName
}

// ClientInfoView is the Client's view of a ClientInfo from the Controller.
type ClientInfoView struct {
	ClientID   types.ClientID
	ClientName string
	Endpoints  map[types.AFName]map[types.ChannelName]*types.Endpoint
	LastSeen   time.Time
	Routes     []types.Type2Route
}

const clientSendQueueSize = 256

func New(cfg *config.ClientConfig) *Client {
	pubKey := crypto.PublicKey(cfg.PrivateKey)
	ctx, cancel := context.WithCancel(context.Background())

	filters, err := filter.NewFilterSet(cfg.Filters)
	if err != nil {
		vlog.Fatalf("[Client] failed to initialize filters: %v", err)
	}

	c := &Client{
		Config:             cfg,
		PrivateKey:         cfg.PrivateKey,
		ClientID:           pubKey,
		Controllers:        make(map[types.ControllerID]*ControllerConn),
		VxlanDevs:          make(map[types.AFName]map[types.ChannelName]*VxlanDev),
		CurrentFDB:         make(map[fdbKey]fdbEntry),
		Filters:            filters,
		mcastStats:         newMcastStats(),
		ntp:                ntp.New(cfg.NTPServers, cfg.NTPRTTThreshold),
		addrEngines:        make(map[types.AFName]map[types.ChannelName]*filter.AddrSelectEngine),
		probeConns:         make(map[types.AFName]map[types.ChannelName]*net.UDPConn),
		probeSessions:      crypto.NewSessionManager(),
		pendingHandshakes:  make(map[types.ClientID]*crypto.HandshakeState),
		probeResponseChs:   make(map[uint64]chan probeResponseData),
		probeHistory:       make(map[probeHistoryKey][]*LocalAFProbeResult),
		preferredAFChannel: make(map[types.ClientID]AFChannel),
		fdbNotifyCh:        make(chan struct{}, 1),
		fwNotifyCh:         make(chan struct{}, 1),
		authorityChangeCh:  make(chan struct{}, 1),
		tapInjectCh:        make(chan []byte, 256),
		initDone:           make(chan struct{}),
		ctx:                ctx,
		cancel:             cancel,
	}

	// Initialize addr select engines for (af, channel) with autoip_interface
	for afName, chans := range cfg.AFSettings {
		for chName, cc := range chans {
			if cc.AutoIPInterface == "" {
				continue
			}
			engine, err := filter.NewAddrSelectEngine(cc.AddrSelectScript)
			if err != nil {
				vlog.Fatalf("[Client] AF=%s channel=%s: failed to initialize addr_select: %v", afName, chName, err)
			}
			if _, ok := c.addrEngines[afName]; !ok {
				c.addrEngines[afName] = make(map[types.ChannelName]*filter.AddrSelectEngine)
			}
			c.addrEngines[afName][chName] = engine
		}
	}

	return c
}

func (c *Client) Run() error {
	vlog.Infof("[Client] starting, ID=%s", c.ClientID.Hex()[:8])

	// Step 1: NTP sync
	go c.ntp.RunLoop(c.Config.NTPPeriod, c.ctx.Done())

	time.Sleep(500 * time.Millisecond)

	// Step 2a: Resolve initial bind addrs for autoip_interface (af, channel)
	for afName, chans := range c.Config.AFSettings {
		for chName, cc := range chans {
			if cc.AutoIPInterface != "" {
				c.resolveInitialBindAddr(afName, chName)
			}
		}
	}

	// Step 2b: Initialize devices
	if err := c.initDevices(); err != nil {
		return fmt.Errorf("init devices: %w", err)
	}

	// Step 2c: Initialize VXLAN firewall (non-fatal)
	if err := c.initFirewall(); err != nil {
		vlog.Warnf("[Client] VXLAN firewall init failed (nftables may not be fully available): %v", err)
		c.Config.VxlanFirewall = false
	}

	// Step 3: Collect unique controllers across all (af, channel)
	controllerMap := make(map[types.ControllerID]bool)
	for _, chans := range c.Config.AFSettings {
		for _, cc := range chans {
			if !cc.Enable {
				continue
			}
			for _, ctrl := range cc.Controllers {
				controllerMap[types.ControllerID(ctrl.PubKey)] = true
			}
		}
	}

	for ctrlID := range controllerMap {
		c.Controllers[ctrlID] = &ControllerConn{
			ControllerID: ctrlID,
			AFConns:      make(map[types.AFName]map[types.ChannelName]*ClientAFConn),
			SendQueue:    make(chan ClientQueueItem, clientSendQueueSize),
			State: &ControllerView{
				Clients:     make(map[types.ClientID]*ClientInfoView),
				RouteMatrix: make(map[types.ClientID]map[types.ClientID]*types.RouteEntry),
			},
		}
	}

	// Step 4: Initialize local state
	neighCh, linkCh, neighDone := c.neighborInit()

	// Start sendloops for all controllers
	for _, cc := range c.Controllers {
		go c.controllerSendLoop(cc)
	}

	// Step 5: Start TCP connections to all controllers per (af, channel)
	for afName, chans := range c.Config.AFSettings {
		for chName, cc := range chans {
			if !cc.Enable {
				continue
			}
			for _, ctrl := range cc.Controllers {
				ctrlID := types.ControllerID(ctrl.PubKey)
				go c.tcpConnLoop(ctrlID, afName, chName, ctrl)
			}
		}
	}

	// Step 5b: Start probe listeners per (af, channel)
	for afName, chans := range c.Config.AFSettings {
		for chName, cc := range chans {
			if !cc.Enable {
				continue
			}
			go c.probeListenLoop(afName, chName)
			_ = cc
		}
	}

	// Step 5c: Start addr watch for autoip_interface (af, channel)
	go c.addrWatchLoop()

	// Step 6: Start neighbor event loop
	go c.neighborEventLoop(neighCh, linkCh, neighDone)

	// Step 7: Start tap loops
	go c.tapReadLoop()
	go c.tapWriteLoop()

	// Step 8: Start FDB reconciler
	go c.fdbReconcileLoop()

	// Step 8b: Start firewall peer sync loop
	go c.firewallLoop()

	// Step 8c: Start mcast stats reporter
	go c.mcastStatsReportLoop()

	// Step 8d: Start sync check daemon
	go c.syncCheckLoop()

	// Step 9: Authority selection with init_timeout
	go func() {
		timer := time.NewTimer(c.Config.InitTimeout)
		select {
		case <-timer.C:
			close(c.initDone)
		case <-c.ctx.Done():
			timer.Stop()
		}
	}()
	go c.authoritySelectLoop()

	// Step 10: API server
	go c.apiServer()

	<-c.ctx.Done()
	return nil
}

func (c *Client) Stop() {
	c.cancel()

	if c.TapFD != nil {
		c.TapFD.Close()
	}

	c.cleanupFDB()
	c.flushManagedFDB()

	if c.Config.ClampMSSToMTU {
		c.cleanupNftables()
	}
	c.cleanupFirewall()

	c.mu.Lock()
	for _, cc := range c.Controllers {
		close(cc.SendQueue)
		for _, chans := range cc.AFConns {
			for _, afc := range chans {
				afc.CloseDone()
				if afc.TCPConn != nil {
					afc.TCPConn.Close()
				}
				if afc.CommUDPConn != nil {
					afc.CommUDPConn.Close()
				}
				if afc.Cancel != nil {
					afc.Cancel()
				}
			}
		}
	}
	c.mu.Unlock()

	c.Filters.Close()

	for _, chans := range c.addrEngines {
		for _, engine := range chans {
			engine.Close()
		}
	}
}

func (c *Client) tcpConnLoop(ctrlID types.ControllerID, af types.AFName, ch types.ChannelName, ctrl config.ControllerEndpoint) {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		start := time.Now()
		err := c.connectToController(ctrlID, af, ch, ctrl)
		elapsed := time.Since(start)

		if err != nil {
			vlog.Warnf("[Client] connection to controller %s AF=%s channel=%s failed: %v", ctrlID.Hex()[:8], af, ch, err)
		}

		if elapsed > 10*time.Second {
			backoff = time.Second
		}

		select {
		case <-time.After(backoff):
		case <-c.ctx.Done():
			return
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) connectToController(ctrlID types.ControllerID, af types.AFName, ch types.ChannelName, ctrl config.ControllerEndpoint) error {
	chans, ok := c.Config.AFSettings[af]
	if !ok {
		return fmt.Errorf("no AF config for %s", af)
	}
	cfgc, ok := chans[ch]
	if !ok {
		return fmt.Errorf("no channel config for %s/%s", af, ch)
	}

	if !cfgc.BindAddr.IsValid() {
		return fmt.Errorf("no bind_addr resolved yet (autoip_interface pending)")
	}

	localAddr := &net.TCPAddr{
		IP: cfgc.BindAddr.AsSlice(),
	}

	dialer := net.Dialer{
		LocalAddr: localAddr,
		Timeout:   10 * time.Second,
	}

	conn, err := dialer.DialContext(c.ctx, "tcp", ctrl.Addr.String())
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	vlog.Infof("[Client] connected to controller %s on AF=%s channel=%s", ctrlID.Hex()[:8], af, ch)

	// Noise IK handshake
	localIndex := c.probeSessions.AllocateIndex()
	initMsg, state, err := crypto.HandshakeInitiate(c.PrivateKey, ctrl.PubKey, localIndex)
	if err != nil {
		conn.Close()
		return fmt.Errorf("handshake init: %w", err)
	}

	if err := protocol.WriteTCPRaw(conn, initMsg); err != nil {
		conn.Close()
		return fmt.Errorf("write handshake: %w", err)
	}

	respMsg, err := protocol.ReadTCPRaw(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("read handshake resp: %w", err)
	}

	session, err := crypto.HandshakeFinalize(state, respMsg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("handshake finalize: %w", err)
	}

	session.IsUDP = false
	vlog.Infof("[Client] handshake completed with controller %s on AF=%s channel=%s", ctrlID.Hex()[:8], af, ch)

	// Send ClientRegister with this conn's (af, channel) and all advertised endpoints
	reg := &pb.ClientRegister{
		ClientId:    c.ClientID[:],
		AfName:      string(af),
		ChannelName: string(ch),
	}

	for afn, chs := range c.Config.AFSettings {
		for chn, cc := range chs {
			if !cc.Enable {
				continue
			}
			reg.Endpoints = append(reg.Endpoints, &pb.AFEndpoint{
				AfName:       string(afn),
				ChannelName:  string(chn),
				ProbePort:    uint32(cc.ProbePort),
				VxlanDstPort: uint32(cc.VxlanDstPort),
			})
		}
	}

	regData, err := proto.Marshal(reg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("marshal register: %w", err)
	}

	if err := protocol.WriteTCPMessage(conn, session, protocol.MsgClientRegister, regData); err != nil {
		conn.Close()
		return fmt.Errorf("send register: %w", err)
	}

	// Setup AF connection
	afCtx, afCancel := context.WithCancel(c.ctx)

	commUDPAddr, err := net.ResolveUDPAddr("udp", netip.AddrPortFrom(cfgc.BindAddr, 0).String())
	if err != nil {
		conn.Close()
		afCancel()
		return fmt.Errorf("resolve udp: %w", err)
	}
	commUDPConn, err := net.ListenUDP("udp", commUDPAddr)
	if err != nil {
		conn.Close()
		afCancel()
		return fmt.Errorf("listen udp: %w", err)
	}

	udpSession := c.setupUDPSession(ctrl, commUDPConn)

	afc := &ClientAFConn{
		AF:          af,
		Channel:     ch,
		TCPConn:     conn,
		Session:     session,
		CommUDPConn: commUDPConn,
		UDPSession:  udpSession,
		Cancel:      afCancel,
		Connected:   true,
		Done:        make(chan struct{}),
		Cleaned:     make(chan struct{}),
	}

	c.mu.Lock()
	cc := c.Controllers[ctrlID]

	// Replace previous (af, channel) connection if exists
	var oldAfc *ClientAFConn
	if chMap, ok := cc.AFConns[af]; ok {
		if old, ok2 := chMap[ch]; ok2 {
			oldAfc = old
			old.CloseDone()
		}
	}
	if oldAfc != nil {
		c.mu.Unlock()
		oldAfc.TCPConn.Close()
		if oldAfc.CommUDPConn != nil {
			oldAfc.CommUDPConn.Close()
		}
		oldAfc.Cancel()
		<-oldAfc.Cleaned
		c.mu.Lock()
	}

	if _, ok := cc.AFConns[af]; !ok {
		cc.AFConns[af] = make(map[types.ChannelName]*ClientAFConn)
	}
	cc.AFConns[af][ch] = afc
	c.mu.Unlock()

	// Start UDP read loop for multicast delivery
	go c.commUDPReadLoop(ctrlID, af, ch, commUDPConn, udpSession, afCtx)

	// Enter recv loop
	c.tcpRecvLoop(ctrlID, af, ch, afc)

	// Cleanup on disconnect
	afCancel()
	conn.Close()
	commUDPConn.Close()
	c.handleClientDisconnect(cc, af, ch, afc)

	return fmt.Errorf("connection closed")
}

func (c *Client) setupUDPSession(ctrl config.ControllerEndpoint, conn *net.UDPConn) *crypto.Session {
	localIndex := crypto.NewSessionManager().AllocateIndex()
	initMsg, state, err := crypto.HandshakeInitiate(c.PrivateKey, ctrl.PubKey, localIndex)
	if err != nil {
		vlog.Errorf("[Client] UDP handshake initiate error: %v", err)
		return nil
	}

	ctrlAddr, err := net.ResolveUDPAddr("udp", ctrl.Addr.String())
	if err != nil {
		vlog.Errorf("[Client] UDP resolve error: %v", err)
		return nil
	}

	conn.WriteToUDP(initMsg, ctrlAddr)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := conn.ReadFromUDP(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		vlog.Warnf("[Client] UDP handshake response timeout: %v", err)
		return nil
	}

	session, err := crypto.HandshakeFinalize(state, buf[:n])
	if err != nil {
		vlog.Errorf("[Client] UDP handshake finalize error: %v", err)
		return nil
	}
	session.IsUDP = true
	vlog.Debugf("[Client] UDP session established with controller at %s", ctrlAddr)
	return session
}

func (c *Client) commUDPReadLoop(ctrlID types.ControllerID, af types.AFName, ch types.ChannelName, conn net.PacketConn, session *crypto.Session, ctx context.Context) {
	if session == nil {
		return
	}

	sm := crypto.NewSessionManager()
	sm.AddSession(session)

	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		msgType, payload, _, err := protocol.ReadUDPPacket(data, sm.FindByIndex)
		if err != nil {
			vlog.Verbosef("[Client] commUDP ReadUDPPacket error: %v (len=%d)", err, n)
			continue
		}

		if msgType == protocol.MsgMulticastDeliver {
			var deliver pb.MulticastDeliver
			if err := proto.Unmarshal(payload, &deliver); err != nil {
				vlog.Errorf("[Client] multicast deliver unmarshal error: %v", err)
				continue
			}

			vlog.Debugf("[Client] received MulticastDeliver: %d byte frame", len(deliver.Payload))

			accepted, reason, detail := c.Filters.InputMcast.FilterMcast(deliver.Payload)
			c.mcastStats.RecordRx(deliver.Payload, accepted, reason, detail)
			if !accepted {
				continue
			}

			select {
			case c.tapInjectCh <- deliver.Payload:
			default:
				vlog.Warnf("[Client] tapInjectCh full, dropping frame")
			}
		}
	}
}

func (c *Client) tcpRecvLoop(ctrlID types.ControllerID, af types.AFName, ch types.ChannelName, afc *ClientAFConn) {
	for {
		select {
		case <-afc.Done:
			return
		case <-c.ctx.Done():
			return
		default:
		}

		msgType, payload, err := protocol.ReadTCPMessage(afc.TCPConn, afc.Session)
		if err != nil {
			if err != io.EOF {
				vlog.Warnf("[Client] TCP recv error from controller %s: %v", ctrlID.Hex()[:8], err)
			}
			return
		}

		switch msgType {
		case protocol.MsgControllerState:
			c.handleControllerState(ctrlID, af, ch, payload)
		case protocol.MsgControllerStateUpdate:
			c.handleControllerStateUpdate(ctrlID, payload)
		case protocol.MsgControllerProbeRequest:
			c.handleControllerProbeRequest(ctrlID, payload)
		default:
			vlog.Warnf("[Client] unknown msg_type %d from controller", msgType)
		}
	}
}

func (c *Client) handleControllerState(ctrlID types.ControllerID, af types.AFName, ch types.ChannelName, payload []byte) {
	var state pb.ControllerState
	if err := proto.Unmarshal(payload, &state); err != nil {
		vlog.Errorf("[Client] unmarshal ControllerState error: %v", err)
		return
	}

	c.mu.Lock()

	cc, ok := c.Controllers[ctrlID]
	if !ok {
		c.mu.Unlock()
		return
	}

	routeTable := controller.ProtoToRouteTable(state.RouteTable)
	routeTable = c.filterRouteTable(routeTable)

	view := &ControllerView{
		ClientCount:      int(state.ClientCount),
		LastClientChange: time.Unix(0, state.LastClientChangeTimestamp),
		Clients:          make(map[types.ClientID]*ClientInfoView),
		RouteMatrix:      controller.ProtoToRouteMatrix(state.RouteMatrix),
		RouteTable:       routeTable,
	}

	for _, ci := range state.Clients {
		civ := protoToClientInfoView(ci)
		view.Clients[civ.ClientID] = civ
	}

	cc.State = view
	cc.Synced = true

	// Full update received on this (af, channel) → set as active
	cc.ActiveAF = af
	cc.ActiveChannel = ch

	vlog.Debugf("[Client] received full state from controller %s (AF=%s channel=%s, %d clients)", ctrlID.Hex()[:8], af, ch, view.ClientCount)

	select {
	case c.authorityChangeCh <- struct{}{}:
	default:
	}

	select {
	case cc.SendQueue <- ClientQueueItem{}:
	default:
	}

	c.mu.Unlock()

	c.notifyFDB()
	c.notifyFirewall()
}

func (c *Client) handleControllerStateUpdate(ctrlID types.ControllerID, payload []byte) {
	var update pb.ControllerStateUpdate
	if err := proto.Unmarshal(payload, &update); err != nil {
		vlog.Errorf("[Client] unmarshal ControllerStateUpdate error: %v", err)
		return
	}

	c.mu.Lock()

	cc, ok := c.Controllers[ctrlID]
	if !ok || cc.State == nil {
		c.mu.Unlock()
		return
	}

	clientsChanged := false

	switch u := update.Update.(type) {
	case *pb.ControllerStateUpdate_ClientJoined:
		civ := protoToClientInfoView(u.ClientJoined.ClientInfo)
		cc.State.Clients[civ.ClientID] = civ
		cc.State.ClientCount = len(cc.State.Clients)
		clientsChanged = true

	case *pb.ControllerStateUpdate_ClientLeft:
		var clientID types.ClientID
		copy(clientID[:], u.ClientLeft.ClientId)
		delete(cc.State.Clients, clientID)
		cc.State.ClientCount = len(cc.State.Clients)
		clientsChanged = true

	case *pb.ControllerStateUpdate_RouteMatrixUpdate:
		cc.State.RouteMatrix = controller.ProtoToRouteMatrix(u.RouteMatrixUpdate.RouteMatrix)

	case *pb.ControllerStateUpdate_RouteTableUpdate:
		rt := controller.ProtoToRouteTable(u.RouteTableUpdate.Entries)
		cc.State.RouteTable = c.filterRouteTable(rt)

	case *pb.ControllerStateUpdate_ClientInfoUpdate:
		civ := protoToClientInfoView(u.ClientInfoUpdate.ClientInfo)
		cc.State.Clients[civ.ClientID] = civ
		clientsChanged = true
	}

	if len(update.SourceClientId) == len(c.ClientID) &&
		update.SourceSessionId != "" {
		var srcID types.ClientID
		copy(srcID[:], update.SourceClientId)
		if srcID == c.ClientID {
			cc.syncMu.Lock()
			cc.remoteSessionID = update.SourceSessionId
			cc.remoteSeqid = update.SourceSeqid
			cc.syncMu.Unlock()
		}
	}

	c.mu.Unlock()

	c.notifyFDB()
	if clientsChanged {
		c.notifyFirewall()
	}
}

func (c *Client) handleControllerProbeRequest(ctrlID types.ControllerID, payload []byte) {
	var req pb.ControllerProbeRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		vlog.Errorf("[Client] unmarshal ControllerProbeRequest error: %v", err)
		return
	}

	c.mu.Lock()
	isAuthority := c.AuthorityCtrl != nil && *c.AuthorityCtrl == ctrlID
	c.mu.Unlock()

	select {
	case <-c.initDone:
	default:
		return
	}

	if !isAuthority {
		return
	}

	go c.executeProbe(&req)
}

func (c *Client) getVxlanDstPort(af types.AFName, ch types.ChannelName) uint16 {
	chans, ok := c.Config.AFSettings[af]
	if !ok {
		return 0
	}
	cc, ok := chans[ch]
	if !ok {
		return 0
	}
	return cc.VxlanDstPort
}

func protoToClientInfoView(p *pb.ClientInfoProto) *ClientInfoView {
	civ := &ClientInfoView{
		ClientName: p.ClientName,
		Endpoints:  make(map[types.AFName]map[types.ChannelName]*types.Endpoint),
		LastSeen:   time.Unix(0, p.LastSeen),
	}
	copy(civ.ClientID[:], p.ClientId)

	for _, ep := range p.Endpoints {
		e := &types.Endpoint{
			ProbePort:    uint16(ep.ProbePort),
			VxlanDstPort: uint16(ep.VxlanDstPort),
		}
		if len(ep.Ip) == 4 {
			e.IP = netip.AddrFrom4([4]byte(ep.Ip))
		} else if len(ep.Ip) == 16 {
			e.IP = netip.AddrFrom16([16]byte(ep.Ip))
		}
		af := types.AFName(ep.AfName)
		ch := types.ChannelName(ep.ChannelName)
		if _, ok := civ.Endpoints[af]; !ok {
			civ.Endpoints[af] = make(map[types.ChannelName]*types.Endpoint)
		}
		civ.Endpoints[af][ch] = e
	}

	for _, r := range p.Routes {
		rt := types.Type2Route{MAC: r.Mac}
		if len(r.Ip) == 4 {
			rt.IP = netip.AddrFrom4([4]byte(r.Ip))
		} else if len(r.Ip) == 16 {
			rt.IP = netip.AddrFrom16([16]byte(r.Ip))
		}
		civ.Routes = append(civ.Routes, rt)
	}

	return civ
}

// filterRouteTable filters a RouteTable through the input_route filter.
func (c *Client) filterRouteTable(rt []*types.RouteTableEntry) []*types.RouteTableEntry {
	var filtered []*types.RouteTableEntry
	for _, entry := range rt {
		mac := entry.MAC.String()
		ip := ""
		if entry.IP.IsValid() {
			ip = entry.IP.String()
		}
		if c.Filters.InputRoute.FilterRoute(mac, ip, false) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func (c *Client) controllerSendLoop(cc *ControllerConn) {
	for item := range cc.SendQueue {
		c.mu.Lock()
		if cc.ActiveAF == "" {
			c.mu.Unlock()
			continue
		}
		chans, ok := cc.AFConns[cc.ActiveAF]
		if !ok {
			c.mu.Unlock()
			continue
		}
		afc := chans[cc.ActiveChannel]
		if afc == nil {
			c.mu.Unlock()
			continue
		}
		synced := cc.MACsSynced
		c.mu.Unlock()

		if !synced {
			fullMsg := c.getFullMACsEncodedAndStamp(cc)

			c.mu.Lock()
			cc.MACsSynced = true
			c.mu.Unlock()

			if fullMsg != nil {
				msgType := protocol.MsgType(fullMsg[0])
				payload := fullMsg[1:]
				if err := protocol.WriteTCPMessage(afc.TCPConn, afc.Session, msgType, payload); err != nil {
					continue
				}
			}
			continue
		}

		if item.MACDelta != nil {
			cc.syncMu.Lock()
			cc.localSeqid++
			sessID := cc.localSessionID
			seqID := cc.localSeqid
			cc.syncMu.Unlock()

			update := &pb.MACUpdate{
				IsFull:    false,
				Routes:    item.MACDelta,
				SessionId: sessID,
				Seqid:     seqID,
			}
			data, err := proto.Marshal(update)
			if err != nil {
				vlog.Errorf("[Client] marshal incremental MACUpdate error: %v", err)
				continue
			}
			if err := protocol.WriteTCPMessage(afc.TCPConn, afc.Session, protocol.MsgMACUpdate, data); err != nil {
				continue
			}
		}

		if item.Message != nil {
			msgType := protocol.MsgType(item.Message[0])
			payload := item.Message[1:]
			protocol.WriteTCPMessage(afc.TCPConn, afc.Session, msgType, payload)
		}
	}
}

// handleClientDisconnect cleans up after an (af, channel) connection to a controller drops.
func (c *Client) handleClientDisconnect(cc *ControllerConn, af types.AFName, ch types.ChannelName, afc *ClientAFConn) {
	defer close(afc.Cleaned)

	c.mu.Lock()
	defer c.mu.Unlock()

	chans, ok := cc.AFConns[af]
	if !ok {
		return
	}
	current, ok2 := chans[ch]
	if !ok2 || current != afc {
		return
	}
	delete(chans, ch)
	if len(chans) == 0 {
		delete(cc.AFConns, af)
	}

	if af == cc.ActiveAF && ch == cc.ActiveChannel {
		cc.ActiveAF = ""
		cc.ActiveChannel = ""
		cc.MACsSynced = false
	}
}

func (c *Client) getFullMACsEncodedAndStamp(cc *ControllerConn) []byte {
	c.macMu.RLock()
	defer c.macMu.RUnlock()

	cc.syncMu.Lock()
	cc.localSessionID = newSessionID()
	cc.localSeqid = 0
	sessID := cc.localSessionID
	cc.syncMu.Unlock()

	update := &pb.MACUpdate{
		IsFull:    true,
		SessionId: sessID,
		Seqid:     0,
	}
	for _, r := range c.LocalMACs {
		rt := &pb.Type2Route{Mac: r.MAC}
		if r.IP.IsValid() {
			rt.Ip = addrToBytes(r.IP)
		}
		update.Routes = append(update.Routes, rt)
	}
	data, err := proto.Marshal(update)
	if err != nil {
		vlog.Errorf("[Client] marshal full MACUpdate error: %v", err)
		return nil
	}
	return clientEncodeMessage(protocol.MsgMACUpdate, data)
}

func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func clientEncodeMessage(msgType protocol.MsgType, payload []byte) []byte {
	msg := make([]byte, 1+len(payload))
	msg[0] = byte(msgType)
	copy(msg[1:], payload)
	return msg
}

func (c *Client) apiServer() {
	sockPath := c.Config.APISocket
	if sockPath == "" {
		sockPath = config.DefaultClientSocket
	}

	if err := apisock.ListenAndServe(c.ctx, sockPath, c.handleAPI); err != nil {
		vlog.Errorf("[Client] API server error: %v", err)
	}
}

func (c *Client) handleAPI(method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case "af.list":
		return c.apiAFList()
	case "af.get":
		return c.apiAFGet(params)
	case "af.set":
		return c.apiAFSet(params)
	case "peer.list":
		return c.apiPeerList()
	case "show.controller":
		return c.apiShowController()
	case "show.route":
		return c.apiShowRoute(params)
	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
}

type afInfo struct {
	AF       string `json:"af"`
	Channel  string `json:"channel"`
	BindAddr string `json:"bind_addr"`
	AutoIP   string `json:"autoip,omitempty"`
}

func (c *Client) apiAFList() ([]afInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []afInfo
	for afName, chans := range c.Config.AFSettings {
		for chName, cc := range chans {
			if !cc.Enable {
				continue
			}
			info := afInfo{
				AF:       string(afName),
				Channel:  string(chName),
				BindAddr: cc.BindAddr.String(),
				AutoIP:   cc.AutoIPInterface,
			}
			result = append(result, info)
		}
	}
	return result, nil
}

type afGetParams struct {
	AF      string `json:"af"`
	Channel string `json:"channel"`
}

func (c *Client) apiAFGet(params json.RawMessage) (*afInfo, error) {
	var p afGetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Channel == "" {
		p.Channel = string(types.DefaultChannelName)
	}

	c.mu.Lock()
	chans, ok := c.Config.AFSettings[types.AFName(p.AF)]
	var cc *config.ClientChannelConfig
	if ok {
		cc, ok = chans[types.ChannelName(p.Channel)]
	}
	c.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown AF/channel: %s/%s", p.AF, p.Channel)
	}

	return &afInfo{
		AF:       p.AF,
		Channel:  p.Channel,
		BindAddr: cc.BindAddr.String(),
		AutoIP:   cc.AutoIPInterface,
	}, nil
}

type afSetParams struct {
	AF      string `json:"af"`
	Channel string `json:"channel"`
	Addr    string `json:"addr"`
}

func (c *Client) apiAFSet(params json.RawMessage) (interface{}, error) {
	var p afSetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Channel == "" {
		p.Channel = string(types.DefaultChannelName)
	}

	af := types.AFName(p.AF)
	ch := types.ChannelName(p.Channel)
	c.mu.Lock()
	chans, ok := c.Config.AFSettings[af]
	var cc *config.ClientChannelConfig
	if ok {
		cc, ok = chans[ch]
	}
	if ok && cc.AutoIPInterface != "" {
		c.mu.Unlock()
		return nil, fmt.Errorf("AF=%s channel=%s uses autoip_interface, cannot set bind_addr manually", p.AF, p.Channel)
	}
	c.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unknown AF/channel: %s/%s", p.AF, p.Channel)
	}

	newAddr, err := netip.ParseAddr(p.Addr)
	if err != nil {
		return nil, fmt.Errorf("invalid addr: %w", err)
	}

	if err := c.updateBindAddr(af, ch, newAddr); err != nil {
		return nil, err
	}

	return map[string]string{"af": p.AF, "channel": p.Channel, "bind_addr": newAddr.String()}, nil
}

type peerListEntry struct {
	ClientID   string                       `json:"client_id"`
	ClientName string                       `json:"client_name"`
	Endpoints  map[string]*peerEndpointInfo `json:"endpoints"` // key: "af/channel"
	LastSeen   string                       `json:"last_seen"`
	Probe      *peerProbeInfo               `json:"probe,omitempty"`
}

type peerEndpointInfo struct {
	IP        string `json:"ip"`
	ProbePort uint16 `json:"probe_port"`
}

type peerProbeInfo struct {
	Time               string                        `json:"time"`
	AFResults          map[string]*peerAFProbeResult `json:"af_results"`           // key: "af/channel"
	DebouncedAFResults map[string]*peerAFProbeResult `json:"debounced_af_results,omitempty"`
}

type peerAFProbeResult struct {
	LatencyMean float64 `json:"latency_mean"`
	LatencyStd  float64 `json:"latency_std"`
	PacketLoss  float64 `json:"packet_loss"`
}

func (c *Client) apiPeerList() ([]peerListEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var view *ControllerView
	if c.AuthorityCtrl != nil {
		if cc, ok := c.Controllers[*c.AuthorityCtrl]; ok && cc.State != nil {
			view = cc.State
		}
	}
	if view == nil {
		return []peerListEntry{}, nil
	}

	var result []peerListEntry
	for clientID, ci := range view.Clients {
		if clientID == c.ClientID {
			continue
		}

		entry := peerListEntry{
			ClientID:   clientID.Hex()[:16],
			ClientName: ci.ClientName,
			Endpoints:  make(map[string]*peerEndpointInfo),
			LastSeen:   ci.LastSeen.Format(time.RFC3339),
		}

		for af, chans := range ci.Endpoints {
			for ch, ep := range chans {
				key := string(af) + "/" + string(ch)
				entry.Endpoints[key] = &peerEndpointInfo{
					IP:        ep.IP.String(),
					ProbePort: ep.ProbePort,
				}
			}
		}

		if pr, ok := c.lastProbeResults[clientID]; ok {
			entry.Probe = &peerProbeInfo{
				Time:      c.lastProbeTime.Format(time.RFC3339),
				AFResults: make(map[string]*peerAFProbeResult),
			}
			for af, chans := range pr.AFResults {
				for ch, afr := range chans {
					key := string(af) + "/" + string(ch)
					entry.Probe.AFResults[key] = &peerAFProbeResult{
						LatencyMean: afr.LatencyMean,
						LatencyStd:  afr.LatencyStd,
						PacketLoss:  afr.PacketLoss,
					}
				}
			}
			if dr, ok := c.lastDebouncedResults[clientID]; ok {
				entry.Probe.DebouncedAFResults = make(map[string]*peerAFProbeResult)
				for af, chans := range dr.AFResults {
					for ch, afr := range chans {
						key := string(af) + "/" + string(ch)
						entry.Probe.DebouncedAFResults[key] = &peerAFProbeResult{
							LatencyMean: afr.LatencyMean,
							LatencyStd:  afr.LatencyStd,
							PacketLoss:  afr.PacketLoss,
						}
					}
				}
			}
		}

		result = append(result, entry)
	}

	return result, nil
}

// ShowControllerEntry is a single controller for show.controller.
type ShowControllerEntry struct {
	ControllerID  string                       `json:"controller_id"`
	State         string                       `json:"state"`
	IsAuthority   bool                         `json:"is_authority"`
	ActiveAF      string                       `json:"active_af"`
	ActiveChannel string                       `json:"active_channel"`
	Synced        bool                         `json:"synced"`
	MACsSynced    bool                         `json:"macs_synced"`
	ClientCount   int                          `json:"client_count"`
	Endpoints     map[string]*showCtrlEndpoint `json:"endpoints"` // key: "af/channel"
}

type showCtrlEndpoint struct {
	Addr      string `json:"addr"`
	Connected bool   `json:"connected"`
}

func (c *Client) apiShowController() ([]ShowControllerEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []ShowControllerEntry
	for ctrlID, cc := range c.Controllers {
		entry := ShowControllerEntry{
			ControllerID:  ctrlID.Hex()[:16],
			ActiveAF:      string(cc.ActiveAF),
			ActiveChannel: string(cc.ActiveChannel),
			Synced:        cc.Synced,
			MACsSynced:    cc.MACsSynced,
			Endpoints:     make(map[string]*showCtrlEndpoint),
		}

		if c.AuthorityCtrl != nil && *c.AuthorityCtrl == ctrlID {
			entry.IsAuthority = true
		}

		hasConnected := false
		totalConns := 0
		for af, chans := range cc.AFConns {
			for ch, afc := range chans {
				ep := &showCtrlEndpoint{
					Connected: afc.Connected,
				}
				if cfgChans, ok := c.Config.AFSettings[af]; ok {
					if cfgc, ok2 := cfgChans[ch]; ok2 {
						for _, ctrl := range cfgc.Controllers {
							if ctrl.PubKey == ctrlID {
								ep.Addr = ctrl.Addr.String()
								break
							}
						}
					}
				}
				key := string(af) + "/" + string(ch)
				entry.Endpoints[key] = ep
				if afc.Connected {
					hasConnected = true
				}
				totalConns++
			}
		}

		if hasConnected {
			entry.State = "established"
		} else if totalConns > 0 {
			entry.State = "connecting"
		} else {
			entry.State = "down"
		}

		if cc.State != nil {
			entry.ClientCount = cc.State.ClientCount
		}

		result = append(result, entry)
	}
	return result, nil
}

// ShowRouteEntry is a single route for show.route (client side).
type ShowRouteEntry struct {
	MAC        string           `json:"mac"`
	IP         string           `json:"ip,omitempty"`
	Owners     []showRouteOwner `json:"owners"`
	NextHop    string           `json:"nexthop,omitempty"`
	NextHopIP  string           `json:"nexthop_ip,omitempty"`
	AF         string           `json:"af,omitempty"`
	Channel    string           `json:"channel,omitempty"`
	Installed  bool             `json:"installed"`
	Controller string           `json:"controller,omitempty"`
}

type showRouteOwner struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Selected   bool   `json:"selected"`
}

type showRouteParams struct {
	Controller string `json:"controller,omitempty"`
}

func (c *Client) apiShowRoute(params json.RawMessage) ([]ShowRouteEntry, error) {
	var p showRouteParams
	if params != nil {
		_ = json.Unmarshal(params, &p)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	type ctrlView struct {
		ctrlID types.ControllerID
		view   *ControllerView
	}
	var views []ctrlView

	if p.Controller != "" {
		for ctrlID, cc := range c.Controllers {
			if cc.State != nil && ctrlID.Hex()[:len(p.Controller)] == p.Controller {
				views = append(views, ctrlView{ctrlID, cc.State})
				break
			}
		}
		if len(views) == 0 {
			return nil, fmt.Errorf("controller %q not found", p.Controller)
		}
	} else {
		if c.AuthorityCtrl != nil {
			if cc, ok := c.Controllers[*c.AuthorityCtrl]; ok && cc.State != nil {
				views = append(views, ctrlView{*c.AuthorityCtrl, cc.State})
			}
		}
		if len(views) == 0 {
			return []ShowRouteEntry{}, nil
		}
	}

	var result []ShowRouteEntry
	for _, cv := range views {
		myRoutes := cv.view.RouteMatrix[c.ClientID]

		for _, entry := range cv.view.RouteTable {
			re := ShowRouteEntry{
				MAC:        entry.MAC.String(),
				Controller: cv.ctrlID.Hex()[:16],
			}
			if entry.IP.IsValid() {
				re.IP = entry.IP.String()
			}

			selectedOwner := c.selectRouteOwner(entry, cv.view)

			for cid := range entry.Owners {
				name := ""
				if ci, ok := cv.view.Clients[cid]; ok {
					name = ci.ClientName
				}
				isSelected := selectedOwner != nil && cid == *selectedOwner
				re.Owners = append(re.Owners, showRouteOwner{
					ClientID:   cid.Hex()[:16],
					ClientName: name,
					Selected:   isSelected,
				})
			}

			if selectedOwner != nil && myRoutes != nil {
				if routeEntry, ok := myRoutes[*selectedOwner]; ok {
					if nhInfo, ok := cv.view.Clients[routeEntry.NextHop]; ok {
						re.NextHop = nhInfo.ClientName
						if re.NextHop == "" {
							re.NextHop = routeEntry.NextHop.Hex()[:16]
						}
						if chans, ok := nhInfo.Endpoints[routeEntry.AF]; ok {
							if ep, ok2 := chans[routeEntry.Channel]; ok2 {
								re.NextHopIP = ep.IP.String()
							}
						}
					}
					re.AF = string(routeEntry.AF)
					re.Channel = string(routeEntry.Channel)
				}
			}

			fKey := fdbKey{MAC: entry.MAC.String()}
			_, re.Installed = c.CurrentFDB[fKey]

			result = append(result, re)
		}
	}
	return result, nil
}

func (c *Client) updateBindAddr(af types.AFName, ch types.ChannelName, newAddr netip.Addr) error {
	c.mu.Lock()
	chans, ok := c.Config.AFSettings[af]
	var cfgc *config.ClientChannelConfig
	if ok {
		cfgc, ok = chans[ch]
	}
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("unknown AF/channel: %s/%s", af, ch)
	}
	oldAddr := cfgc.BindAddr
	if oldAddr == newAddr {
		c.mu.Unlock()
		return nil
	}
	cfgc.BindAddr = newAddr
	c.mu.Unlock()

	vlog.Infof("[Client] bind_addr updated: AF=%s channel=%s %s -> %s", af, ch, oldAddr, newAddr)

	// Update VXLAN device local IP
	if vdChans, ok := c.VxlanDevs[af]; ok {
		if vd, ok2 := vdChans[ch]; ok2 {
			cmd := exec.Command("ip", "link", "set", vd.Name, "type", "vxlan", "local", newAddr.String())
			if out, err := cmd.CombinedOutput(); err != nil {
				vlog.Errorf("[Client] vxlan %s local update error: %v: %s", vd.Name, err, out)
			} else {
				vlog.Infof("[Client] vxlan %s local updated to %s", vd.Name, newAddr)
			}
		}
	}

	// Disconnect all controllers on this (af, channel)
	c.mu.Lock()
	for _, cc := range c.Controllers {
		if chMap, ok := cc.AFConns[af]; ok {
			if afc, ok2 := chMap[ch]; ok2 {
				if afc.TCPConn != nil {
					afc.TCPConn.Close()
				}
				if afc.CommUDPConn != nil {
					afc.CommUDPConn.Close()
				}
				if afc.Cancel != nil {
					afc.Cancel()
				}
			}
		}
	}
	// Close and restart probe listener on this (af, channel)
	if pChans, ok := c.probeConns[af]; ok {
		if probeConn, ok2 := pChans[ch]; ok2 {
			probeConn.Close()
			delete(pChans, ch)
			if len(pChans) == 0 {
				delete(c.probeConns, af)
			}
		}
	}
	c.mu.Unlock()

	go c.probeListenLoop(af, ch)

	c.fwBindAddrChanged()

	return nil
}
