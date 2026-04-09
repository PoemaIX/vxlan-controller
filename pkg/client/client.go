package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"vxlan-controller/pkg/vlog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"

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

// Client implements the VXLAN client.
type Client struct {
	Config     *config.ClientConfig
	PrivateKey [32]byte
	ClientID   types.ClientID

	mu            sync.Mutex
	Controllers   map[types.ControllerID]*ControllerConn
	AuthorityCtrl *types.ControllerID

	// Network devices
	VxlanDevs map[types.AFName]*VxlanDev
	TapFD     *os.File

	// Local state
	LocalMACs []types.Type2Route

	// FDB state
	CurrentFDB map[fdbKey]fdbEntry

	// Filters
	Filters *filter.FilterSet

	// Multicast stats
	mcastStats *McastStats

	// NTP
	ntp *ntp.TimeSync

	// Addr watch
	addrEngines map[types.AFName]*filter.AddrSelectEngine

	// Probe
	probeConns         map[types.AFName]*net.UDPConn
	probeSessions      *crypto.SessionManager
	pendingHandshakes  map[types.ClientID]*crypto.HandshakeState
	pendingHandshakesMu sync.Mutex
	probeResultsMu     sync.Mutex
	probeResponseChs   map[uint64]chan probeResponseData
	lastProbeTime      time.Time
	lastProbeResults   map[types.ClientID]*LocalProbeResult

	// Channels
	fdbNotifyCh       chan struct{}
	fwNotifyCh        chan struct{}
	authorityChangeCh chan struct{}
	tapInjectCh       chan []byte
	initDone          chan struct{} // closed after init_timeout

	ctx    context.Context
	cancel context.CancelFunc
}

// ClientQueueItem is the sendqueue element for client→controller messages.
type ClientQueueItem struct {
	State   []byte // encoded MAC update (full or inc), nil if none
	Message []byte // encoded non-state message (probe results, etc.), nil if none
}

// ControllerConn represents Client's connection to a single Controller.
type ControllerConn struct {
	ControllerID types.ControllerID
	AFConns      map[types.AFName]*ClientAFConn
	ActiveAF     types.AFName
	State        *ControllerView
	Synced       bool
	MACsSynced   bool
	SendQueue    chan ClientQueueItem
}

// ClientAFConn represents a single AF connection to a controller.
type ClientAFConn struct {
	AF          types.AFName
	TCPConn     net.Conn
	Session     *crypto.Session
	CommUDPConn net.PacketConn // UDP for multicast on communication channel
	UDPSession  *crypto.Session
	Cancel      context.CancelFunc
	Connected   bool
	Done        chan struct{} // closed when this conn should stop
	Cleaned     chan struct{} // closed after handleClientDisconnect completes
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
	AFResults map[types.AFName]*LocalAFProbeResult
}

// LocalAFProbeResult stores per-AF probe result.
type LocalAFProbeResult struct {
	LatencyMean float64
	LatencyStd  float64
	PacketLoss  float64
}

// ClientInfoView is the Client's view of a ClientInfo from the Controller.
type ClientInfoView struct {
	ClientID  types.ClientID
	ClientName string
	Endpoints map[types.AFName]*types.Endpoint
	LastSeen  time.Time
	Routes    []types.Type2Route
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
		Config:            cfg,
		PrivateKey:        cfg.PrivateKey,
		ClientID:          pubKey,
		Controllers:       make(map[types.ControllerID]*ControllerConn),
		VxlanDevs:         make(map[types.AFName]*VxlanDev),
		CurrentFDB:        make(map[fdbKey]fdbEntry),
		Filters:           filters,
		mcastStats:        newMcastStats(),
		ntp:               ntp.New(cfg.NTPServers, cfg.NTPRTTThreshold),
		addrEngines:       make(map[types.AFName]*filter.AddrSelectEngine),
		probeConns:        make(map[types.AFName]*net.UDPConn),
		probeSessions:     crypto.NewSessionManager(),
		pendingHandshakes: make(map[types.ClientID]*crypto.HandshakeState),
		probeResponseChs:  make(map[uint64]chan probeResponseData),
		fdbNotifyCh:       make(chan struct{}, 1),
		fwNotifyCh:        make(chan struct{}, 1),
		authorityChangeCh: make(chan struct{}, 1),
		tapInjectCh:       make(chan []byte, 256),
		initDone:          make(chan struct{}),
		ctx:               ctx,
		cancel:            cancel,
	}

	// Initialize addr select engines for AFs with autoip_interface
	for afName, afCfg := range cfg.AFSettings {
		if afCfg.AutoIPInterface == "" {
			continue
		}
		engine, err := filter.NewAddrSelectEngine(afCfg.AddrSelectScript)
		if err != nil {
			vlog.Fatalf("[Client] AF=%s: failed to initialize addr_select: %v", afName, err)
		}
		c.addrEngines[afName] = engine
	}

	return c
}

func (c *Client) Run() error {
	vlog.Infof("[Client] starting, ID=%s", c.ClientID.Hex()[:8])

	// Step 1: NTP sync
	go c.ntp.RunLoop(c.Config.NTPPeriod, c.ctx.Done())

	// Wait a moment for first NTP sync
	time.Sleep(500 * time.Millisecond)

	// Step 2a: Resolve initial bind addrs for autoip_interface AFs
	for afName, afCfg := range c.Config.AFSettings {
		if afCfg.AutoIPInterface != "" {
			c.resolveInitialBindAddr(afName)
		}
	}

	// Step 2b: Initialize devices
	if err := c.initDevices(); err != nil {
		return fmt.Errorf("init devices: %w", err)
	}

	// Step 2c: Initialize VXLAN firewall (non-fatal; may fail in LXC without full nftables support)
	if err := c.initFirewall(); err != nil {
		vlog.Warnf("[Client] VXLAN firewall init failed (nftables may not be fully available): %v", err)
		c.Config.VxlanFirewall = false // disable further firewall operations
	}

	// Step 3: Collect unique controllers across all AFs
	controllerMap := make(map[types.ControllerID]bool)
	for _, afCfg := range c.Config.AFSettings {
		if !afCfg.Enable {
			continue
		}
		for _, ctrl := range afCfg.Controllers {
			controllerMap[types.ControllerID(ctrl.PubKey)] = true
		}
	}

	for ctrlID := range controllerMap {
		c.Controllers[ctrlID] = &ControllerConn{
			ControllerID: ctrlID,
			AFConns:      make(map[types.AFName]*ClientAFConn),
			SendQueue:    make(chan ClientQueueItem, clientSendQueueSize),
			State: &ControllerView{
				Clients:     make(map[types.ClientID]*ClientInfoView),
				RouteMatrix: make(map[types.ClientID]map[types.ClientID]*types.RouteEntry),
			},
		}
	}

	// Start sendloops for all controllers
	for _, cc := range c.Controllers {
		go c.controllerSendLoop(cc)
	}

	// Step 4: Start TCP connections to all controllers
	for _, afCfg := range c.Config.AFSettings {
		if !afCfg.Enable {
			continue
		}
		for _, ctrl := range afCfg.Controllers {
			ctrlID := types.ControllerID(ctrl.PubKey)
			go c.tcpConnLoop(ctrlID, afCfg.Name, ctrl)
		}
	}

	// Step 5: Start probe listeners
	for afName := range c.Config.AFSettings {
		if !c.Config.AFSettings[afName].Enable {
			continue
		}
		go c.probeListenLoop(afName)
	}

	// Step 5b: Start addr watch for autoip_interface AFs
	go c.addrWatchLoop()

	// Step 6: Start neighbor watch
	go c.neighborWatchLoop()

	// Step 7: Start tap loops
	go c.tapReadLoop()
	go c.tapWriteLoop()

	// Step 8: Start FDB reconciler
	go c.fdbReconcileLoop()

	// Step 8b: Start firewall peer sync loop
	go c.firewallLoop()

	// Step 8c: Start mcast stats reporter
	go c.mcastStatsReportLoop()

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

	// Clean up FDB entries
	c.cleanupFDB()

	// Clean up nftables
	if c.Config.ClampMSSToMTU {
		c.cleanupNftables()
	}
	c.cleanupFirewall()

	// Close all connections and sendqueues
	c.mu.Lock()
	for _, cc := range c.Controllers {
		close(cc.SendQueue)
		for _, afc := range cc.AFConns {
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
	c.mu.Unlock()

	c.Filters.Close()

	for _, engine := range c.addrEngines {
		engine.Close()
	}
}

func (c *Client) tcpConnLoop(ctrlID types.ControllerID, af types.AFName, ctrl config.ControllerEndpoint) {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		start := time.Now()
		err := c.connectToController(ctrlID, af, ctrl)
		elapsed := time.Since(start)

		if err != nil {
			vlog.Warnf("[Client] connection to controller %s AF=%s failed: %v", ctrlID.Hex()[:8], af, err)
		}

		// Reset backoff if connection lasted > 10s (was a real connection, not immediate fail)
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

func (c *Client) connectToController(ctrlID types.ControllerID, af types.AFName, ctrl config.ControllerEndpoint) error {
	afCfg := c.Config.AFSettings[af]

	if !afCfg.BindAddr.IsValid() {
		return fmt.Errorf("no bind_addr resolved yet (autoip_interface pending)")
	}

	// Bind to local addr
	localAddr := &net.TCPAddr{
		IP: afCfg.BindAddr.AsSlice(),
	}

	dialer := net.Dialer{
		LocalAddr: localAddr,
		Timeout:   10 * time.Second,
	}

	conn, err := dialer.DialContext(c.ctx, "tcp", ctrl.Addr.String())
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	// Enable TCP keepalive
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	vlog.Infof("[Client] connected to controller %s on AF=%s", ctrlID.Hex()[:8], af)

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
	vlog.Infof("[Client] handshake completed with controller %s on AF=%s", ctrlID.Hex()[:8], af)

	// Send ClientRegister
	reg := &pb.ClientRegister{
		ClientId:    c.ClientID[:],
		AfEndpoints: make(map[string]*pb.AFEndpoint),
	}

	for afn, afc := range c.Config.AFSettings {
		if !afc.Enable {
			continue
		}
		reg.AfEndpoints[string(afn)] = &pb.AFEndpoint{
			ProbePort:    uint32(afc.ProbePort),
			VxlanDstPort: uint32(c.getVxlanDstPort(afn)),
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

	// Create UDP connection for multicast on this AF
	commUDPAddr, err := net.ResolveUDPAddr("udp", netip.AddrPortFrom(afCfg.BindAddr, 0).String())
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

	// UDP handshake with controller for multicast
	udpSession := c.setupUDPSession(ctrl, commUDPConn)

	afc := &ClientAFConn{
		AF:          af,
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

	// Replace previous AF connection if exists:
	// CloseDone → unlock → close TCP → wait Cleaned → relock → set new
	var oldAfc *ClientAFConn
	if old, ok := cc.AFConns[af]; ok {
		oldAfc = old
		old.CloseDone()
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

	cc.AFConns[af] = afc
	c.mu.Unlock()

	// Start UDP read loop for multicast delivery
	go c.commUDPReadLoop(ctrlID, af, commUDPConn, udpSession, afCtx)

	// Enter recv loop
	c.tcpRecvLoop(ctrlID, af, afc)

	// Cleanup on disconnect
	afCancel()
	conn.Close()
	commUDPConn.Close()
	c.handleClientDisconnect(cc, af, afc)

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

	// Wait for response
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

func (c *Client) commUDPReadLoop(ctrlID types.ControllerID, af types.AFName, conn net.PacketConn, session *crypto.Session, ctx context.Context) {
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
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
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

			// Filter inbound multicast
			accepted, reason, detail := c.Filters.InputMcast.FilterMcast(deliver.Payload)
			c.mcastStats.RecordRx(deliver.Payload, accepted, reason, detail)
			if !accepted {
				continue
			}

			// Inject into tap
			select {
			case c.tapInjectCh <- deliver.Payload:
			default:
				vlog.Warnf("[Client] tapInjectCh full, dropping frame")
			}
		}
	}
}

func (c *Client) tcpRecvLoop(ctrlID types.ControllerID, af types.AFName, afc *ClientAFConn) {
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
			c.handleControllerState(ctrlID, af, payload)
		case protocol.MsgControllerStateUpdate:
			c.handleControllerStateUpdate(ctrlID, payload)
		case protocol.MsgControllerProbeRequest:
			c.handleControllerProbeRequest(ctrlID, payload)
		default:
			vlog.Warnf("[Client] unknown msg_type %d from controller", msgType)
		}
	}
}

func (c *Client) handleControllerState(ctrlID types.ControllerID, af types.AFName, payload []byte) {
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

	// Update view
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

	// Full update received on this AF → set as active AF
	cc.ActiveAF = af

	vlog.Debugf("[Client] received full state from controller %s (AF=%s, %d clients)", ctrlID.Hex()[:8], af, view.ClientCount)

	// Notify authority selection and FDB
	select {
	case c.authorityChangeCh <- struct{}{}:
	default:
	}

	// Trigger sendloop to send full MACs (MACsSynced=false ensures full send)
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

	c.mu.Unlock()

	// Notify FDB reconciler
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

	// Only process if from authority controller
	c.mu.Lock()
	isAuthority := c.AuthorityCtrl != nil && *c.AuthorityCtrl == ctrlID
	c.mu.Unlock()

	// Wait for init_done before processing
	select {
	case <-c.initDone:
	default:
		return // not initialized yet
	}

	if !isAuthority {
		return
	}

	go c.executeProbe(&req)
}

func (c *Client) getVxlanDstPort(af types.AFName) uint16 {
	afCfg, ok := c.Config.AFSettings[af]
	if !ok {
		return 0
	}
	return afCfg.VxlanDstPort
}

func protoToClientInfoView(p *pb.ClientInfoProto) *ClientInfoView {
	civ := &ClientInfoView{
		ClientName: p.ClientName,
		Endpoints:  make(map[types.AFName]*types.Endpoint),
		LastSeen:   time.Unix(0, p.LastSeen),
	}
	copy(civ.ClientID[:], p.ClientId)

	for af, ep := range p.Endpoints {
		e := &types.Endpoint{
			ProbePort:    uint16(ep.ProbePort),
			VxlanDstPort: uint16(ep.VxlanDstPort),
		}
		if len(ep.Ip) == 4 {
			e.IP = netip.AddrFrom4([4]byte(ep.Ip))
		} else if len(ep.Ip) == 16 {
			e.IP = netip.AddrFrom16([16]byte(ep.Ip))
		}
		civ.Endpoints[types.AFName(af)] = e
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

// controllerSendLoop dequeues items and sends to the controller.
// If activeAF is empty, items are discarded (client waits for controller to pick).
func (c *Client) controllerSendLoop(cc *ControllerConn) {
	for item := range cc.SendQueue {
		c.mu.Lock()
		if cc.ActiveAF == "" {
			c.mu.Unlock()
			continue // discard — wait for controller to select AF
		}
		afc := cc.AFConns[cc.ActiveAF]
		if afc == nil {
			c.mu.Unlock()
			continue
		}
		needFullMACs := !cc.MACsSynced
		if needFullMACs {
			item.State = c.getFullMACsEncoded()
			// Mark synced immediately so concurrent neighbor events queue
			// incremental updates instead of being silently dropped.
			// If the write below fails we revert to false.
			cc.MACsSynced = true
		}
		c.mu.Unlock()

		// Send State
		if item.State != nil {
			msgType := protocol.MsgType(item.State[0])
			payload := item.State[1:]
			if err := protocol.WriteTCPMessage(afc.TCPConn, afc.Session, msgType, payload); err != nil {
				if needFullMACs {
					c.mu.Lock()
					cc.MACsSynced = false
					c.mu.Unlock()
				}
				continue
			}
		}

		// Send Message
		if item.Message != nil {
			msgType := protocol.MsgType(item.Message[0])
			payload := item.Message[1:]
			protocol.WriteTCPMessage(afc.TCPConn, afc.Session, msgType, payload)
		}
	}
}

// handleClientDisconnect cleans up after an AF connection to a controller drops.
func (c *Client) handleClientDisconnect(cc *ControllerConn, af types.AFName, afc *ClientAFConn) {
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
		cc.MACsSynced = false
		// No drain — sendloop will overwrite State with full MACs on next dequeue.
	}
	// Non-activeAF disconnect: just cleared the handle, nothing else.
}

// getFullMACsEncoded returns encoded full MACUpdate from LocalMACs.
// Must be called with c.mu held.
func (c *Client) getFullMACsEncoded() []byte {
	update := &pb.MACUpdate{IsFull: true}
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

// clientEncodeMessage prepends the msg_type byte to payload.
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
	BindAddr string `json:"bind_addr"`
	AutoIP   string `json:"autoip,omitempty"` // interface name if autoip mode
}

func (c *Client) apiAFList() ([]afInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []afInfo
	for afName, afCfg := range c.Config.AFSettings {
		if !afCfg.Enable {
			continue
		}
		info := afInfo{
			AF:       string(afName),
			BindAddr: afCfg.BindAddr.String(),
			AutoIP:   afCfg.AutoIPInterface,
		}
		result = append(result, info)
	}
	return result, nil
}

type afGetParams struct {
	AF string `json:"af"`
}

func (c *Client) apiAFGet(params json.RawMessage) (*afInfo, error) {
	var p afGetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	c.mu.Lock()
	afCfg, ok := c.Config.AFSettings[types.AFName(p.AF)]
	c.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown AF: %s", p.AF)
	}

	return &afInfo{
		AF:       p.AF,
		BindAddr: afCfg.BindAddr.String(),
		AutoIP:   afCfg.AutoIPInterface,
	}, nil
}

type afSetParams struct {
	AF   string `json:"af"`
	Addr string `json:"addr"`
}

func (c *Client) apiAFSet(params json.RawMessage) (interface{}, error) {
	var p afSetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	af := types.AFName(p.AF)
	c.mu.Lock()
	afCfg, ok := c.Config.AFSettings[af]
	if ok && afCfg.AutoIPInterface != "" {
		c.mu.Unlock()
		return nil, fmt.Errorf("AF %s uses autoip_interface, cannot set bind_addr manually", p.AF)
	}
	c.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unknown AF: %s", p.AF)
	}

	newAddr, err := netip.ParseAddr(p.Addr)
	if err != nil {
		return nil, fmt.Errorf("invalid addr: %w", err)
	}

	if err := c.updateBindAddr(af, newAddr); err != nil {
		return nil, err
	}

	return map[string]string{"af": p.AF, "bind_addr": newAddr.String()}, nil
}

type peerListEntry struct {
	ClientID   string                       `json:"client_id"`
	ClientName string                       `json:"client_name"`
	Endpoints  map[string]*peerEndpointInfo `json:"endpoints"`
	LastSeen   string                       `json:"last_seen"`
	Probe      *peerProbeInfo               `json:"probe,omitempty"`
}

type peerEndpointInfo struct {
	IP        string `json:"ip"`
	ProbePort uint16 `json:"probe_port"`
}

type peerProbeInfo struct {
	Time      string                        `json:"time"`
	AFResults map[string]*peerAFProbeResult `json:"af_results"`
}

type peerAFProbeResult struct {
	LatencyMean float64 `json:"latency_mean"`
	LatencyStd  float64 `json:"latency_std"`
	PacketLoss  float64 `json:"packet_loss"`
}

func (c *Client) apiPeerList() ([]peerListEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Find authority controller view
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

		for af, ep := range ci.Endpoints {
			entry.Endpoints[string(af)] = &peerEndpointInfo{
				IP:        ep.IP.String(),
				ProbePort: ep.ProbePort,
			}
		}

		if pr, ok := c.lastProbeResults[clientID]; ok {
			entry.Probe = &peerProbeInfo{
				Time:      c.lastProbeTime.Format(time.RFC3339),
				AFResults: make(map[string]*peerAFProbeResult),
			}
			for af, afr := range pr.AFResults {
				entry.Probe.AFResults[string(af)] = &peerAFProbeResult{
					LatencyMean: afr.LatencyMean,
					LatencyStd:  afr.LatencyStd,
					PacketLoss:  afr.PacketLoss,
				}
			}
		}

		result = append(result, entry)
	}

	return result, nil
}

// ShowControllerEntry is a single controller for show.controller.
type ShowControllerEntry struct {
	ControllerID string                       `json:"controller_id"`
	State        string                       `json:"state"`
	IsAuthority  bool                         `json:"is_authority"`
	ActiveAF     string                       `json:"active_af"`
	Synced       bool                         `json:"synced"`
	MACsSynced   bool                         `json:"macs_synced"`
	ClientCount  int                          `json:"client_count"`
	Endpoints    map[string]*showCtrlEndpoint `json:"endpoints"`
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
			ControllerID: ctrlID.Hex()[:16],
			ActiveAF:     string(cc.ActiveAF),
			Synced:       cc.Synced,
			MACsSynced:   cc.MACsSynced,
			Endpoints:    make(map[string]*showCtrlEndpoint),
		}

		if c.AuthorityCtrl != nil && *c.AuthorityCtrl == ctrlID {
			entry.IsAuthority = true
		}

		// Determine connection state
		hasConnected := false
		for af, afc := range cc.AFConns {
			ep := &showCtrlEndpoint{
				Connected: afc.Connected,
			}
			// Find addr from config
			for _, afCfg := range c.Config.AFSettings {
				for _, ctrl := range afCfg.Controllers {
					if ctrl.PubKey == ctrlID {
						ep.Addr = ctrl.Addr.String()
					}
				}
			}
			entry.Endpoints[string(af)] = ep
			if afc.Connected {
				hasConnected = true
			}
		}

		if hasConnected {
			entry.State = "established"
		} else if len(cc.AFConns) > 0 {
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
	Controller string           `json:"controller,omitempty"`
}

type showRouteOwner struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
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

	// Select which controller view(s) to use
	type ctrlView struct {
		ctrlID types.ControllerID
		view   *ControllerView
	}
	var views []ctrlView

	if p.Controller != "" {
		// Find controller by ID prefix
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
		// Use authority controller
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
		for _, entry := range cv.view.RouteTable {
			re := ShowRouteEntry{
				MAC:        entry.MAC.String(),
				Controller: cv.ctrlID.Hex()[:16],
			}
			if entry.IP.IsValid() {
				re.IP = entry.IP.String()
			}
			for cid := range entry.Owners {
				name := ""
				if ci, ok := cv.view.Clients[cid]; ok {
					name = ci.ClientName
				}
				re.Owners = append(re.Owners, showRouteOwner{
					ClientID:   cid.Hex()[:16],
					ClientName: name,
				})
			}
			result = append(result, re)
		}
	}
	return result, nil
}

func (c *Client) updateBindAddr(af types.AFName, newAddr netip.Addr) error {
	c.mu.Lock()
	afCfg, ok := c.Config.AFSettings[af]
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("unknown AF: %s", af)
	}
	oldAddr := afCfg.BindAddr
	if oldAddr == newAddr {
		c.mu.Unlock()
		return nil
	}
	afCfg.BindAddr = newAddr
	c.mu.Unlock()

	vlog.Infof("[Client] bind_addr updated: AF=%s %s -> %s", af, oldAddr, newAddr)

	// Update VXLAN device local IP (requires ip command, netlink LinkModify doesn't support it)
	if vd, ok := c.VxlanDevs[af]; ok {
		cmd := exec.Command("ip", "link", "set", vd.Name, "type", "vxlan", "local", newAddr.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			vlog.Errorf("[Client] vxlan %s local update error: %v: %s", vd.Name, err, out)
		} else {
			vlog.Infof("[Client] vxlan %s local updated to %s", vd.Name, newAddr)
		}
	}

	// Disconnect all controllers on this AF - tcpConnLoop will reconnect with new bind addr
	c.mu.Lock()
	for _, cc := range c.Controllers {
		if afc, ok := cc.AFConns[af]; ok {
			// Close TCP conn first to unblock blocking reads, then cancel context
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
	// Close and restart probe listener on this AF
	if probeConn, ok := c.probeConns[af]; ok {
		probeConn.Close()
		delete(c.probeConns, af)
	}
	c.mu.Unlock()

	// Restart probe listener with new bind addr
	go c.probeListenLoop(af)

	// Rebuild firewall rules (bind addr in chain rules changed)
	c.fwBindAddrChanged()

	return nil
}
