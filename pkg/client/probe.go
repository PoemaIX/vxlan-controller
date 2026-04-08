package client

import (
	"bytes"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/vlog"
	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/types"

	pb "vxlan-controller/proto"
)

// probeListenLoop listens on the probe UDP port for a given AF.
func (c *Client) probeListenLoop(af types.AFName) {
	afCfg := c.Config.AFSettings[af]
	bindStr := netip.AddrPortFrom(afCfg.BindAddr, afCfg.ProbePort).String()

	udpAddr, err := net.ResolveUDPAddr("udp", bindStr)
	if err != nil {
		vlog.Errorf("[Client] probe listen: resolve error for %s: %v", af, err)
		return
	}

	// Retry bind with backoff (IPv6 DAD may delay address availability)
	var conn *net.UDPConn
	for attempt := 0; attempt < 10; attempt++ {
		conn, err = net.ListenUDP("udp", udpAddr)
		if err == nil {
			break
		}
		select {
		case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
		case <-c.ctx.Done():
			return
		}
	}
	if err != nil {
		vlog.Errorf("[Client] probe listen error on %s after retries: %v", bindStr, err)
		return
	}
	defer conn.Close()

	c.mu.Lock()
	c.probeConns[af] = conn
	c.mu.Unlock()

	vlog.Debugf("[Client] probe listening on %s (AF=%s)", bindStr, af)

	buf := make([]byte, 65536)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				continue
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		// Check if handshake
		if n > 0 && data[0] == byte(protocol.MsgHandshakeInit) {
			go c.handleProbeHandshake(af, conn, data, remoteAddr)
			continue
		}

		if n > 0 && data[0] == byte(protocol.MsgHandshakeResp) {
			go c.handleProbeHandshakeResp(af, data)
			continue
		}

		// Decrypt
		msgType, payload, peerID, err := protocol.ReadUDPPacket(data, c.probeSessions.FindByIndex)
		if err != nil {
			continue
		}

		switch msgType {
		case protocol.MsgProbeRequest:
			c.handleProbeRequest(af, conn, remoteAddr, peerID, payload)
		case protocol.MsgProbeResponse:
			c.handleProbeResponse(af, peerID, payload)
		}
	}
}

func (c *Client) handleProbeHandshake(af types.AFName, conn *net.UDPConn, data []byte, remoteAddr *net.UDPAddr) {
	localIndex := c.probeSessions.AllocateIndex()

	// Collect allowed keys: all known peer public keys
	var allowedKeys [][32]byte
	c.mu.Lock()
	for _, cc := range c.Controllers {
		if cc.State == nil {
			continue
		}
		for _, ci := range cc.State.Clients {
			allowedKeys = append(allowedKeys, ci.ClientID)
		}
	}
	c.mu.Unlock()

	respMsg, session, err := crypto.HandshakeRespond(c.PrivateKey, data, allowedKeys, localIndex)
	if err != nil {
		return
	}

	// Tie-breaking: if we also have a pending outbound handshake to this
	// peer, both sides sent HandshakeInit simultaneously.  Compare public
	// keys to elect a single initiator — the side with the larger key wins
	// and keeps its initiator role; the other side becomes the responder.
	peerID := types.ClientID(session.PeerID)
	c.pendingHandshakesMu.Lock()
	_, hasPending := c.pendingHandshakes[peerID]
	if hasPending {
		if bytes.Compare(c.ClientID[:], peerID[:]) > 0 {
			// We win → stay initiator, ignore this inbound init
			c.pendingHandshakesMu.Unlock()
			return
		}
		// We lose → abandon our outbound handshake, become responder
		delete(c.pendingHandshakes, peerID)
	}
	c.pendingHandshakesMu.Unlock()

	session.IsUDP = true
	c.probeSessions.AddSession(session)
	conn.WriteToUDP(respMsg, remoteAddr)
}

func (c *Client) handleProbeHandshakeResp(af types.AFName, data []byte) {
	c.pendingHandshakesMu.Lock()
	for peerID, state := range c.pendingHandshakes {
		session, err := crypto.HandshakeFinalize(state, data)
		if err != nil {
			continue
		}
		session.IsUDP = true
		c.probeSessions.AddSession(session)
		delete(c.pendingHandshakes, peerID)
		c.pendingHandshakesMu.Unlock()
		return
	}
	c.pendingHandshakesMu.Unlock()
}

func (c *Client) handleProbeRequest(af types.AFName, conn *net.UDPConn, remoteAddr *net.UDPAddr, peerID [32]byte, payload []byte) {
	var req pb.ProbeRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return
	}

	resp := &pb.ProbeResponse{
		ProbeId:      req.ProbeId,
		DstTimestamp:  c.ntp.Now().UnixNano(),
		SrcTimestamp: req.SrcTimestamp,
	}
	respData, err := proto.Marshal(resp)
	if err != nil {
		return
	}

	// Find the session for this specific peer
	session := c.probeSessions.FindByPeer(types.ClientID(peerID))
	if session == nil {
		return
	}

	protocol.WriteUDPPacket(conn, remoteAddr, session, protocol.MsgProbeResponse, respData)
}

func (c *Client) handleProbeResponse(af types.AFName, peerID [32]byte, payload []byte) {
	var resp pb.ProbeResponse
	if err := proto.Unmarshal(payload, &resp); err != nil {
		return
	}

	// Route to the matching probe channel by probe_id
	c.probeResultsMu.Lock()
	if ch, ok := c.probeResponseChs[resp.ProbeId]; ok {
		select {
		case ch <- probeResponseData{af: af, peerID: types.ClientID(peerID), srcTimestamp: resp.SrcTimestamp, dstTimestamp: resp.DstTimestamp}:
		default:
		}
	}
	c.probeResultsMu.Unlock()
}

type probeResponseData struct {
	af           types.AFName
	peerID       types.ClientID
	srcTimestamp int64 // original sender's timestamp (echoed back)
	dstTimestamp int64 // responder's timestamp when received
}

// executeProbe runs a full probe cycle as requested by the controller.
func (c *Client) executeProbe(req *pb.ControllerProbeRequest) {
	probeID := req.ProbeId
	probeTimes := int(req.ProbeTimes)
	inProbeInterval := time.Duration(req.InProbeIntervalMs) * time.Millisecond
	probeTimeout := time.Duration(req.ProbeTimeoutMs) * time.Millisecond

	vlog.Debugf("[Client] starting probe (probe_id=%d, times=%d)", probeID, probeTimes)

	// Collect peers
	c.mu.Lock()
	var peers []peerInfo
	if c.AuthorityCtrl != nil {
		cc, ok := c.Controllers[*c.AuthorityCtrl]
		if ok && cc.State != nil {
			for clientID, ci := range cc.State.Clients {
				if clientID == c.ClientID {
					continue
				}
				peers = append(peers, peerInfo{
					clientID: clientID,
					info:     ci,
				})
			}
		}
	}
	c.mu.Unlock()

	if len(peers) == 0 {
		vlog.Debugf("[Client] no peers for probe")
		return
	}

	// Create response channel
	responseCh := make(chan probeResponseData, probeTimes*len(peers)*2)
	c.probeResultsMu.Lock()
	c.probeResponseChs[probeID] = responseCh
	c.probeResultsMu.Unlock()

	defer func() {
		c.probeResultsMu.Lock()
		delete(c.probeResponseChs, probeID)
		c.probeResultsMu.Unlock()
	}()

	// Track per-peer, per-AF latencies
	type latKey struct {
		clientID types.ClientID
		af       types.AFName
	}
	latencies := make(map[latKey][]float64)
	sent := make(map[latKey]int)
	var latMu sync.Mutex

	// Send probes
	for i := 0; i < probeTimes; i++ {
		if i > 0 {
			time.Sleep(inProbeInterval)
		}

		srcTimestamp := c.ntp.Now().UnixNano()

		probeReq := &pb.ProbeRequest{
			ProbeId:      probeID,
			SrcTimestamp: srcTimestamp,
		}
		probeReqData, _ := proto.Marshal(probeReq)

		for _, peer := range peers {
			for af, probeConn := range c.probeConns {
				// Check if both self and peer have this AF
				_, selfHasAF := c.Config.AFSettings[af]
				if !selfHasAF {
					continue
				}
				peerEP, peerHasAF := peer.info.Endpoints[af]
				if !peerHasAF {
					continue
				}

				// Expire stale session (no successful decrypt for 30-45s).
				// Jitter derived from our own ClientID byte so each client
				// gets a different but stable expiry, avoiding synchronized
				// re-handshake collisions.
				jitter := int(c.ClientID[0]) * 15000 / 256
				expiry := 30*time.Second + time.Duration(jitter)*time.Millisecond
				c.probeSessions.ExpireByPeer(peer.clientID, expiry)

				// Ensure we have a probe session with this peer
				session := c.probeSessions.FindByPeer(peer.clientID)
				if session == nil {
					c.initiateProbeHandshake(af, peer.clientID, peerEP)
					time.Sleep(100 * time.Millisecond)
					session = c.probeSessions.FindByPeer(peer.clientID)
					if session == nil {
						continue
					}
				}

				addr := &net.UDPAddr{
					IP:   peerEP.IP.AsSlice(),
					Port: int(peerEP.ProbePort),
				}

				latMu.Lock()
				key := latKey{clientID: peer.clientID, af: af}
				sent[key]++
				latMu.Unlock()

				protocol.WriteUDPPacket(probeConn, addr, session, protocol.MsgProbeRequest, probeReqData)
			}
		}
	}

	// Wait for responses
	deadline := time.After(probeTimeout)
	collecting := true
	for collecting {
		select {
		case resp := <-responseCh:
			// Single-way latency: local → peer (NTP-synced clocks)
			// Negative values are valid (clock skew); sign cancels on any
			// end-to-end path, so routing correctness is preserved.
			latency := float64(resp.dstTimestamp-resp.srcTimestamp) / 1e6 // ms

			key := latKey{clientID: resp.peerID, af: resp.af}
			latMu.Lock()
			latencies[key] = append(latencies[key], latency)
			latMu.Unlock()
		case <-deadline:
			collecting = false
		case <-c.ctx.Done():
			return
		}
	}

	// Log collected latencies
	latMu.Lock()
	for key, lats := range latencies {
		vlog.Debugf("[Client] probe results: peer=%s af=%s latencies=%v sent=%d", key.clientID.Hex()[:8], key.af, lats, sent[key])
	}
	for key, s := range sent {
		if _, ok := latencies[key]; !ok {
			vlog.Debugf("[Client] probe results: peer=%s af=%s NO RESPONSES sent=%d", key.clientID.Hex()[:8], key.af, s)
		}
	}
	latMu.Unlock()

	// Build ProbeResults from collected data
	results := &pb.ProbeResults{
		ProbeId:        probeID,
		SourceClientId: c.ClientID[:],
		Results:        make(map[string]*pb.ProbeResultEntry),
	}

	for _, peer := range peers {
		entry := &pb.ProbeResultEntry{
			AfResults: make(map[string]*pb.AFProbeResult),
		}

		for af := range c.Config.AFSettings {
			afCfg := c.Config.AFSettings[af]
			key := latKey{clientID: peer.clientID, af: af}

			latMu.Lock()
			lats := latencies[key]
			sentCount := sent[key]
			latMu.Unlock()

			if sentCount == 0 {
				continue
			}

			result := &pb.AFProbeResult{
				Priority:       int32(afCfg.Priority),
				AdditionalCost: afCfg.AdditionalCost,
			}

			if len(lats) == 0 {
				result.LatencyMean = types.INF_LATENCY
				result.PacketLoss = 1.0
			} else {
				var sum float64
				for _, l := range lats {
					sum += l
				}
				result.LatencyMean = sum / float64(len(lats))

				var variance float64
				for _, l := range lats {
					diff := l - result.LatencyMean
					variance += diff * diff
				}
				result.LatencyStd = math.Sqrt(variance / float64(len(lats)))
				result.PacketLoss = 1.0 - float64(len(lats))/float64(sentCount)
			}

			entry.AfResults[string(af)] = result
		}

		results.Results[peer.clientID.Hex()] = entry
	}

	// Save local probe results for API
	c.mu.Lock()
	c.lastProbeTime = time.Now()
	c.lastProbeResults = make(map[types.ClientID]*LocalProbeResult)
	for _, peer := range peers {
		lpr := &LocalProbeResult{AFResults: make(map[types.AFName]*LocalAFProbeResult)}
		for af := range c.Config.AFSettings {
			key := latKey{clientID: peer.clientID, af: af}
			latMu.Lock()
			lats := latencies[key]
			sentCount := sent[key]
			latMu.Unlock()
			if sentCount == 0 {
				continue
			}
			afr := &LocalAFProbeResult{}
			if len(lats) == 0 {
				afr.LatencyMean = types.INF_LATENCY
				afr.PacketLoss = 1.0
			} else {
				var sum float64
				for _, l := range lats {
					sum += l
				}
				afr.LatencyMean = sum / float64(len(lats))
				var variance float64
				for _, l := range lats {
					diff := l - afr.LatencyMean
					variance += diff * diff
				}
				afr.LatencyStd = math.Sqrt(variance / float64(len(lats)))
				afr.PacketLoss = 1.0 - float64(len(lats))/float64(sentCount)
			}
			lpr.AFResults[af] = afr
		}
		c.lastProbeResults[peer.clientID] = lpr
	}
	c.mu.Unlock()

	// Send ProbeResults to ALL controllers via sendqueue
	resultsData, err := proto.Marshal(results)
	if err != nil {
		return
	}

	msg := clientEncodeMessage(protocol.MsgProbeResults, resultsData)
	c.mu.Lock()
	for _, cc := range c.Controllers {
		select {
		case cc.SendQueue <- ClientQueueItem{Message: msg}:
		default:
		}
	}
	c.mu.Unlock()

	vlog.Debugf("[Client] probe completed (probe_id=%d), results sent to all controllers", probeID)
}

type peerInfo struct {
	clientID types.ClientID
	info     *ClientInfoView
}

func (c *Client) initiateProbeHandshake(af types.AFName, peerID types.ClientID, ep *types.Endpoint) {
	probeConn, ok := c.probeConns[af]
	if !ok {
		return
	}

	localIndex := c.probeSessions.AllocateIndex()
	initMsg, state, err := crypto.HandshakeInitiate(c.PrivateKey, peerID, localIndex)
	if err != nil {
		return
	}

	c.pendingHandshakesMu.Lock()
	c.pendingHandshakes[peerID] = state
	c.pendingHandshakesMu.Unlock()

	addr := &net.UDPAddr{
		IP:   ep.IP.AsSlice(),
		Port: int(ep.ProbePort),
	}

	probeConn.WriteToUDP(initMsg, addr)
}
