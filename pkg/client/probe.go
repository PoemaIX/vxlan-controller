package client

import (
	"bytes"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/sockopt"
	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"

	pb "vxlan-controller/proto"
)

// probeListenLoop listens on the probe UDP port for a given (af, channel).
func (c *Client) probeListenLoop(af types.AFName, ch types.ChannelName) {
	chans, ok := c.Config.AFSettings[af]
	if !ok {
		return
	}
	cc, ok := chans[ch]
	if !ok {
		return
	}
	bindStr := netip.AddrPortFrom(cc.BindAddr, cc.ProbePort).String()

	lc := net.ListenConfig{
		Control: sockopt.ControlFn(sockopt.Options{BindDevice: cc.BindDevice}),
	}

	// Retry bind with backoff (IPv6 DAD may delay address availability)
	var pc net.PacketConn
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		pc, err = lc.ListenPacket(c.ctx, "udp", bindStr)
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
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		vlog.Errorf("[Client] probe listen on %s: unexpected conn type %T", bindStr, pc)
		return
	}
	defer conn.Close()

	c.mu.Lock()
	if _, ok := c.probeConns[af]; !ok {
		c.probeConns[af] = make(map[types.ChannelName]*net.UDPConn)
	}
	c.probeConns[af][ch] = conn
	c.mu.Unlock()

	vlog.Debugf("[Client] probe listening on %s (AF=%s channel=%s)", bindStr, af, ch)

	buf := make([]byte, 65536)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// UDP listener has no recoverable transient errors; any error
			// means the socket was closed (Stop / updateBindAddr) or is
			// otherwise unusable. Exit so the goroutine doesn't spin.
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		// Check if handshake
		if n > 0 && data[0] == byte(protocol.MsgHandshakeInit) {
			go c.handleProbeHandshake(af, ch, conn, data, remoteAddr)
			continue
		}

		if n > 0 && data[0] == byte(protocol.MsgHandshakeResp) {
			go c.handleProbeHandshakeResp(af, ch, data)
			continue
		}

		// Decrypt
		msgType, payload, peerID, err := protocol.ReadUDPPacket(data, c.probeSessions.FindByIndex)
		if err != nil {
			continue
		}

		switch msgType {
		case protocol.MsgProbeRequest:
			c.handleProbeRequest(af, ch, conn, remoteAddr, peerID, payload)
		case protocol.MsgProbeResponse:
			c.handleProbeResponse(af, ch, peerID, payload)
		}
	}
}

func (c *Client) handleProbeHandshake(af types.AFName, ch types.ChannelName, conn *net.UDPConn, data []byte, remoteAddr *net.UDPAddr) {
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

func (c *Client) handleProbeHandshakeResp(af types.AFName, ch types.ChannelName, data []byte) {
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

func (c *Client) handleProbeRequest(af types.AFName, ch types.ChannelName, conn *net.UDPConn, remoteAddr *net.UDPAddr, peerID [32]byte, payload []byte) {
	var req pb.ProbeRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return
	}

	resp := &pb.ProbeResponse{
		ProbeId:        req.ProbeId,
		DstTimestamp:   c.ntp.Now().UnixNano(),
		SrcTimestamp:   req.SrcTimestamp,
		SrcChannelName: req.SrcChannelName,
		DstChannelName: req.DstChannelName,
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

func (c *Client) handleProbeResponse(af types.AFName, ch types.ChannelName, peerID [32]byte, payload []byte) {
	var resp pb.ProbeResponse
	if err := proto.Unmarshal(payload, &resp); err != nil {
		return
	}

	// The response echoes the channel pair the request was sent for. A peer
	// running an older build echoes nothing — fall back to the receiving
	// socket's channel on both sides (the old same-name assumption).
	local := types.ChannelName(resp.SrcChannelName)
	peer := types.ChannelName(resp.DstChannelName)
	if local == "" {
		local = ch
	}
	if peer == "" {
		peer = ch
	}

	// Route to the matching probe channel by probe_id
	c.probeResultsMu.Lock()
	if rchan, ok := c.probeResponseChs[resp.ProbeId]; ok {
		select {
		case rchan <- probeResponseData{af: af, pair: types.ChannelPair{Local: local, Peer: peer}, peerID: types.ClientID(peerID), srcTimestamp: resp.SrcTimestamp, dstTimestamp: resp.DstTimestamp}:
		default:
		}
	}
	c.probeResultsMu.Unlock()
}

type probeResponseData struct {
	af           types.AFName
	pair         types.ChannelPair
	peerID       types.ClientID
	srcTimestamp int64 // original sender's timestamp (echoed back)
	dstTimestamp int64 // responder's timestamp when received
}

// latKey is a per-(peer, af, channel pair) probe key used in executeProbe.
type latKey struct {
	clientID types.ClientID
	af       types.AFName
	pair     types.ChannelPair
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

	latencies := make(map[latKey][]float64)
	sent := make(map[latKey]int)
	var latMu sync.Mutex

	// Send probes: every local channel probes every peer channel in the same
	// AF. Channel names are per-node labels, so no name matching is assumed —
	// the (local, peer) pair identifies the link being measured.
	for i := 0; i < probeTimes; i++ {
		if i > 0 {
			time.Sleep(inProbeInterval)
		}

		for _, peer := range peers {
			for af, chans := range c.probeConns {
				for lch, probeConn := range chans {
					selfChans, selfHasAF := c.Config.AFSettings[af]
					if !selfHasAF {
						continue
					}
					if _, ok := selfChans[lch]; !ok {
						continue
					}
					peerChans, peerHasAF := peer.info.Endpoints[af]
					if !peerHasAF {
						continue
					}
					for pch, peerEP := range peerChans {
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
							c.initiateProbeHandshake(af, lch, peer.clientID, peerEP)
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

						probeReq := &pb.ProbeRequest{
							ProbeId:        probeID,
							SrcTimestamp:   c.ntp.Now().UnixNano(),
							SrcChannelName: string(lch),
							DstChannelName: string(pch),
						}
						probeReqData, _ := proto.Marshal(probeReq)

						latMu.Lock()
						key := latKey{clientID: peer.clientID, af: af, pair: types.ChannelPair{Local: lch, Peer: pch}}
						sent[key]++
						latMu.Unlock()

						protocol.WriteUDPPacket(probeConn, addr, session, protocol.MsgProbeRequest, probeReqData)
					}
				}
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

			key := latKey{clientID: resp.peerID, af: resp.af, pair: resp.pair}
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
		vlog.Debugf("[Client] probe results: peer=%s af=%s channel=%s>%s latencies=%v sent=%d", key.clientID.Hex()[:8], key.af, key.pair.Local, key.pair.Peer, lats, sent[key])
	}
	for key, s := range sent {
		if _, ok := latencies[key]; !ok {
			vlog.Debugf("[Client] probe results: peer=%s af=%s channel=%s>%s NO RESPONSES sent=%d", key.clientID.Hex()[:8], key.af, key.pair.Local, key.pair.Peer, s)
		}
	}
	latMu.Unlock()

	// Build raw results per peer/(af, channel)
	type rawAFResult struct {
		result *pb.AFProbeResult
		local  *LocalAFProbeResult
	}
	rawResults := make(map[latKey]*rawAFResult)

	for _, peer := range peers {
		for af, chans := range c.Config.AFSettings {
			peerChans, peerHasAF := peer.info.Endpoints[af]
			if !peerHasAF {
				continue
			}
			for lch, cc := range chans {
				for pch := range peerChans {
					key := latKey{clientID: peer.clientID, af: af, pair: types.ChannelPair{Local: lch, Peer: pch}}

					latMu.Lock()
					lats := latencies[key]
					sentCount := sent[key]
					latMu.Unlock()

					pbr := &pb.AFProbeResult{
						AfName:          string(af),
						ChannelName:     string(lch),
						PeerChannelName: string(pch),
						Priority:        int32(cc.Priority),
						ForwardCost:     cc.ForwardCost,
					}
					afr := &LocalAFProbeResult{}

					if sentCount == 0 || len(lats) == 0 {
						pbr.LatencyMean = types.INF_LATENCY
						pbr.PacketLoss = 1.0
						afr.LatencyMean = types.INF_LATENCY
						afr.PacketLoss = 1.0
					} else {
						var sum float64
						for _, l := range lats {
							sum += l
						}
						mean := sum / float64(len(lats))
						var variance float64
						for _, l := range lats {
							diff := l - mean
							variance += diff * diff
						}
						std := math.Sqrt(variance / float64(len(lats)))
						loss := 1.0 - float64(len(lats))/float64(sentCount)

						pbr.LatencyMean = mean
						pbr.LatencyStd = std
						pbr.PacketLoss = loss
						afr.LatencyMean = mean
						afr.LatencyStd = std
						afr.PacketLoss = loss
					}

					rawResults[key] = &rawAFResult{result: pbr, local: afr}
				}
			}
		}
	}

	// Push raw results into ring buffer and compute debounced results
	windowSize := c.Config.ProbeWindowSize

	c.mu.Lock()

	debouncedResults := make(map[latKey]*rawAFResult)

	for key, raw := range rawResults {
		chans, ok := c.Config.AFSettings[key.af]
		if !ok {
			continue
		}
		cc, ok := chans[key.pair.Local]
		if !ok {
			continue
		}

		// packet_loss == 1.0 bypass: don't store in ring buffer, propagate immediately
		if raw.local.PacketLoss >= 1.0 {
			debouncedResults[key] = raw
			continue
		}

		hk := probeHistoryKey{ClientID: key.clientID, AF: key.af, Pair: key.pair}
		history := c.probeHistory[hk]

		history = append(history, raw.local)
		if len(history) > windowSize {
			history = history[len(history)-windowSize:]
		}
		c.probeHistory[hk] = history

		// Find median of means (pick the result whose mean is the median)
		type indexedMean struct {
			idx  int
			mean float64
		}
		var reachable []indexedMean
		for i, h := range history {
			if h.PacketLoss < 1.0 {
				reachable = append(reachable, indexedMean{idx: i, mean: h.LatencyMean})
			}
		}

		if len(reachable) == 0 {
			debouncedResults[key] = raw
			continue
		}

		sort.Slice(reachable, func(i, j int) bool {
			return reachable[i].mean < reachable[j].mean
		})

		medianEntry := history[reachable[len(reachable)/2].idx]

		dbPb := &pb.AFProbeResult{
			AfName:          string(key.af),
			ChannelName:     string(key.pair.Local),
			PeerChannelName: string(key.pair.Peer),
			LatencyMean:     medianEntry.LatencyMean,
			LatencyStd:      medianEntry.LatencyStd,
			PacketLoss:      medianEntry.PacketLoss,
			Priority:        int32(cc.Priority),
			ForwardCost:     cc.ForwardCost,
		}
		dbLocal := &LocalAFProbeResult{
			LatencyMean: medianEntry.LatencyMean,
			LatencyStd:  medianEntry.LatencyStd,
			PacketLoss:  medianEntry.PacketLoss,
		}
		debouncedResults[key] = &rawAFResult{result: dbPb, local: dbLocal}
	}

	// (af, channel pair) hysteresis + final cost computation
	switchCost := c.Config.AFSwitchCost
	for _, peer := range peers {
		// Step 1: compute base cost (quality_cost + forward_cost + per-rule
		// channel_additional_cost, without switch_cost) per (af, pair).
		type afChEntry struct {
			af        types.AFName
			pair      types.ChannelPair
			baseCost  float64 // includes channel_additional_cost
			extraCost float64 // the channel_additional_cost portion alone
		}
		var reachable []afChEntry
		for key, db := range debouncedResults {
			if key.clientID != peer.clientID || db.local.PacketLoss >= 1.0 {
				continue
			}
			qualityCost := db.local.LatencyMean
			extraCost := c.lookupChannelAdditionalCost(peer.info, key.af, key.pair.Peer)
			baseCost := qualityCost + db.result.ForwardCost + extraCost
			reachable = append(reachable, afChEntry{af: key.af, pair: key.pair, baseCost: baseCost, extraCost: extraCost})
		}

		if len(reachable) == 0 {
			// All unreachable — set final_cost = INF on debounced results
			for key, db := range debouncedResults {
				if key.clientID == peer.clientID {
					db.result.FinalCost = types.INF_LATENCY
				}
			}
			continue
		}

		// Step 2: find lowest base cost
		best := reachable[0]
		for _, e := range reachable[1:] {
			if e.baseCost < best.baseCost {
				best = e
			}
		}

		// Step 3: preferred (af, channel pair) hysteresis based on base cost
		curPref, hasPref := c.preferredAFChannel[peer.clientID]
		if !hasPref || curPref.AF == "" {
			c.preferredAFChannel[peer.clientID] = AFChannel{AF: best.af, Pair: best.pair}
		} else {
			prefKey := latKey{clientID: peer.clientID, af: curPref.AF, pair: curPref.Pair}
			prefDB, prefOK := debouncedResults[prefKey]
			if !prefOK || prefDB.local.PacketLoss >= 1.0 {
				c.preferredAFChannel[peer.clientID] = AFChannel{AF: best.af, Pair: best.pair}
			} else {
				prefQuality := prefDB.local.LatencyMean
				prefExtra := c.lookupChannelAdditionalCost(peer.info, curPref.AF, curPref.Pair.Peer)
				prefBaseCost := prefQuality + prefDB.result.ForwardCost + prefExtra
				if prefBaseCost-best.baseCost > switchCost {
					c.preferredAFChannel[peer.clientID] = AFChannel{AF: best.af, Pair: best.pair}
				}
			}
		}

		// Step 4: set quality_cost, switch_cost and compute final_cost.
		// Bake the per-rule channel_additional_cost into final_cost so the
		// controller's Floyd-Warshall and every other client see the same
		// asymmetric cost we use locally for hysteresis.
		pref := c.preferredAFChannel[peer.clientID]
		for key, db := range debouncedResults {
			if key.clientID != peer.clientID {
				continue
			}
			qualityCost := db.local.LatencyMean
			extraCost := c.lookupChannelAdditionalCost(peer.info, key.af, key.pair.Peer)
			baseCost := qualityCost + db.result.ForwardCost + extraCost
			db.result.QualityCost = qualityCost
			if key.af == pref.AF && key.pair == pref.Pair {
				db.result.SwitchCost = 0
				db.result.FinalCost = baseCost
			} else {
				db.result.SwitchCost = switchCost
				db.result.FinalCost = baseCost + switchCost
			}
		}
	}

	c.mu.Unlock()

	// Build ProbeResults proto
	results := &pb.ProbeResults{
		ProbeId:        probeID,
		SourceClientId: c.ClientID[:],
		Results:        make(map[string]*pb.ProbeResultEntry),
	}

	for _, peer := range peers {
		entry := &pb.ProbeResultEntry{}

		for key, raw := range rawResults {
			if key.clientID != peer.clientID {
				continue
			}
			entry.AfResults = append(entry.AfResults, raw.result)
		}
		for key, db := range debouncedResults {
			if key.clientID != peer.clientID {
				continue
			}
			entry.DebouncedAfResults = append(entry.DebouncedAfResults, db.result)
		}

		results.Results[peer.clientID.Hex()] = entry
	}

	// Save local probe results for API
	c.mu.Lock()
	c.lastProbeTime = time.Now()
	c.lastProbeResults = make(map[types.ClientID]*LocalProbeResult)
	c.lastDebouncedResults = make(map[types.ClientID]*LocalProbeResult)
	for _, peer := range peers {
		lpr := &LocalProbeResult{AFResults: make(map[types.AFName]map[types.ChannelPair]*LocalAFProbeResult)}
		dlpr := &LocalProbeResult{AFResults: make(map[types.AFName]map[types.ChannelPair]*LocalAFProbeResult)}
		for key, raw := range rawResults {
			if key.clientID != peer.clientID {
				continue
			}
			if _, ok := lpr.AFResults[key.af]; !ok {
				lpr.AFResults[key.af] = make(map[types.ChannelPair]*LocalAFProbeResult)
			}
			lpr.AFResults[key.af][key.pair] = raw.local
		}
		for key, db := range debouncedResults {
			if key.clientID != peer.clientID {
				continue
			}
			if _, ok := dlpr.AFResults[key.af]; !ok {
				dlpr.AFResults[key.af] = make(map[types.ChannelPair]*LocalAFProbeResult)
			}
			dlpr.AFResults[key.af][key.pair] = db.local
		}
		c.lastProbeResults[peer.clientID] = lpr
		c.lastDebouncedResults[peer.clientID] = dlpr
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

// lookupChannelAdditionalCost returns the sum of every channel_additional_costs
// rule that matches (peer's client_name, af, peer's isp_name-on-this-channel).
// "*" matches any value, empty rule field is treated as "*".
// Falls back to channel_name when the peer didn't advertise an isp_name.
//
// Must be called with c.mu held (reads c.Config which is immutable, but
// access via peer.info is shared).
func (c *Client) lookupChannelAdditionalCost(peer *ClientInfoView, af types.AFName, ch types.ChannelName) float64 {
	if len(c.Config.ChannelAdditionalCosts) == 0 {
		return 0
	}
	isp := ""
	if peer != nil {
		if chs, ok := peer.Endpoints[af]; ok {
			if ep, ok2 := chs[ch]; ok2 {
				isp = ep.IspName
			}
		}
	}
	if isp == "" {
		isp = string(ch)
	}
	peerName := ""
	if peer != nil {
		peerName = peer.ClientName
	}
	total := 0.0
	for _, rule := range c.Config.ChannelAdditionalCosts {
		if !matchRule(rule.Peer, peerName) {
			continue
		}
		if !matchRule(rule.AF, string(af)) {
			continue
		}
		if !matchRule(rule.ISP, isp) {
			continue
		}
		total += rule.Cost
	}
	return total
}

// matchRule returns true when pattern == "*" / "" or pattern == value.
func matchRule(pattern, value string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	return pattern == value
}

func (c *Client) initiateProbeHandshake(af types.AFName, ch types.ChannelName, peerID types.ClientID, ep *types.Endpoint) {
	chans, ok := c.probeConns[af]
	if !ok {
		return
	}
	probeConn, ok := chans[ch]
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
