package client

import (
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"vxlan-controller/pkg/protocol"
	"vxlan-controller/pkg/vlog"

	pb "vxlan-controller/proto"
)

const maxDetailsPerReason = 64

// McastStats tracks per-source-MAC multicast packet counts.
type McastStats struct {
	mu   sync.Mutex
	macs map[string]*macCounters // key: src MAC string
}

type macCounters struct {
	txAccepted uint64
	txRejected map[string]*rejectEntry // reason -> entry
	rxAccepted uint64
	rxRejected map[string]*rejectEntry
}

type rejectEntry struct {
	count   uint64
	details map[string]uint64 // detail string -> count (deduped)
}

func newMcastStats() *McastStats {
	return &McastStats{
		macs: make(map[string]*macCounters),
	}
}

func (ms *McastStats) get(mac string) *macCounters {
	mc, ok := ms.macs[mac]
	if !ok {
		mc = &macCounters{
			txRejected: make(map[string]*rejectEntry),
			rxRejected: make(map[string]*rejectEntry),
		}
		ms.macs[mac] = mc
	}
	return mc
}

func recordReject(m map[string]*rejectEntry, reason, detail string) {
	re, ok := m[reason]
	if !ok {
		re = &rejectEntry{details: make(map[string]uint64)}
		m[reason] = re
	}
	re.count++
	if detail != "" {
		if len(re.details) < maxDetailsPerReason || re.details[detail] > 0 {
			re.details[detail]++
		}
	}
}

// RecordTx records an outbound (tap → controller) mcast result.
func (ms *McastStats) RecordTx(frame []byte, accepted bool, reason, detail string) {
	if len(frame) < 14 {
		return
	}
	srcMAC := net.HardwareAddr(frame[6:12]).String()

	ms.mu.Lock()
	mc := ms.get(srcMAC)
	if accepted {
		mc.txAccepted++
	} else {
		recordReject(mc.txRejected, reason, detail)
	}
	ms.mu.Unlock()
}

// RecordRx records an inbound (controller → tap) mcast result.
func (ms *McastStats) RecordRx(frame []byte, accepted bool, reason, detail string) {
	if len(frame) < 14 {
		return
	}
	srcMAC := net.HardwareAddr(frame[6:12]).String()

	ms.mu.Lock()
	mc := ms.get(srcMAC)
	if accepted {
		mc.rxAccepted++
	} else {
		recordReject(mc.rxRejected, reason, detail)
	}
	ms.mu.Unlock()
}

func buildRejectReasons(m map[string]*rejectEntry, direction string) (uint64, []*pb.McastRejectReason) {
	var total uint64
	var reasons []*pb.McastRejectReason
	for reason, re := range m {
		total += re.count
		rr := &pb.McastRejectReason{
			Direction: direction,
			Reason:    reason,
			Count:     re.count,
		}
		for detail, cnt := range re.details {
			rr.Details = append(rr.Details, &pb.McastRejectDetail{
				Detail: detail,
				Count:  cnt,
			})
		}
		reasons = append(reasons, rr)
	}
	return total, reasons
}

// snapshotAndReset returns the current stats and resets all counters.
func (ms *McastStats) snapshotAndReset() []*pb.MACMcastStats {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	var result []*pb.MACMcastStats
	for mac, mc := range ms.macs {
		hwAddr, err := net.ParseMAC(mac)
		if err != nil {
			continue
		}

		txRejected, txReasons := buildRejectReasons(mc.txRejected, "tx")
		rxRejected, rxReasons := buildRejectReasons(mc.rxRejected, "rx")

		entry := &pb.MACMcastStats{
			Mac:            hwAddr,
			TxAccepted:     mc.txAccepted,
			TxRejected:     txRejected,
			RxAccepted:     mc.rxAccepted,
			RxRejected:     rxRejected,
			RejectReasons:  append(txReasons, rxReasons...),
		}
		result = append(result, entry)
	}

	// Reset
	ms.macs = make(map[string]*macCounters)

	return result
}

// mcastStatsReportLoop periodically sends mcast stats to all controllers.
func (c *Client) mcastStatsReportLoop() {
	if c.Config.StatsInterval <= 0 {
		return
	}
	ticker := time.NewTicker(c.Config.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			stats := c.mcastStats.snapshotAndReset()
			if len(stats) == 0 {
				continue
			}

			report := &pb.McastStatsReport{
				MacStats: stats,
			}
			data, err := proto.Marshal(report)
			if err != nil {
				continue
			}

			msg := clientEncodeMessage(protocol.MsgMcastStatsReport, data)
			c.mu.Lock()
			for _, cc := range c.Controllers {
				select {
				case cc.SendQueue <- ClientQueueItem{Message: msg}:
				default:
				}
			}
			c.mu.Unlock()

			vlog.Verbosef("[Client] mcast stats report sent (%d MACs)", len(stats))
		case <-c.ctx.Done():
			return
		}
	}
}
