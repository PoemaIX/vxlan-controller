package ntp

import (
	"sort"
	"sync"
	"time"

	"github.com/beevik/ntp"

	"vxlan-controller/pkg/vlog"
)

// TimeSync manages NTP time offset correction.
type TimeSync struct {
	mu           sync.RWMutex
	offset       time.Duration
	servers      []string
	rttThreshold time.Duration // max acceptable RTT; 0 = no limit
}

func New(servers []string, rttThreshold time.Duration) *TimeSync {
	return &TimeSync{servers: servers, rttThreshold: rttThreshold}
}

// Sync queries all NTP servers, trims outliers if >4 results, and averages.
func (ts *TimeSync) Sync() error {
	var offsets []time.Duration

	for _, server := range ts.servers {
		resp, err := ntp.Query(server)
		if err != nil {
			vlog.Warnf("[NTP] query %s failed: %v", server, err)
			continue
		}
		if err := resp.Validate(); err != nil {
			vlog.Warnf("[NTP] validate %s failed: %v", server, err)
			continue
		}
		if ts.rttThreshold > 0 && resp.RTT > ts.rttThreshold {
			vlog.Debugf("[NTP] %s: RTT %v exceeds threshold %v, skipping", server, resp.RTT, ts.rttThreshold)
			continue
		}
		vlog.Debugf("[NTP] %s: offset=%v rtt=%v stratum=%d", server, resp.ClockOffset, resp.RTT, resp.Stratum)
		offsets = append(offsets, resp.ClockOffset)
	}

	if len(offsets) == 0 {
		vlog.Warnf("[NTP] no servers responded, keeping current offset")
		return nil
	}

	// Sort for trimming
	sort.Slice(offsets, func(i, j int) bool {
		return offsets[i] < offsets[j]
	})

	// Trim highest and lowest if >4 results
	trimmed := offsets
	if len(offsets) > 4 {
		trimmed = offsets[1 : len(offsets)-1]
	}

	// Average
	var sum time.Duration
	for _, o := range trimmed {
		sum += o
	}
	avg := sum / time.Duration(len(trimmed))

	ts.mu.Lock()
	ts.offset = avg
	ts.mu.Unlock()

	vlog.Debugf("[NTP] synced: %d/%d servers responded, offset=%v (used %d after trim)",
		len(offsets), len(ts.servers), avg, len(trimmed))
	return nil
}

// Now returns the corrected current time.
func (ts *TimeSync) Now() time.Time {
	ts.mu.RLock()
	offset := ts.offset
	ts.mu.RUnlock()
	return time.Now().Add(offset)
}

// Offset returns the current NTP offset.
func (ts *TimeSync) Offset() time.Duration {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.offset
}

// RunLoop periodically syncs NTP. Call in a goroutine.
func (ts *TimeSync) RunLoop(interval time.Duration, stop <-chan struct{}) {
	// Initial sync
	ts.Sync()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ts.Sync()
		case <-stop:
			return
		}
	}
}
