// Package sockopt provides per-(af, channel) socket option helpers.
//
// SO_BINDTODEVICE binds a socket to a specific interface so all egress
// goes via that link regardless of routing tables. The same name is passed
// to vxlan device creation (IFLA_VXLAN_LINK) so the data plane is bound
// end-to-end, not just the control plane.
//
// SO_MARK / fwmark is intentionally not supported here: the kernel VXLAN
// driver has no SO_MARK option, so marking the control channel only would
// leave data plane silently misrouted.
//
// SO_BINDTODEVICE requires CAP_NET_RAW/CAP_NET_ADMIN; the rest of the
// controller already needs netlink+nftables privileges anyway.
package sockopt

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Options bundles per-channel socket overrides. Empty means "leave default".
type Options struct {
	BindDevice string // SO_BINDTODEVICE, e.g. "ei1-v4"
}

// Empty reports whether no socket-level overrides should be applied.
func (o Options) Empty() bool {
	return o.BindDevice == ""
}

// Apply sets the configured options on a raw fd.
// Safe to call with Options{}; in that case it is a no-op.
func Apply(fd uintptr, o Options) error {
	if o.BindDevice != "" {
		if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, o.BindDevice); err != nil {
			return fmt.Errorf("SO_BINDTODEVICE %q: %w", o.BindDevice, err)
		}
	}
	return nil
}

// SetTCPUserTimeout sets TCP_USER_TIMEOUT on an established TCP connection: the
// kernel fails a write whose data stays unacknowledged for longer than d,
// instead of waiting out tcp_retries2 (~15 min). Crucially — unlike TCP
// keepalive — this is NOT suppressed by other in-flight data, so a control
// write to a silently-dead link (e.g. a probe broadcast to a standby channel
// whose ISP went down with no RST) errors within d and lets the sender tear
// the connection down. Best-effort: a nil/ non-TCP conn is a no-op.
func SetTCPUserTimeout(conn net.Conn, d time.Duration) error {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(d.Milliseconds()))
	}); err != nil {
		return err
	}
	return serr
}

// ControlFn returns a function suitable for net.Dialer.Control /
// net.ListenConfig.Control. It applies the options before connect()/bind().
func ControlFn(o Options) func(network, address string, c syscall.RawConn) error {
	if o.Empty() {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var applyErr error
		if err := c.Control(func(fd uintptr) {
			applyErr = Apply(fd, o)
		}); err != nil {
			return err
		}
		return applyErr
	}
}
