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
	"syscall"

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
