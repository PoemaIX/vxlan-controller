package filter

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"vxlan-controller/pkg/vlog"

	"net/netip"

	"github.com/vishvananda/netlink"
	lua "github.com/yuin/gopher-lua"
	"golang.org/x/sys/unix"
)

// AddrSelectEngine wraps a Lua VM for address selection.
// The Lua script must define a global function select(info) returning a string IP or nil.
type AddrSelectEngine struct {
	mu       sync.Mutex
	vm       *lua.LState
	selectFn *lua.LFunction
}

// AddrInfo represents one address on an interface, passed to the Lua select function.
type AddrInfo struct {
	IP          string
	PrefixLen   int
	Scope       int
	Deprecated  bool
	ValidLft    int // seconds remaining, 0 = forever
	PreferedLft int // seconds remaining, 0 = forever
}

// NewAddrSelectEngine creates an engine from a Lua script string.
func NewAddrSelectEngine(script string) (*AddrSelectEngine, error) {
	code := script
	if strings.HasPrefix(script, "@") {
		data, err := os.ReadFile(script[1:])
		if err != nil {
			return nil, fmt.Errorf("load addr_select script %s: %w", script[1:], err)
		}
		code = string(data)
	}

	vm := lua.NewState(lua.Options{SkipOpenLibs: true})
	lua.OpenBase(vm)
	lua.OpenString(vm)
	lua.OpenMath(vm)
	lua.OpenTable(vm)

	if err := vm.DoString(code); err != nil {
		vm.Close()
		return nil, fmt.Errorf("compile addr_select script: %w", err)
	}

	fn := vm.GetGlobal("select")
	selectFn, ok := fn.(*lua.LFunction)
	if !ok {
		vm.Close()
		return nil, fmt.Errorf("addr_select script must define a global function 'select'")
	}

	return &AddrSelectEngine{
		vm:       vm,
		selectFn: selectFn,
	}, nil
}

// Select calls the Lua select function with the given address list and previous IP.
// Returns the selected IP string, or "" if Lua returns nil.
func (e *AddrSelectEngine) Select(addrs []AddrInfo, prevIP string, iface string) string {
	e.mu.Lock()
	defer e.mu.Unlock()

	info := e.vm.NewTable()

	addrsTable := e.vm.NewTable()
	for i, a := range addrs {
		entry := e.vm.NewTable()
		entry.RawSetString("ip", lua.LString(a.IP))
		entry.RawSetString("prefix_len", lua.LNumber(a.PrefixLen))
		entry.RawSetString("scope", lua.LNumber(a.Scope))
		entry.RawSetString("deprecated", lua.LBool(a.Deprecated))
		entry.RawSetString("valid_lft", lua.LNumber(a.ValidLft))
		entry.RawSetString("prefered_lft", lua.LNumber(a.PreferedLft))
		addrsTable.RawSetInt(i+1, entry)
	}
	info.RawSetString("addrs", addrsTable)
	info.RawSetString("prev_ip", lua.LString(prevIP))
	info.RawSetString("iface", lua.LString(iface))

	if err := e.vm.CallByParam(lua.P{
		Fn:      e.selectFn,
		NRet:    1,
		Protect: true,
	}, info); err != nil {
		vlog.Errorf("[AddrWatch] Lua select error: %v", err)
		return ""
	}

	ret := e.vm.Get(-1)
	e.vm.Pop(1)

	if s, ok := ret.(lua.LString); ok {
		return string(s)
	}
	return ""
}

// Close releases the Lua VM.
func (e *AddrSelectEngine) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.vm.Close()
}

// GetInterfaceAddrs retrieves addresses from the given interface for Lua addr selection.
func GetInterfaceAddrs(ifaceName string, af string) []AddrInfo {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil
	}

	family := unix.AF_UNSPEC
	addrList, err := netlink.AddrList(link, family)
	if err != nil {
		vlog.Warnf("[AddrWatch] AF=%s: AddrList(%s) error: %v", af, ifaceName, err)
		return nil
	}

	var result []AddrInfo
	for _, a := range addrList {
		if a.IP == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		ones, _ := a.Mask.Size()
		result = append(result, AddrInfo{
			IP:          ip.String(),
			PrefixLen:   ones,
			Scope:       int(a.Scope),
			Deprecated:  a.Flags&unix.IFA_F_DEPRECATED != 0,
			ValidLft:    a.ValidLft,
			PreferedLft: a.PreferedLft,
		})
	}
	return result
}
