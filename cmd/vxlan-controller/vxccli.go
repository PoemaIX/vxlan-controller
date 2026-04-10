package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"

	"vxlan-controller/pkg/apisock"
	"vxlan-controller/pkg/config"
)

func runVxccli(sockPath string, args []string) {
	if sockPath == "" {
		sockPath = config.DefaultClientSocket
	}

	if len(args) < 1 {
		vxccliUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "af":
		if len(args) < 2 {
			vxccliUsage()
			os.Exit(1)
		}
		switch args[1] {
		case "list":
			vxccliAFList(sockPath)
		case "get":
			if len(args) < 3 {
				fmt.Fprintln(os.Stderr, "Usage: vxccli af get <af_name>")
				os.Exit(1)
			}
			vxccliAFGet(sockPath, args[2])
		case "set":
			if len(args) < 4 {
				fmt.Fprintln(os.Stderr, "Usage: vxccli af set <af_name> <addr>")
				os.Exit(1)
			}
			vxccliAFSet(sockPath, args[2], args[3])
		default:
			vxccliUsage()
			os.Exit(1)
		}
	case "peer":
		if len(args) < 2 {
			vxccliUsage()
			os.Exit(1)
		}
		switch args[1] {
		case "list":
			vxccliPeerList(sockPath)
		default:
			vxccliUsage()
			os.Exit(1)
		}
	case "show":
		if len(args) < 2 {
			vxccliUsage()
			os.Exit(1)
		}
		switch args[1] {
		case "controller":
			vxccliShowController(sockPath)
		case "route":
			if len(args) >= 4 && args[2] == "controller" {
				vxccliShowRoute(sockPath, args[3])
			} else {
				vxccliShowRoute(sockPath, "")
			}
		default:
			vxccliUsage()
			os.Exit(1)
		}
	default:
		vxccliUsage()
		os.Exit(1)
	}
}

func vxccliUsage() {
	fmt.Fprintln(os.Stderr, "Usage: vxlan-controller --mode vxccli [--sock <path>] <command>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  show controller                    Show controller connection states")
	fmt.Fprintln(os.Stderr, "  show route                         Show route table (from authority)")
	fmt.Fprintln(os.Stderr, "  show route controller <id>         Show route table from a specific controller")
	fmt.Fprintln(os.Stderr, "  af list                            List address families and bind addresses")
	fmt.Fprintln(os.Stderr, "  af get <af>                        Get bind address for an AF")
	fmt.Fprintln(os.Stderr, "  af set <af> <addr>                 Set bind address (non-autoip only)")
	fmt.Fprintln(os.Stderr, "  peer list                          List peers with endpoints and probe results")
}

type afInfoResult struct {
	AF       string `json:"af"`
	BindAddr string `json:"bind_addr"`
	AutoIP   string `json:"autoip,omitempty"`
}

func vxccliAFList(sockPath string) {
	raw, err := apisock.Call(sockPath, "af.list", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result []afInfoResult
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(result) == 0 {
		fmt.Println("(no address families)")
		return
	}

	for _, af := range result {
		if af.AutoIP != "" {
			fmt.Printf("%s: %s (autoip: %s)\n", af.AF, af.BindAddr, af.AutoIP)
		} else {
			fmt.Printf("%s: %s (static)\n", af.AF, af.BindAddr)
		}
	}
}

func vxccliAFGet(sockPath string, afName string) {
	raw, err := apisock.Call(sockPath, "af.get", map[string]string{"af": afName})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result afInfoResult
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}

	if result.AutoIP != "" {
		fmt.Printf("%s: %s (autoip: %s)\n", result.AF, result.BindAddr, result.AutoIP)
	} else {
		fmt.Printf("%s: %s (static)\n", result.AF, result.BindAddr)
	}
}

func vxccliAFSet(sockPath string, afName, addr string) {
	raw, err := apisock.Call(sockPath, "af.set", map[string]string{"af": afName, "addr": addr})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result map[string]string
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s: %s\n", result["af"], result["bind_addr"])
}

type peerListResult struct {
	ClientID   string                          `json:"client_id"`
	ClientName string                          `json:"client_name"`
	Endpoints  map[string]*peerEndpointResult  `json:"endpoints"`
	LastSeen   string                          `json:"last_seen"`
	Probe      *peerProbeResult                `json:"probe,omitempty"`
}

type peerEndpointResult struct {
	IP        string `json:"ip"`
	ProbePort uint16 `json:"probe_port"`
}

type peerProbeResult struct {
	Time      string                            `json:"time"`
	AFResults map[string]*peerAFProbeResultCLI  `json:"af_results"`
}

type peerAFProbeResultCLI struct {
	LatencyMean float64 `json:"latency_mean"`
	LatencyStd  float64 `json:"latency_std"`
	PacketLoss  float64 `json:"packet_loss"`
}

func vxccliPeerList(sockPath string) {
	raw, err := apisock.Call(sockPath, "peer.list", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result []peerListResult
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(result) == 0 {
		fmt.Println("(no peers)")
		return
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].ClientName != result[j].ClientName {
			return result[i].ClientName < result[j].ClientName
		}
		return result[i].ClientID < result[j].ClientID
	})

	for _, peer := range result {
		name := peer.ClientName
		if name == "" {
			name = peer.ClientID
		}
		fmt.Printf("%s (%s)  last_seen=%s\n", name, peer.ClientID, peer.LastSeen)

		for _, af := range sortedKeys(peer.Endpoints) {
			ep := peer.Endpoints[af]
			fmt.Printf("  %s: %s\n", af, net.JoinHostPort(ep.IP, strconv.Itoa(int(ep.ProbePort))))
		}

		if peer.Probe != nil {
			fmt.Printf("  probe_time=%s\n", peer.Probe.Time)
			for _, af := range sortedKeys(peer.Probe.AFResults) {
				pr := peer.Probe.AFResults[af]
				if pr.PacketLoss >= 1.0 {
					fmt.Printf("    %s: unreachable\n", af)
				} else {
					lossStr := fmt.Sprintf("%.0f%%", pr.PacketLoss*100)
					fmt.Printf("    %s: mean=%.2fms std=%.2fms loss=%s\n", af, pr.LatencyMean, pr.LatencyStd, lossStr)
				}
			}
		} else {
			fmt.Printf("  (no probe data)\n")
		}
	}
}

type showControllerEntry struct {
	ControllerID string                          `json:"controller_id"`
	State        string                          `json:"state"`
	IsAuthority  bool                            `json:"is_authority"`
	ActiveAF     string                          `json:"active_af"`
	Synced       bool                            `json:"synced"`
	MACsSynced   bool                            `json:"macs_synced"`
	ClientCount  int                             `json:"client_count"`
	Endpoints    map[string]*showCtrlEndpointCLI `json:"endpoints"`
}

type showCtrlEndpointCLI struct {
	Addr      string `json:"addr"`
	Connected bool   `json:"connected"`
}

func vxccliShowController(sockPath string) {
	raw, err := apisock.Call(sockPath, "show.controller", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result []showControllerEntry
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(result) == 0 {
		fmt.Println("(no controllers)")
		return
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ControllerID < result[j].ControllerID
	})

	for _, c := range result {
		authStr := ""
		if c.IsAuthority {
			authStr = " *"
		}
		syncStr := ""
		if !c.Synced {
			syncStr = " (not synced)"
		}
		macStr := ""
		if !c.MACsSynced {
			macStr = " (MACs not synced)"
		}
		fmt.Printf("%-16s  %-12s af=%s clients=%d%s%s%s\n",
			c.ControllerID, c.State, c.ActiveAF, c.ClientCount, authStr, syncStr, macStr)
		for _, af := range sortedKeys(c.Endpoints) {
			ep := c.Endpoints[af]
			connStr := "down"
			if ep.Connected {
				connStr = "up"
			}
			fmt.Printf("  %s: %s (%s)\n", af, ep.Addr, connStr)
		}
	}
}

type showRouteCLIEntry struct {
	MAC        string              `json:"mac"`
	IP         string              `json:"ip,omitempty"`
	Owners     []showRouteOwnerCLI `json:"owners"`
	NextHop    string              `json:"nexthop,omitempty"`
	NextHopIP  string              `json:"nexthop_ip,omitempty"`
	AF         string              `json:"af,omitempty"`
	Installed  bool                `json:"installed"`
	Controller string              `json:"controller,omitempty"`
}

type showRouteOwnerCLI struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Selected   bool   `json:"selected"`
}

func vxccliShowRoute(sockPath string, ctrlID string) {
	var params interface{}
	if ctrlID != "" {
		params = map[string]string{"controller": ctrlID}
	}

	raw, err := apisock.Call(sockPath, "show.route", params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result []showRouteCLIEntry
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(result) == 0 {
		fmt.Println("(no routes)")
		return
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].MAC < result[j].MAC
	})

	for _, r := range result {
		// Build owner string, marking selected owner with *
		ownerNames := make([]string, 0, len(r.Owners))
		for _, o := range r.Owners {
			name := o.ClientName
			if name == "" {
				name = o.ClientID
			}
			if o.Selected {
				name = "*" + name
			}
			ownerNames = append(ownerNames, name)
		}
		sort.Strings(ownerNames)

		ipStr := ""
		if r.IP != "" {
			ipStr = " " + r.IP
		}

		// Build nexthop info
		nhStr := ""
		if r.NextHop != "" {
			nhStr = fmt.Sprintf("  nhop=%s(%s) af=%s", r.NextHop, r.NextHopIP, r.AF)
		}

		// Installed status
		fdbStr := ""
		if !r.Installed {
			if r.NextHop == "" {
				fdbStr = "  [no route]"
			} else {
				fdbStr = "  [not installed]"
			}
		}

		fmt.Printf("%-20s%s  via %s%s%s\n", r.MAC, ipStr, joinStrings(ownerNames, ", "), nhStr, fdbStr)
	}
}

