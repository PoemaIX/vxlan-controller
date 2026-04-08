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
	default:
		vxccliUsage()
		os.Exit(1)
	}
}

func vxccliUsage() {
	fmt.Fprintln(os.Stderr, "Usage: vxlan-controller --mode vxccli [--sock <path>] <command>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  af list             List address families and bind addresses")
	fmt.Fprintln(os.Stderr, "  af get <af>         Get bind address for an AF")
	fmt.Fprintln(os.Stderr, "  af set <af> <addr>  Set bind address (non-autoip only)")
	fmt.Fprintln(os.Stderr, "  peer list           List peers with endpoints and probe results")
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
