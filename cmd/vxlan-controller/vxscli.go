package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"vxlan-controller/pkg/apisock"
	"vxlan-controller/pkg/config"
)

func runVxscli(sockPath string, args []string) {
	if sockPath == "" {
		sockPath = config.DefaultControllerSocket
	}

	if len(args) < 1 {
		vxscliUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "cost":
		if len(args) < 2 {
			vxscliUsage()
			os.Exit(1)
		}
		switch args[1] {
		case "get":
			vxscliCostGet(sockPath)
		case "getmode":
			vxscliCostGetMode(sockPath)
		case "setmode":
			if len(args) < 3 {
				fmt.Fprintln(os.Stderr, "Usage: vxscli cost setmode <probe|static>")
				os.Exit(1)
			}
			vxscliCostSetMode(sockPath, args[2])
		case "store":
			vxscliCostStore(sockPath)
		default:
			vxscliUsage()
			os.Exit(1)
		}
	case "show":
		if len(args) < 2 {
			vxscliUsage()
			os.Exit(1)
		}
		switch args[1] {
		case "client":
			vxscliShowClient(sockPath)
		case "route":
			if len(args) >= 4 && args[2] == "client" {
				vxscliShowRoute(sockPath, args[3])
			} else {
				vxscliShowRoute(sockPath, "")
			}
		case "sync":
			vxscliShowSync(sockPath)
		default:
			vxscliUsage()
			os.Exit(1)
		}
	default:
		vxscliUsage()
		os.Exit(1)
	}
}

func vxscliUsage() {
	fmt.Fprintln(os.Stderr, "Usage: vxlan-controller --mode vxscli [--sock <path>] <command>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  show client                      Show connected clients")
	fmt.Fprintln(os.Stderr, "  show route                       Show route table")
	fmt.Fprintln(os.Stderr, "  show route client <name>         Show routes for a specific client")
	fmt.Fprintln(os.Stderr, "  show sync                        Per-client sync health (seqid, last-recv age, conns)")
	fmt.Fprintln(os.Stderr, "  cost get                         Show cost matrix")
	fmt.Fprintln(os.Stderr, "  cost getmode                     Show current cost mode")
	fmt.Fprintln(os.Stderr, "  cost setmode <probe|static>      Set cost mode")
	fmt.Fprintln(os.Stderr, "  cost store                       Save current costs to config")
}

type afCostInfo struct {
	Mean        float64          `json:"mean"`
	Std         float64          `json:"std"`
	PacketLoss  float64          `json:"packet_loss"`
	Priority    int              `json:"priority"`
	ForwardCost float64          `json:"forward_cost"`
	TotalCost   float64          `json:"total_cost"`
	Debounced   *afCostDebounced `json:"debounced,omitempty"`
}

type afCostDebounced struct {
	Mean       float64 `json:"mean"`
	Std        float64 `json:"std"`
	PacketLoss float64 `json:"packet_loss"`
	SwitchCost float64 `json:"switch_cost"`
	TotalCost  float64 `json:"total_cost"`
}

type costGetResult struct {
	CostMode string                                                  `json:"cost_mode"`
	Matrix   map[string]map[string]map[string]map[string]*afCostInfo `json:"matrix"` // src/dst/af/channel
}

func vxscliCostGet(sockPath string) {
	raw, err := apisock.Call(sockPath, "cost.get", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result costGetResult
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("cost mode: %s\n", result.CostMode)

	if len(result.Matrix) == 0 {
		fmt.Println("\n(no cost data)")
		return
	}

	// Sort sources
	srcs := sortedKeys(result.Matrix)
	for _, src := range srcs {
		dsts := result.Matrix[src]
		dstNames := sortedKeys(dsts)
		for _, dst := range dstNames {
			fmt.Printf("\n%s -> %s:\n", src, dst)
			afs := dsts[dst]
			afNames := sortedKeys(afs)
			for _, af := range afNames {
				chans := afs[af]
				chNames := sortedKeys(chans)
				for _, ch := range chNames {
					info := chans[ch]
					lossStr := fmt.Sprintf("%.2f", info.PacketLoss)
					if info.PacketLoss >= 1.0 {
						lossStr = "1.00 (unreachable)"
					}
					label := af + "/" + ch
					fmt.Printf("  %s: cost=%.2f mean=%.2f std=%.2f loss=%s prio=%d fwd=%.2f\n",
						label, info.TotalCost, info.Mean, info.Std, lossStr, info.Priority, info.ForwardCost)
					if info.Debounced != nil {
						dbLossStr := fmt.Sprintf("%.2f", info.Debounced.PacketLoss)
						if info.Debounced.PacketLoss >= 1.0 {
							dbLossStr = "1.00 (unreachable)"
						}
						fmt.Printf("  %s(debounced): cost=%.2f mean=%.2f std=%.2f loss=%s sw=%.0f\n",
							label, info.Debounced.TotalCost, info.Debounced.Mean, info.Debounced.Std, dbLossStr, info.Debounced.SwitchCost)
					}
				}
			}
		}
	}
}

func vxscliCostGetMode(sockPath string) {
	raw, err := apisock.Call(sockPath, "cost.getmode", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result map[string]string
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(result["mode"])
}

func vxscliCostSetMode(sockPath string, mode string) {
	raw, err := apisock.Call(sockPath, "cost.setmode", map[string]string{"mode": mode})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result map[string]string
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("cost mode set to: %s\n", result["mode"])
}

func vxscliCostStore(sockPath string) {
	raw, err := apisock.Call(sockPath, "cost.store", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result map[string]int
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("stored %d cost entries to config\n", result["entries"])
}

type showClientEntry struct {
	ClientID      string                       `json:"client_id"`
	ClientName    string                       `json:"client_name"`
	Online        bool                         `json:"online"`
	LastSeen      string                       `json:"last_seen"`
	Endpoints     map[string]*showEndpointInfo `json:"endpoints"` // key: "af/channel"
	ActiveAF      string                       `json:"active_af"`
	ActiveChannel string                       `json:"active_channel"`
	Synced        bool                         `json:"synced"`
	RouteCount    int                          `json:"route_count"`
}

type showEndpointInfo struct {
	IP string `json:"ip"`
}

func vxscliShowClient(sockPath string) {
	raw, err := apisock.Call(sockPath, "show.client", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result []showClientEntry
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(result) == 0 {
		fmt.Println("(no clients)")
		return
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].ClientName != result[j].ClientName {
			return result[i].ClientName < result[j].ClientName
		}
		return result[i].ClientID < result[j].ClientID
	})

	for _, c := range result {
		name := c.ClientName
		if name == "" {
			name = c.ClientID
		}
		state := "up"
		if !c.Online {
			state = "down"
		}
		syncStr := ""
		if !c.Synced {
			syncStr = " (not synced)"
		}
		activeLabel := c.ActiveAF
		if c.ActiveChannel != "" {
			activeLabel = c.ActiveAF + "/" + c.ActiveChannel
		}
		fmt.Printf("%-20s %-6s id=%s active=%s routes=%d%s\n",
			name, state, c.ClientID, activeLabel, c.RouteCount, syncStr)
		for _, key := range sortedKeys(c.Endpoints) {
			ep := c.Endpoints[key]
			fmt.Printf("  %s: %s\n", key, ep.IP)
		}
		fmt.Printf("  last_seen=%s\n", c.LastSeen)
	}
}

type showRouteEntry struct {
	MAC    string           `json:"mac"`
	IP     string           `json:"ip,omitempty"`
	Owners []showRouteOwner `json:"owners"`
}

type showRouteOwner struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
}

func vxscliShowRoute(sockPath string, clientName string) {
	var params interface{}
	if clientName != "" {
		params = map[string]string{"client": clientName}
	}

	raw, err := apisock.Call(sockPath, "show.route", params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result []showRouteEntry
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
		ownerNames := make([]string, 0, len(r.Owners))
		for _, o := range r.Owners {
			if o.ClientName != "" {
				ownerNames = append(ownerNames, o.ClientName)
			} else {
				ownerNames = append(ownerNames, o.ClientID)
			}
		}
		sort.Strings(ownerNames)

		ipStr := ""
		if r.IP != "" {
			ipStr = " " + r.IP
		}
		fmt.Printf("%-20s%s  via %s\n", r.MAC, ipStr, joinStrings(ownerNames, ", "))
	}
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for _, s := range strs[1:] {
		result += sep + s
	}
	return result
}

type ctrlSyncEntry struct {
	ClientName    string `json:"client_name"`
	ClientID      string `json:"client_id"`
	Synced        bool   `json:"synced"`
	ActiveAF      string `json:"active_af"`
	ActiveChannel string `json:"active_channel"`
	RecvSessionID string `json:"recv_session_id"`
	RecvSeqid     uint64 `json:"recv_seqid"`
	LastRecvAgoMs int64  `json:"last_recv_ago_ms"`
	LastSeenAgoMs int64  `json:"last_seen_ago_ms"`
	Conns         []struct {
		AF        string `json:"af"`
		Channel   string `json:"channel"`
		ConnAgeMs int64  `json:"conn_age_ms"`
	} `json:"conns"`
}

func vxscliShowSync(sockPath string) {
	raw, err := apisock.Call(sockPath, "show.sync", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	var result []ctrlSyncEntry
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}
	if len(result) == 0 {
		fmt.Println("(no clients)")
		return
	}
	for _, e := range result {
		flags := ""
		if !e.Synced {
			flags = " NOT-SYNCED"
		}
		active := e.ActiveAF
		if e.ActiveChannel != "" {
			active += "/" + e.ActiveChannel
		}
		fmt.Printf("%-16s %s  active=%s  last_recv=%s  last_seen=%s%s\n",
			e.ClientName, e.ClientID, active, syncAgo(e.LastRecvAgoMs), syncAgo(e.LastSeenAgoMs), flags)
		fmt.Printf("    rx: session=%s seqid=%d\n", e.RecvSessionID, e.RecvSeqid)
		for _, cn := range e.Conns {
			fmt.Printf("    %s/%s: up %s\n", cn.AF, cn.Channel, syncAgo(cn.ConnAgeMs))
		}
	}
}

func syncAgo(ms int64) string {
	if ms < 0 {
		return "never"
	}
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
