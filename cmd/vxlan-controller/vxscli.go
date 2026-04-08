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
	default:
		vxscliUsage()
		os.Exit(1)
	}
}

func vxscliUsage() {
	fmt.Fprintln(os.Stderr, "Usage: vxlan-controller --mode vxscli [--sock <path>] <command>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  cost get                    Show cost matrix")
	fmt.Fprintln(os.Stderr, "  cost getmode                Show current cost mode")
	fmt.Fprintln(os.Stderr, "  cost setmode <probe|static> Set cost mode")
	fmt.Fprintln(os.Stderr, "  cost store                  Save current costs to config")
}

type afCostInfo struct {
	Mean           float64 `json:"mean"`
	Std            float64 `json:"std"`
	PacketLoss     float64 `json:"packet_loss"`
	Priority       int     `json:"priority"`
	AdditionalCost float64 `json:"additional_cost"`
	TotalCost      float64 `json:"total_cost"`
}

type costGetResult struct {
	CostMode string                                       `json:"cost_mode"`
	Matrix   map[string]map[string]map[string]*afCostInfo `json:"matrix"`
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
				info := afs[af]
				lossStr := fmt.Sprintf("%.2f", info.PacketLoss)
				if info.PacketLoss >= 1.0 {
					lossStr = "1.00 (unreachable)"
				}
				fmt.Printf("  %s: cost=%.2f mean=%.2f std=%.2f loss=%s prio=%d addl=%.2f\n",
					af, info.TotalCost, info.Mean, info.Std, lossStr, info.Priority, info.AdditionalCost)
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

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
