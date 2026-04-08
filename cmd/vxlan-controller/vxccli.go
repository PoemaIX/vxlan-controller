package main

import (
	"encoding/json"
	"fmt"
	"os"

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
