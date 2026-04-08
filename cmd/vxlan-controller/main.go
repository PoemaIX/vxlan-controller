package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"vxlan-controller/pkg/client"
	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/controller"
	"vxlan-controller/pkg/crypto"
	"vxlan-controller/pkg/vlog"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	mode := flag.String("mode", "", "run mode: controller, client, keygen, vxscli, vxccli")
	configPath := flag.String("config", "", "path to config file")
	defaultConfig := flag.Bool("default-config", false, "print default config and exit (controller/client modes)")
	mockMode := flag.Bool("mock", false, "run controller in mock mode for WebUI demo")
	logLevel := flag.String("log-level", "", "log level: error, warn, info, debug, verbose (overrides config)")
	sockPath := flag.String("sock", "", "Unix socket path (overrides default for vxscli/vxccli)")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *version {
		fmt.Println("vxlan-controller", Version)
		return
	}

	switch *mode {
	case "controller", "server":
		runController(*configPath, *defaultConfig, *mockMode, *logLevel)
	case "client":
		runClient(*configPath, *defaultConfig, *logLevel)
	case "keygen":
		runKeygen(flag.Args())
	case "vxscli":
		runVxscli(*sockPath, flag.Args())
	case "vxccli":
		runVxccli(*sockPath, flag.Args())
	default:
		fmt.Fprintln(os.Stderr, "Usage: vxlan-controller --mode <controller|client|keygen|vxscli|vxccli> [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Modes:")
		fmt.Fprintln(os.Stderr, "  controller  Run as VXLAN controller (alias: server)")
		fmt.Fprintln(os.Stderr, "  client      Run as VXLAN client")
		fmt.Fprintln(os.Stderr, "  keygen      Key generation (genkey/pubkey)")
		fmt.Fprintln(os.Stderr, "  vxscli      Controller CLI (cost get/setmode/store)")
		fmt.Fprintln(os.Stderr, "  vxccli      Client CLI (af list/get/set)")
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
		os.Exit(1)
	}
}

func runController(configPath string, defaultConfig, mockMode bool, logLevel string) {
	if defaultConfig {
		data, err := config.DefaultControllerConfigYAML()
		if err != nil {
			log.Fatalf("Failed to marshal default config: %v", err)
		}
		fmt.Print(string(data))
		return
	}

	if configPath == "" {
		configPath = "controller.yaml"
	}

	cfg, err := config.LoadControllerConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if logLevel != "" {
		vlog.SetLevel(vlog.ParseLevel(logLevel))
	} else if cfg.LogLevel != "" {
		vlog.SetLevel(vlog.ParseLevel(cfg.LogLevel))
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	if mockMode {
		go func() {
			<-sigCh
			log.Println("[Mock] shutting down...")
			os.Exit(0)
		}()
		if err := controller.RunMock(cfg); err != nil {
			log.Fatalf("Mock error: %v", err)
		}
		return
	}

	ctrl := controller.New(cfg)

	go func() {
		<-sigCh
		log.Println("[Controller] shutting down...")
		ctrl.Stop()
	}()

	if err := ctrl.Run(); err != nil {
		log.Fatalf("Controller error: %v", err)
	}
}

func runClient(configPath string, defaultConfig bool, logLevel string) {
	if defaultConfig {
		data, err := config.DefaultClientConfigYAML()
		if err != nil {
			log.Fatalf("Failed to marshal default config: %v", err)
		}
		fmt.Print(string(data))
		return
	}

	if configPath == "" {
		configPath = "client.yaml"
	}

	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if logLevel != "" {
		vlog.SetLevel(vlog.ParseLevel(logLevel))
	} else if cfg.LogLevel != "" {
		vlog.SetLevel(vlog.ParseLevel(cfg.LogLevel))
	}

	cl := client.New(cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigCh
		log.Println("[Client] shutting down...")
		cl.Stop()
	}()

	if err := cl.Run(); err != nil {
		log.Fatalf("Client error: %v", err)
	}
}

func runKeygen(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: vxlan-controller --mode keygen <genkey|pubkey> [key]")
		os.Exit(1)
	}

	switch args[0] {
	case "genkey":
		priv, _ := crypto.GenerateKeyPair()
		fmt.Println(base64.StdEncoding.EncodeToString(priv[:]))

	case "pubkey":
		var privB64 string
		if len(args) >= 2 {
			privB64 = args[1]
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() {
				fmt.Fprintln(os.Stderr, "Error: no input")
				os.Exit(1)
			}
			privB64 = scanner.Text()
		}

		privBytes, err := base64.StdEncoding.DecodeString(privB64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid base64: %v\n", err)
			os.Exit(1)
		}
		if len(privBytes) != 32 {
			fmt.Fprintf(os.Stderr, "Key must be 32 bytes, got %d\n", len(privBytes))
			os.Exit(1)
		}

		var priv [32]byte
		copy(priv[:], privBytes)
		pub := crypto.PublicKey(priv)
		fmt.Println(base64.StdEncoding.EncodeToString(pub[:]))

	default:
		fmt.Fprintln(os.Stderr, "Usage: vxlan-controller --mode keygen <genkey|pubkey> [key]")
		os.Exit(1)
	}
}
