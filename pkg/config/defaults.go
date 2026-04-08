package config

import (
	"encoding/base64"

	"vxlan-controller/pkg/crypto"

	"gopkg.in/yaml.v3"
)

func DefaultClientConfigYAML() ([]byte, error) {
	cfg := DefaultClientConfig
	priv, pub := crypto.GenerateKeyPair()
	cfg.PrivateKey = base64.StdEncoding.EncodeToString(priv[:])
	cfg.PublicKey = base64.StdEncoding.EncodeToString(pub[:])
	return yaml.Marshal(&cfg)
}

func DefaultControllerConfigYAML() ([]byte, error) {
	cfg := DefaultControllerConfig
	priv, pub := crypto.GenerateKeyPair()
	cfg.PrivateKey = base64.StdEncoding.EncodeToString(priv[:])
	cfg.PublicKey = base64.StdEncoding.EncodeToString(pub[:])
	return yaml.Marshal(&cfg)
}

var DefaultNTPServers = []string{
	"time.cloudflare.com",
	"time.google.com",
	"time.apple.com",
	"pool.ntp.org",
	"0.pool.ntp.org",
	"1.pool.ntp.org",
	"2.pool.ntp.org",
	"3.pool.ntp.org",
	"ntp.ubuntu.com",
}

const (
	DefaultControllerSocket = "/var/run/vxlan-controller.sock"
	DefaultClientSocket     = "/var/run/vxlan-client.sock"
)

var DefaultClientConfig = ClientConfigFile{
	PrivateKey:         "<base64 private key from: wg genkey>",
	BridgeName:         "br-vxlan",
	ClampMSSToMTU:      false,
	ClampMSSTable:      "vxlan_mss",
	NeighSuppress:      false,
	VxlanFirewall:      false,
	VxlanFirewallTable: "vxlan_fw",
	InitTimeout:        10,
	StatsIntervalS:     5,
	NTPServers:         DefaultNTPServers,
	NTPPeriodH:         23,
	AFSettings: map[string]*ClientAFConfigFile{
		"v4": {
			Enable:            true,
			BindAddr:          "0.0.0.0",
			ProbePort:         5010,
			CommunicationPort: 0,
			VxlanName:         "vxlan-v4",
			VxlanVNI:          100,
			VxlanMTU:          1400,
			VxlanDstPort:      4789,
			VxlanSrcPortStart: 4789,
			VxlanSrcPortEnd:   4789,
			Priority:          10,
			AdditionalCost:    20,
			Controllers: []ControllerEndpointFile{
				{PubKey: "<base64 controller pubkey from: wg pubkey>", Addr: "192.168.1.1:5000"},
			},
		},
		"v6": {
			Enable:            false,
			BindAddr:          "::",
			ProbePort:         5010,
			CommunicationPort: 0,
			VxlanName:         "vxlan-v6",
			VxlanVNI:          100,
			VxlanMTU:          1400,
			VxlanDstPort:      4789,
			VxlanSrcPortStart: 4789,
			VxlanSrcPortEnd:   4789,
			Priority:          10,
			AdditionalCost:    20,
			Controllers: []ControllerEndpointFile{
				{PubKey: "<base64 controller pubkey from: wg pubkey>", Addr: "[fd00::1]:5000"},
			},
		},
	},
}

var DefaultControllerConfig = ControllerConfigFile{
	PrivateKey:                "<base64 private key from: wg genkey>",
	CostMode:                 "probe",
	ClientOfflineTimeout:      30,
	SyncNewClientDebounce:     3,
	SyncNewClientDebounceMax:  10,
	TopologyUpdateDebounce:    3,
	TopologyUpdateDebounceMax: 7,
	Probing: ProbingConfigFile{
		ProbeIntervalS:    5,
		ProbeTimes:        5,
		InProbeIntervalMs: 200,
		ProbeTimeoutMs:    1000,
	},
	AFSettings: map[string]*ControllerAFConfigFile{
		"v4": {
			Enable:            true,
			BindAddr:          "0.0.0.0",
			CommunicationPort: 5000,
			VxlanVNI:          100,
			VxlanDstPort:      4789,
			VxlanSrcPortStart: 4789,
			VxlanSrcPortEnd:   4789,
		},
		"v6": {
			Enable:            false,
			BindAddr:          "::",
			CommunicationPort: 5000,
			VxlanVNI:          100,
			VxlanDstPort:      4789,
			VxlanSrcPortStart: 4789,
			VxlanSrcPortEnd:   4789,
		},
	},
	AllowedClients: []PerClientConfigFile{
		{
			ClientID:   "<base64 client pubkey from: wg pubkey>",
			ClientName: "node-1",
		},
	},
}
