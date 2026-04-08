# VXLAN Controller

A VXLAN L2 overlay network controller, similar to EVPN but with IPv6 support and multi-AF routing.

Clients collect local MAC addresses and IPs, report them to the Controller. The Controller computes L2 routing (Floyd-Warshall shortest path) and distributes FDB entries to all clients via the Linux kernel.

## Why

FRR still lacks proper IPv6 VXLAN-EVPN support. This project provides a lightweight alternative with:

- **Dual-stack**: IPv4 and IPv6 underlay, with cross-AF transit routing
- **Multi-AF design**: Beyond v4/v6, supports arbitrary address families (e.g. `asia_v4`, `europe_v4`) for regional topologies
- **WireGuard-style encryption**: Noise IK handshake (X25519 + ChaCha20-Poly1305) on all control plane traffic. data plane uses plain vxlan.
- **Controller failover**: Clients connect to multiple controllers, automatically switch on failure
- **Broadcast relay**: Controller relays ARP/ND across all AF listeners, no multicast FDB needed
- **Dynamic IP**: Runtime bind address changes via automatic interface monitoring (`autoip_interface`)
- **Lua filtering**: User-defined Lua scripts for multicast/route filtering with per-MAC/per-client rate limiting
- **VXLAN firewall**: nftables-based injection protection, whitelisting only known peer endpoint IPs
- **WebUI**: Real-time web dashboard with client status, routing tables, latency matrix, and multicast stats
- **Per-AF AdditionalCost**: Fine-grained path selection cost tuning per address family
- **Leveled logging**: Five log levels (error/warn/info/debug/verbose) for flexible observability

## Architecture

```
┌──────────────┐         TCP (control)         ┌──────────────┐
│   Client 1   │◄────────────────────────────►  │  Controller  │
│  (node-1)    │         UDP (broadcast)        │  (node-10)   │
│              │◄────────────────────────────►  │              │
└──────┬───────┘                                └──────────────┘
       │ VXLAN
       │ FDB entries
       ▼
┌──────────────┐
│  br-vxlan    │
│  ├ vxlan-v4  │
│  ├ vxlan-v6  │
│  └ tap-inject│
└──────────────┘
```

## Build

```bash
go build -o vxlan-controller ./cmd/controller
go build -o vxlan-client ./cmd/client
go build -o keygen ./cmd/keygen
```

## Key Generation

Compatible with WireGuard key format:

```bash
# Using wg (if available)
wg genkey | tee privatekey | wg pubkey > publickey

# Using built-in keygen
./keygen genkey | tee privatekey | ./keygen pubkey > publickey
```

## Configuration

### Client (`client.yaml`)

```yaml
private_key: "<base64 private key>"
bridge_name: "br-vxlan"
neigh_suppress: false
clamp_mss_to_mtu: true
clamp_mss_table: "vxlan_mss"        # nftables table name (default: vxlan_mss)
vxlan_firewall: true                 # enable nftables VXLAN injection protection
vxlan_firewall_table: "vxlan_fw"     # nftables table name (default: vxlan_fw)
init_timeout: 10
stats_interval_s: 5                  # multicast stats reporting interval
log_level: "info"                    # error/warn/info/debug/verbose
filters:
  output_mcast: |
    function filter(pkt)
      if pkt.ethertype == 0x0806 then return true end  -- ARP
      if pkt.ethertype == 0x86dd and pkt.ipv6_next_header == 58 then
        if pkt.icmpv6_type == 135 or pkt.icmpv6_type == 136 then return true end
      end
      return "non-arp/nd"
    end
  rate_limit:
    per_mac: 64
    per_client: 1000
address_families:
  v4:
    enable: true
    bind_addr: "192.168.1.100"       # or use autoip_interface instead
    # autoip_interface: "eth0"       # auto-detect IP from interface
    # addr_select: |                 # optional Lua address selection
    #   function select(info) ... end
    probe_port: 5010
    additional_cost: 20              # per-AF routing cost penalty
    vxlan_name: "vxlan-v4"
    vxlan_vni: 100
    vxlan_mtu: 1400
    vxlan_dstport: 4789
    controllers:
      - public_key: "<controller pubkey>"
        endpoint: "10.0.0.1:5000"
  v6:
    enable: true
    bind_addr: "fd00::100"
    probe_port: 5010
    additional_cost: 20
    vxlan_name: "vxlan-v6"
    vxlan_vni: 100
    vxlan_mtu: 1400
    vxlan_dstport: 4789
    controllers:
      - public_key: "<controller pubkey>"
        endpoint: "[fd00::1]:5000"
```

### Controller (`controller.yaml`)

```yaml
private_key: "<base64 private key>"
client_offline_timeout: 300
sync_new_client_debounce: 2
sync_new_client_debounce_max: 10
topology_update_debounce: 1
topology_update_debounce_max: 5
log_level: "info"
probing:
  probe_interval_s: 60
  probe_times: 5
  in_probe_interval_ms: 200
  probe_timeout_ms: 1000
web_ui:
  bind_addr: ":8080"                 # WebUI listen address (omit to disable)
  mac_aliases:                       # optional MAC display names
    "aa:bb:cc:dd:ee:ff": "server-1"
  nodes:                             # optional node display config
    node-1:
      label: "Tokyo"
      pos: [100, 200]
address_families:
  v4:
    enable: true
    bind_addr: "0.0.0.0"
    # autoip_interface: "eth0"       # auto-detect IP from interface
    port: 5000
  v6:
    enable: true
    bind_addr: "::"
    port: 5000
allowed_clients:
  - public_key: "<client pubkey>"
    name: "node-1"
    # filters:                       # optional per-client Lua filters
    #   input_mcast: |
    #     function filter(pkt) return true end
```

## Tests

Integration tests require root (network namespaces). 10 test suites:

| # | Test | Description |
|---|------|-------------|
| 1 | `test_connectivity.sh` | Full mesh 30-pair ping (6 nodes) |
| 2 | `test_neigh_suppress.sh` | ARP suppression with priming |
| 3 | `test_controller_failover.sh` | Kill/restore both controllers |
| 4 | `test_transit_failure.sh` | Transit node failure and recovery |
| 5 | `test_broadcast_relay.sh` | Cross-AF broadcast relay |
| 6 | `test_dual_stack.sh` | IPv4-only ↔ IPv6-only via dual-stack transit |
| 7 | `test_ip_change.sh` | Runtime IP change via API / autoip_interface |
| 8 | `test_no_flood.sh` | Unknown unicast suppression (no flood) |
| 9 | `test_firewall.sh` | VXLAN injection protection (nftables) |
| 10 | `compare_static_vs_controller.sh` | Benchmark: static FDB vs controller-driven |

```bash
# Run all tests
sudo bash tests/run_all.sh

# Run specific test
sudo bash tests/test_connectivity.sh
```

## License

See [LICENSE](LICENSE).
