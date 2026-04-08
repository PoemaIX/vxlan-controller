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
- **Static cost mode**: Freeze routing costs from live probes for stable, predictable routing
- **Runtime CLI**: `wg`-style Unix socket CLI (`vxscli`/`vxccli`) for runtime inspection and control
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

Single binary, all modes:

```bash
go build -o vxlan-controller ./cmd/vxlan-controller
```

Optional symlinks for CLI convenience:

```bash
ln -s vxlan-controller /usr/local/bin/vxscli
ln -s vxlan-controller /usr/local/bin/vxccli
```

## Quick Start with Autogen

The fastest way to set up a network. Define your topology in one file, generate all configs automatically:

```bash
vxlan-controller --mode autogen --config topology.yaml
```

See [`demo/topology.yaml`](demo/topology.yaml) for a complete example:

```yaml
vxlan_dst_port: 4789
vxlan_src_port_start: 4789
vxlan_src_port_end: 4789
communication_port: 5000

nodes:
  tokyo:
    v4:
      bind: 10.0.1.1            # local bind address
      ddns: tokyo.example.com   # address clients use to connect
    v6: "2001:db8:1::1"         # shorthand: bind = this IP
  osaka:
    v4: 203.0.113.10
    v6: "2001:db8:2::1"
  seoul:
    v4: 198.51.100.20
  singapore:
    v4: 192.0.2.30
    v6: eth0                    # autoip_interface

controllers:
  - tokyo
  - osaka

clients:
  - tokyo
  - osaka
  - seoul
  - singapore
```

This generates `tokyo.controller.yaml`, `tokyo.client.yaml`, `osaka.controller.yaml`, etc. with all keypairs and cross-references pre-filled.

**Bind vs DDNS**:
- `bind` — local address the process listens on (`bind_addr` or `autoip_interface` if it's an interface name)
- `ddns` — address clients use to connect to this controller (IP, hostname, or DDNS). Defaults to `bind` if bind is a static IP. Required when controller uses `autoip_interface`.

## Key Generation

Compatible with WireGuard key format:

```bash
# Using built-in keygen
vxlan-controller --mode keygen genkey | tee privatekey | vxlan-controller --mode keygen pubkey > publickey

# Or generate a default config with random keys
vxlan-controller --mode controller --default-config > controller.yaml
vxlan-controller --mode client --default-config > client.yaml
```

The `--default-config` output includes both `private_key` and `public_key` fields. Copy `public_key` to other configs where needed (e.g. `client_id` in controller config).

## CLI Tools

Runtime inspection and control via Unix socket (like `wg show`):

```bash
# Controller CLI
vxscli cost get                     # show cost matrix with readable names
vxscli cost getmode                 # show current cost mode (probe/static)
vxscli cost setmode static          # switch to static cost mode
vxscli cost store                   # save current probed costs to config

# Client CLI
vxccli af list                      # list address families and bind addresses
vxccli af get v4                    # get bind address for an AF
vxccli af set v4 192.168.1.100      # set bind address (non-autoip only)
```

Or without symlinks: `vxlan-controller --mode vxscli cost get`

Custom socket path: `vxscli --sock /path/to/sock cost get`

Default sockets: `/var/run/vxlan-controller.sock`, `/var/run/vxlan-client.sock`

### Static Cost Mode

For stable, predictable routing without probe-driven changes:

```bash
vxscli cost setmode probe           # 1. ensure probe mode (default)
vxscli cost get                     # 2. wait for convergence, inspect costs
vxscli cost store                   # 3. snapshot costs to config (static_costs)
vxscli cost setmode static          # 4. switch to static routing
```

In static mode, probing still runs (WebUI sees live data), but route computation uses only the stored costs. Unreachable links (100% packet loss) are still detected and excluded.

## Configuration

### Client (`client.yaml`)

```bash
vxlan-controller --mode client --default-config   # print full default config
```

```yaml
private_key: "<base64>"
public_key: "<base64>"              # display-only, for easy copying
bridge_name: "br-vxlan"
clamp_mss_to_mtu: true
vxlan_firewall: true
log_level: "info"
api_socket: "/var/run/vxlan-client.sock"
address_families:
  v4:
    enable: true
    bind_addr: "192.168.1.100"       # or use autoip_interface instead
    # autoip_interface: "eth0"       # auto-detect IP from interface
    # addr_select: |                 # inline Lua, or path to .lua file
    #   function select(info) ... end
    probe_port: 5010
    additional_cost: 20
    vxlan_name: "vxlan-v4"
    vxlan_vni: 100
    vxlan_mtu: 1400
    vxlan_dst_port: 4789
    controllers:
      - pubkey: "<controller pubkey>"
        addr: "10.0.0.1:5000"
```

### Controller (`controller.yaml`)

```bash
vxlan-controller --mode controller --default-config   # print full default config
```

```yaml
private_key: "<base64>"
public_key: "<base64>"
cost_mode: "probe"                   # "probe" or "static"
api_socket: "/var/run/vxlan-controller.sock"
probing:
  probe_interval_s: 5
  probe_times: 5
web_ui:
  bind_addr: ":8080"
address_families:
  v4:
    enable: true
    bind_addr: "0.0.0.0"
    communication_port: 5000
  v6:
    enable: true
    bind_addr: "::"
    communication_port: 5000
allowed_clients:
  - client_id: "<client pubkey>"
    client_name: "node-1"
# static_costs:                      # populated by "vxscli cost store"
#   node-1:
#     node-2:
#       v4: 12.5
```

## Modes

```
vxlan-controller --mode <mode> [options]

  controller    Run as VXLAN controller (alias: server)
  client        Run as VXLAN client
  keygen        Key generation (genkey/pubkey)
  vxscli        Controller CLI (cost get/setmode/store)
  vxccli        Client CLI (af list/get/set)
  autogen       Generate configs from topology file
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
