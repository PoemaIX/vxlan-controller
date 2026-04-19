#!/bin/bash
# Shared test helpers for VXLAN controller integration tests.
# Sources should set SCRIPT_DIR before sourcing this file.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BRIDGE_NAME="br-vxlan"
VNI=100
COMM_PORT=5000
PROBE_PORT=5010
VXLAN_DSTPORT=4789
VXLAN_MTU=1400
INIT_TIMEOUT=3

V4_SUBNET="192.168.47"
V6_PREFIX="fd87:4789::"
LEAF_SUBNET_V4="192.168.100"

CLEANUP_PIDS=()
CLEANUP_NS=()
TMPDIR=$(mktemp -d)

test_pass=0
test_fail=0
test_total=0

# =========================================
# Build
# =========================================
build_binaries() {
    echo "=== Building binaries ==="
    cd "$PROJECT_DIR"
    go build -o vxlan-controller ./cmd/vxlan-controller/
}

# =========================================
# Key generation (WireGuard-compatible)
# =========================================
generate_keys() {
    PRIV_1=$(wg genkey); PUB_1=$(echo "$PRIV_1" | wg pubkey)
    PRIV_2=$(wg genkey); PUB_2=$(echo "$PRIV_2" | wg pubkey)
    PRIV_3=$(wg genkey); PUB_3=$(echo "$PRIV_3" | wg pubkey)
    PRIV_4=$(wg genkey); PUB_4=$(echo "$PRIV_4" | wg pubkey)
    PRIV_5=$(wg genkey); PUB_5=$(echo "$PRIV_5" | wg pubkey)
    PRIV_6=$(wg genkey); PUB_6=$(echo "$PRIV_6" | wg pubkey)
    PRIV_10=$(wg genkey); PUB_10=$(echo "$PRIV_10" | wg pubkey)
}

# =========================================
# Cleanup
# =========================================
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${CLEANUP_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    for ns in "${CLEANUP_NS[@]:-}"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del br-lan-v4 2>/dev/null || true
    ip link del br-lan-v6 2>/dev/null || true
    echo "Logs preserved in: $TMPDIR"
    echo "=== Cleanup complete ==="
}

pre_cleanup() {
    pkill -x "vxlan-controller" 2>/dev/null || true
    sleep 0.5
    for i in 1 2 3 4 5 6 10; do
        ip netns del "node-$i" 2>/dev/null || true
        ip netns del "leaf-$i" 2>/dev/null || true
        ip link del "veth-r-v4-$i" 2>/dev/null || true
        ip link del "veth-r-v6-$i" 2>/dev/null || true
        ip link del "veth-leaf-c-$i" 2>/dev/null || true
    done
    ip link del br-lan-v4 2>/dev/null || true
    ip link del br-lan-v6 2>/dev/null || true
}

# =========================================
# Topology setup
# =========================================
setup_topology() {
    pre_cleanup

    echo "=== Creating network namespaces ==="
    for i in 1 2 3 4 5 6 10; do
        ip netns add "node-$i"
        CLEANUP_NS+=("node-$i")
        ip netns exec "node-$i" ip link set lo up
    done
    for i in 1 2 3 4 5 6; do
        ip netns add "leaf-$i"
        CLEANUP_NS+=("leaf-$i")
        ip netns exec "leaf-$i" ip link set lo up
    done

    echo "=== Creating L2 LANs ==="
    ip link add br-lan-v4 type bridge
    ip link set br-lan-v4 up
    ip link add br-lan-v6 type bridge
    ip link set br-lan-v6 up

    # v4 LAN: nodes 1,2,3,4,10 (no per-interface delay; per-dst delays below)
    connect_to_lan 1  v4 "${V4_SUBNET}.1/24"
    connect_to_lan 2  v4 "${V4_SUBNET}.2/24"
    connect_to_lan 3  v4 "${V4_SUBNET}.3/24"
    connect_to_lan 4  v4 "${V4_SUBNET}.4/24"
    connect_to_lan 10 v4 "${V4_SUBNET}.10/24"

    # v6 LAN: nodes 3,4,10,5,6
    connect_to_lan 3  v6 "${V6_PREFIX}3/64"
    connect_to_lan 4  v6 "${V6_PREFIX}4/64"
    connect_to_lan 10 v6 "${V6_PREFIX}10/64"
    connect_to_lan 5  v6 "${V6_PREFIX}5/64"
    connect_to_lan 6  v6 "${V6_PREFIX}6/64"

    setup_delays

    echo "=== Setting up leaf connections ==="
    for i in 1 2 3 4 5 6; do
        veth_client="veth-leaf-c-$i"
        veth_leaf="veth-leaf-l-$i"

        ip link add "$veth_client" type veth peer name "$veth_leaf"
        ip link set "$veth_client" netns "node-$i"
        ip link set "$veth_leaf" netns "leaf-$i"

        leaf_mac=$(printf "02:aa:%02x:00:00:%02x" $i $((RANDOM%256)))
        ip netns exec "leaf-$i" ip link set "$veth_leaf" address "$leaf_mac"
        ip netns exec "leaf-$i" ip link set "$veth_leaf" up
        ip netns exec "leaf-$i" ip addr add "${LEAF_SUBNET_V4}.$i/24" dev "$veth_leaf"

        ip netns exec "node-$i" ip link add "$BRIDGE_NAME" type bridge
        ip netns exec "node-$i" ip link set "$BRIDGE_NAME" up
        ip netns exec "node-$i" ip link set "$veth_client" master "$BRIDGE_NAME"
        ip netns exec "node-$i" ip link set "$veth_client" up
    done

    echo "=== Seeding bridge FDB ==="
    for i in 1 2 3 4 5 6; do
        ip netns exec "leaf-$i" arping -c 1 -A -I "veth-leaf-l-$i" "${LEAF_SUBNET_V4}.$i" > /dev/null 2>&1 || true
    done

    echo "=== Verifying LAN connectivity ==="
    sleep 2  # IPv6 DAD
    ip netns exec node-1 ping -c 1 -W 2 ${V4_SUBNET}.2 > /dev/null 2>&1 && echo "  v4: 1->2 OK" || echo "  v4: 1->2 FAIL"
    ip netns exec node-3 ping -c 1 -W 2 ${V4_SUBNET}.4 > /dev/null 2>&1 && echo "  v4: 3->4 OK" || echo "  v4: 3->4 FAIL"
    ip netns exec node-5 ping6 -c 1 -W 2 ${V6_PREFIX}6 > /dev/null 2>&1 && echo "  v6: 5->6 OK" || echo "  v6: 5->6 FAIL"
}

# =========================================
# Per-destination delay setup
# =========================================
# Creates per-dst netem delays using tc prio qdisc + u32 filters.
# This allows different latencies to different peers on the same interface,
# breaking the star-topology triangle inequality so same-stack transit can occur.
#
# Design:
#   node-1 ↔ node-2 (v4): 30ms (slow direct → forces transit via node-3/4)
#   node-5 ↔ node-6 (v6): 30ms (slow direct → forces transit via node-3/4)
#   node-3 (dual-stack):   1ms to all (best transit node)
#   node-4 (dual-stack):   2ms to all (backup transit node)
#   everything else:       1ms
#
# With ForwardCost=20:
#   1→2 direct:  30 + 20 = 50
#   1→3→2:       (1+20) + (1+20) = 42  ← transit wins by 8ms margin
#   1→4→2:       (2+20) + (2+20) = 44  ← also beats direct

setup_delays() {
    echo "=== Setting up per-destination delays ==="

    # node-1 (v4 only): 30ms to node-2, 1ms to rest
    set_per_dst_delay 1 v4 ip "${V4_SUBNET}.2/32" 30 1

    # node-2 (v4 only): 30ms to node-1, 1ms to rest
    set_per_dst_delay 2 v4 ip "${V4_SUBNET}.1/32" 30 1

    # node-3 (dual-stack): 1ms uniform
    ip netns exec "node-3" tc qdisc add dev eth-v4 root netem delay 1ms
    ip netns exec "node-3" tc qdisc add dev eth-v6 root netem delay 1ms

    # node-4 (dual-stack): 2ms uniform (slightly worse than node-3)
    ip netns exec "node-4" tc qdisc add dev eth-v4 root netem delay 2ms
    ip netns exec "node-4" tc qdisc add dev eth-v6 root netem delay 2ms

    # node-5 (v6 only): 30ms to node-6, 1ms to rest
    set_per_dst_delay 5 v6 ip6 "${V6_PREFIX}6/128" 30 1

    # node-6 (v6 only): 30ms to node-5, 1ms to rest
    set_per_dst_delay 6 v6 ip6 "${V6_PREFIX}5/128" 30 1

    # node-10 (controller only): 1ms uniform
    ip netns exec "node-10" tc qdisc add dev eth-v4 root netem delay 1ms
    ip netns exec "node-10" tc qdisc add dev eth-v6 root netem delay 1ms
}

# set_per_dst_delay NODE AF_NAME PROTO DST_CIDR SLOW_MS DEFAULT_MS
#   AF_NAME: v4 or v6 (determines device name eth-v4 / eth-v6)
#   PROTO:   ip or ip6 (for tc filter protocol + match)
#   DST_CIDR: e.g. "192.168.47.2/32" or "fd87:4789::6/128"
set_per_dst_delay() {
    local node=$1 af=$2 proto=$3 dst=$4 slow_ms=$5 default_ms=$6
    local dev="eth-${af}"
    local ns="node-$node"
    local tc_proto="ip"
    [ "$proto" = "ip6" ] && tc_proto="ipv6"

    ip netns exec "$ns" tc qdisc add dev "$dev" root handle 1: prio bands 3 \
        priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    ip netns exec "$ns" tc qdisc add dev "$dev" parent 1:1 handle 10: netem delay "${default_ms}ms"
    ip netns exec "$ns" tc qdisc add dev "$dev" parent 1:2 handle 20: netem delay "${slow_ms}ms"
    ip netns exec "$ns" tc qdisc add dev "$dev" parent 1:3 handle 30: netem delay "${default_ms}ms"
    ip netns exec "$ns" tc filter add dev "$dev" parent 1:0 protocol "$tc_proto" prio 1 \
        u32 match "$proto" dst "$dst" flowid 1:2
}

connect_to_lan() {
    local node=$1 lan=$2 ip_addr=$3 delay=${4:-0}
    local veth_root="veth-r-${lan}-${node}"
    local veth_ns="eth-${lan}"

    ip link add "$veth_root" type veth peer name "$veth_ns"
    ip link set "$veth_ns" netns "node-$node"
    ip link set "$veth_root" master "br-lan-${lan}"
    ip link set "$veth_root" up
    local mac=$(printf "02:%02x:%02x:00:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $node $((RANDOM%256)))
    ip netns exec "node-$node" ip link set "$veth_ns" address "$mac"
    ip netns exec "node-$node" ip link set "$veth_ns" up
    ip netns exec "node-$node" ip addr add "$ip_addr" dev "$veth_ns"

    if [ "$delay" != "0" ]; then
        ip netns exec "node-$node" tc qdisc add dev "$veth_ns" root netem delay "${delay}ms"
    fi
}

# =========================================
# Config generation
# =========================================
write_controller_config() {
    local node=$1 privkey=$2
    local f="$TMPDIR/controller-${node}.yaml"
    cat > "$f" << YAML
private_key: "${privkey}"
client_offline_timeout: 8
sync_new_client_debounce: 1
sync_new_client_debounce_max: 2
topology_update_debounce: 1
topology_update_debounce_max: 2
probing:
  probe_interval_s: 5
  probe_times: 3
  in_probe_interval_ms: 50
  probe_timeout_ms: 1000
address_families:
  v4:
    enable: true
    bind_addr: "${V4_SUBNET}.${node}"
    communication_port: ${COMM_PORT}
    vxlan_vni: ${VNI}
    vxlan_dst_port: ${VXLAN_DSTPORT}
    vxlan_src_port_start: ${VXLAN_DSTPORT}
    vxlan_src_port_end: ${VXLAN_DSTPORT}
  v6:
    enable: true
    bind_addr: "${V6_PREFIX}${node}"
    communication_port: $((COMM_PORT + 1))
    vxlan_vni: ${VNI}
    vxlan_dst_port: ${VXLAN_DSTPORT}
    vxlan_src_port_start: ${VXLAN_DSTPORT}
    vxlan_src_port_end: ${VXLAN_DSTPORT}
allowed_clients:
  - client_id: "${PUB_1}"
    client_name: "node-1"

  - client_id: "${PUB_2}"
    client_name: "node-2"

  - client_id: "${PUB_3}"
    client_name: "node-3"

  - client_id: "${PUB_4}"
    client_name: "node-4"

  - client_id: "${PUB_5}"
    client_name: "node-5"

  - client_id: "${PUB_6}"
    client_name: "node-6"

YAML
    echo "$f"
}

write_client_config() {
    local node=$1 privkey=$2 neigh_suppress=${3:-false} auto_detect=${4:-false} vxlan_firewall=${5:-false}
    local f="$TMPDIR/client-${node}.yaml"
    local has_v4=false has_v6=false

    case "$node" in 1|2|3|4) has_v4=true ;; esac
    case "$node" in 3|4|5|6) has_v6=true ;; esac

    cat > "$f" << YAML
private_key: "${privkey}"
bridge_name: "${BRIDGE_NAME}"
clamp_mss_to_mtu: false
neigh_suppress: ${neigh_suppress}
vxlan_firewall: ${vxlan_firewall}
init_timeout: ${INIT_TIMEOUT}
ntp_servers: []
address_families:
YAML

    if $has_v4; then
        if $auto_detect; then
            cat >> "$f" << YAML
  v4:
    enable: true
    autoip_interface: "eth-v4"
    probe_port: ${PROBE_PORT}
    communication_port: ${COMM_PORT}
    vxlan_name: "vxlan-v4"
    vxlan_vni: ${VNI}
    vxlan_mtu: ${VXLAN_MTU}
    vxlan_dst_port: ${VXLAN_DSTPORT}
    priority: 10
    controllers:
      - pubkey: "${PUB_4}"
        addr: "${V4_SUBNET}.4:${COMM_PORT}"
      - pubkey: "${PUB_10}"
        addr: "${V4_SUBNET}.10:${COMM_PORT}"
YAML
        else
            cat >> "$f" << YAML
  v4:
    enable: true
    bind_addr: "${V4_SUBNET}.${node}"
    probe_port: ${PROBE_PORT}
    communication_port: ${COMM_PORT}
    vxlan_name: "vxlan-v4"
    vxlan_vni: ${VNI}
    vxlan_mtu: ${VXLAN_MTU}
    vxlan_dst_port: ${VXLAN_DSTPORT}
    priority: 10
    controllers:
      - pubkey: "${PUB_4}"
        addr: "${V4_SUBNET}.4:${COMM_PORT}"
      - pubkey: "${PUB_10}"
        addr: "${V4_SUBNET}.10:${COMM_PORT}"
YAML
        fi
    fi

    if $has_v6; then
        if $auto_detect; then
            cat >> "$f" << YAML
  v6:
    enable: true
    autoip_interface: "eth-v6"
    probe_port: $((PROBE_PORT + 1))
    communication_port: $((COMM_PORT + 1))
    vxlan_name: "vxlan-v6"
    vxlan_vni: ${VNI}
    vxlan_mtu: ${VXLAN_MTU}
    vxlan_dst_port: ${VXLAN_DSTPORT}
    priority: 10
    controllers:
      - pubkey: "${PUB_4}"
        addr: "[${V6_PREFIX}4]:$((COMM_PORT + 1))"
      - pubkey: "${PUB_10}"
        addr: "[${V6_PREFIX}10]:$((COMM_PORT + 1))"
YAML
        else
            cat >> "$f" << YAML
  v6:
    enable: true
    bind_addr: "${V6_PREFIX}${node}"
    probe_port: $((PROBE_PORT + 1))
    communication_port: $((COMM_PORT + 1))
    vxlan_name: "vxlan-v6"
    vxlan_vni: ${VNI}
    vxlan_mtu: ${VXLAN_MTU}
    vxlan_dst_port: ${VXLAN_DSTPORT}
    priority: 10
    controllers:
      - pubkey: "${PUB_4}"
        addr: "[${V6_PREFIX}4]:$((COMM_PORT + 1))"
      - pubkey: "${PUB_10}"
        addr: "[${V6_PREFIX}10]:$((COMM_PORT + 1))"
YAML
        fi
    fi

    echo "$f"
}

generate_all_configs() {
    local neigh_suppress=${1:-false}
    CTRL_4_CONF=$(write_controller_config 4 "$PRIV_4")
    CTRL_10_CONF=$(write_controller_config 10 "$PRIV_10")
    CLIENT_1_CONF=$(write_client_config 1 "$PRIV_1" "$neigh_suppress")
    CLIENT_2_CONF=$(write_client_config 2 "$PRIV_2" "$neigh_suppress")
    CLIENT_3_CONF=$(write_client_config 3 "$PRIV_3" "$neigh_suppress")
    CLIENT_4_CONF=$(write_client_config 4 "$PRIV_4" "$neigh_suppress")
    CLIENT_5_CONF=$(write_client_config 5 "$PRIV_5" "$neigh_suppress")
    CLIENT_6_CONF=$(write_client_config 6 "$PRIV_6" "$neigh_suppress")
}

# =========================================
# Process management
# =========================================
start_process() {
    local ns=$1 mode=$2 config=$3 logname=$4
    ip netns exec "$ns" "$PROJECT_DIR/vxlan-controller" -mode "$mode" -config "$config" -log-level verbose > "$TMPDIR/${logname}.log" 2>&1 &
    local pid=$!
    CLEANUP_PIDS+=("$pid")
    echo "  $logname started (PID=$pid)"
}

start_controllers() {
    echo "=== Starting controllers ==="
    start_process "node-10" controller "$CTRL_10_CONF" "ctrl-10"
    start_process "node-4"  controller "$CTRL_4_CONF"  "ctrl-4"
    sleep 2
}

start_clients() {
    echo "=== Starting clients ==="
    start_process "node-1" client "$CLIENT_1_CONF" "client-1"
    start_process "node-2" client "$CLIENT_2_CONF" "client-2"
    start_process "node-3" client "$CLIENT_3_CONF" "client-3"
    start_process "node-4" client "$CLIENT_4_CONF" "client-4"
    start_process "node-5" client "$CLIENT_5_CONF" "client-5"
    start_process "node-6" client "$CLIENT_6_CONF" "client-6"
}

wait_converge() {
    local wait=$((INIT_TIMEOUT + 10))
    echo "=== Waiting ${wait}s for convergence ==="
    sleep $wait
}

kill_by_log() {
    local logname="$1"
    for pid in "${CLEANUP_PIDS[@]}"; do
        cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null || true)
        if echo "$cmdline" | grep -q "$logname"; then
            kill "$pid" 2>/dev/null || true
            return 0
        fi
    done
    return 1
}

# =========================================
# Test runner
# =========================================
run_test() {
    local name="$1"; shift
    test_total=$((test_total + 1))
    echo -n "  TEST: $name ... "
    if "$@" > /dev/null 2>&1; then
        echo "PASS"
        test_pass=$((test_pass + 1))
    else
        echo "FAIL"
        test_fail=$((test_fail + 1))
    fi
}

print_results() {
    echo ""
    echo "==========================================="
    echo "  Results: ${test_pass}/${test_total} passed, ${test_fail} failed"
    echo "==========================================="

    if [ $test_fail -gt 0 ]; then
        echo ""
        echo "=== Recent logs ==="
        for f in "$TMPDIR"/*.log; do
            echo "--- $(basename $f) ---"
            tail -10 "$f" 2>/dev/null || true
        done
    fi
}

# Send command to client API socket via python3
unix_sock_cmd() {
    local sock="$1" cmd="$2"
    python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect('$sock')
s.sendall(b'$cmd\n')
resp = s.recv(4096).decode().strip()
print(resp)
s.close()
" 2>/dev/null
}

# Find socket for a client by checking its bind addr
find_client_sock() {
    local af="$1" expected_addr="$2"
    for sock in /tmp/vxlan-client-*.sock; do
        [ -S "$sock" ] || continue
        local resp
        resp=$(unix_sock_cmd "$sock" "GET_BIND_ADDR $af" 2>/dev/null || true)
        if echo "$resp" | grep -q "$expected_addr"; then
            echo "$sock"
            return
        fi
    done
}
