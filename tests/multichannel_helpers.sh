#!/bin/bash
# Multi-channel (multi-ISP) test helpers for the per-af-channels feature.
#
# Topology:
#   4 nodes (node-1..4) each with two v4 ISP uplinks and two v6 ISP uplinks.
#     ISP1 v4 LAN: br-isp1-v4 (10.1.1.0/24)
#     ISP2 v4 LAN: br-isp2-v4 (10.2.1.0/24)
#     ISP1 v6 LAN: br-isp1-v6 (fd1:0:1::/64)
#     ISP2 v6 LAN: br-isp2-v6 (fd2:0:2::/64)
#   1 controller node (node-10) reachable via both ISPs.
#   Each node also has a leaf veth in a separate "leaf-<n>" namespace used
#   for end-to-end ping tests across the VXLAN fabric.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BRIDGE_NAME="br-vxlan"
VNI=200
COMM_PORT_V4=6000   # v4/ISP1
COMM_PORT_V4_ISP2=6010
COMM_PORT_V6=6100   # v6/ISP1
COMM_PORT_V6_ISP2=6110
PROBE_PORT_V4=6020
PROBE_PORT_V4_ISP2=6030
PROBE_PORT_V6=6120
PROBE_PORT_V6_ISP2=6130
VXLAN_DSTPORT=4789
VXLAN_MTU=1400
INIT_TIMEOUT=3

ISP1_V4="10.1.1"
ISP2_V4="10.2.1"
ISP1_V6="fd1:0:1::"
ISP2_V6="fd2:0:2::"
LEAF_V4="192.168.250"

CLEANUP_PIDS=()
CLEANUP_NS=()
TMPDIR=$(mktemp -d)

test_pass=0
test_fail=0
test_total=0

build_binaries() {
    echo "=== Building binaries ==="
    cd "$PROJECT_DIR"
    go build -o vxlan-controller ./cmd/vxlan-controller/
}

generate_keys() {
    for i in 1 2 3 4 10; do
        priv=$(wg genkey)
        pub=$(echo "$priv" | wg pubkey)
        eval "PRIV_$i=\$priv"
        eval "PUB_$i=\$pub"
    done
}

mc_cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${CLEANUP_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    for ns in "${CLEANUP_NS[@]:-}"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    for br in br-isp1-v4 br-isp2-v4 br-isp1-v6 br-isp2-v6; do
        ip link del "$br" 2>/dev/null || true
    done
    echo "Logs preserved in: $TMPDIR"
}

mc_pre_cleanup() {
    pkill -x "vxlan-controller" 2>/dev/null || true
    sleep 0.5
    for i in 1 2 3 4 10; do
        ip netns del "node-$i" 2>/dev/null || true
        ip netns del "leaf-$i" 2>/dev/null || true
    done
    for i in 1 2 3 4 10; do
        for isp in 1 2; do
            for af in v4 v6; do
                ip link del "vr-i${isp}-${af}-${i}" 2>/dev/null || true
            done
        done
        ip link del "veth-leaf-c-$i" 2>/dev/null || true
    done
    for br in br-isp1-v4 br-isp2-v4 br-isp1-v6 br-isp2-v6; do
        ip link del "$br" 2>/dev/null || true
    done
}

# connect_isp NODE ISP_NUM AF IP_CIDR
#   ISP_NUM: 1 or 2
#   AF: v4 or v6
connect_isp() {
    local node=$1 isp=$2 af=$3 ip_cidr=$4
    # Names must fit IFNAMSIZ (15 chars). e.g. "vr-i1-v4-10" = 11.
    local veth_root="vr-i${isp}-${af}-${node}"
    local veth_ns="ei${isp}-${af}"
    local br="br-isp${isp}-${af}"

    ip link add "$veth_root" type veth peer name "$veth_ns"
    ip link set "$veth_ns" netns "node-$node"
    ip link set "$veth_root" master "$br"
    ip link set "$veth_root" up
    local af_byte=4
    [ "$af" = "v6" ] && af_byte=6
    local mac=$(printf "02:cc:%02x:%02x:%02x:%02x" "$isp" "$af_byte" "$node" $((RANDOM%256)))
    ip netns exec "node-$node" ip link set "$veth_ns" address "$mac"
    ip netns exec "node-$node" ip link set "$veth_ns" up
    ip netns exec "node-$node" ip addr add "$ip_cidr" dev "$veth_ns"
}

setup_topology_mc() {
    mc_pre_cleanup

    echo "=== Creating namespaces ==="
    for i in 1 2 3 4 10; do
        ip netns add "node-$i"
        CLEANUP_NS+=("node-$i")
        ip netns exec "node-$i" ip link set lo up
        # Enable IPv6 in the netns
        ip netns exec "node-$i" sysctl -w net.ipv6.conf.all.disable_ipv6=0 > /dev/null
        ip netns exec "node-$i" sysctl -w net.ipv6.conf.default.disable_ipv6=0 > /dev/null
    done
    for i in 1 2 3 4; do
        ip netns add "leaf-$i"
        CLEANUP_NS+=("leaf-$i")
        ip netns exec "leaf-$i" ip link set lo up
    done

    echo "=== Creating ISP L2 LANs ==="
    for br in br-isp1-v4 br-isp2-v4 br-isp1-v6 br-isp2-v6; do
        ip link add "$br" type bridge
        ip link set "$br" up
    done

    # All clients on both ISPs, both AFs.
    for i in 1 2 3 4 10; do
        connect_isp $i 1 v4 "${ISP1_V4}.${i}/24"
        connect_isp $i 2 v4 "${ISP2_V4}.${i}/24"
        connect_isp $i 1 v6 "${ISP1_V6}${i}/64"
        connect_isp $i 2 v6 "${ISP2_V6}${i}/64"
    done

    echo "=== Setting up leaf veths ==="
    for i in 1 2 3 4; do
        local veth_client="veth-leaf-c-$i"
        local veth_leaf="veth-leaf-l-$i"
        ip link add "$veth_client" type veth peer name "$veth_leaf"
        ip link set "$veth_client" netns "node-$i"
        ip link set "$veth_leaf" netns "leaf-$i"
        local leaf_mac=$(printf "02:cc:ee:00:00:%02x" $i)
        ip netns exec "leaf-$i" ip link set "$veth_leaf" address "$leaf_mac"
        ip netns exec "leaf-$i" ip link set "$veth_leaf" up
        ip netns exec "leaf-$i" ip addr add "${LEAF_V4}.${i}/24" dev "$veth_leaf"

        ip netns exec "node-$i" ip link add "$BRIDGE_NAME" type bridge
        ip netns exec "node-$i" ip link set "$BRIDGE_NAME" up
        ip netns exec "node-$i" ip link set "$veth_client" master "$BRIDGE_NAME"
        ip netns exec "node-$i" ip link set "$veth_client" up
    done

    # Wait for IPv6 DAD
    sleep 2

    # Seed bridge FDB so unicast works before VXLAN is fully programmed
    for i in 1 2 3 4; do
        ip netns exec "leaf-$i" arping -c 1 -A -I "veth-leaf-l-$i" "${LEAF_V4}.${i}" > /dev/null 2>&1 || true
    done

    echo "=== ISP basic reachability check ==="
    ip netns exec node-1 ping -c 1 -W 2 ${ISP1_V4}.2 > /dev/null 2>&1 && echo "  ISP1 v4: 1->2 OK" || echo "  ISP1 v4: 1->2 FAIL"
    ip netns exec node-1 ping -c 1 -W 2 ${ISP2_V4}.2 > /dev/null 2>&1 && echo "  ISP2 v4: 1->2 OK" || echo "  ISP2 v4: 1->2 FAIL"
    ip netns exec node-1 ping6 -c 1 -W 2 "${ISP1_V6}2" > /dev/null 2>&1 && echo "  ISP1 v6: 1->2 OK" || echo "  ISP1 v6: 1->2 FAIL"
    ip netns exec node-1 ping6 -c 1 -W 2 "${ISP2_V6}2" > /dev/null 2>&1 && echo "  ISP2 v6: 1->2 OK" || echo "  ISP2 v6: 1->2 FAIL"
}

# Apply uniform delay to all node ISP egress (helpful for "no-delay" tests).
set_default_delays() {
    for i in 1 2 3 4 10; do
        for isp in 1 2; do
            for af in v4 v6; do
                ip netns exec "node-$i" tc qdisc add dev "ei${isp}-${af}" root netem delay 1ms 2>/dev/null || true
            done
        done
    done
}

# Set delay on a single (node, isp, af).
set_link_delay() {
    local node=$1 isp=$2 af=$3 delay=$4
    local dev="ei${isp}-${af}"
    ip netns exec "node-$node" tc qdisc del dev "$dev" root 2>/dev/null || true
    ip netns exec "node-$node" tc qdisc add dev "$dev" root netem delay "${delay}ms"
}

# Set 100% loss on a single (node, isp, af) — simulate ISP outage.
set_link_down() {
    local node=$1 isp=$2 af=$3
    local dev="ei${isp}-${af}"
    ip netns exec "node-$node" tc qdisc del dev "$dev" root 2>/dev/null || true
    ip netns exec "node-$node" tc qdisc add dev "$dev" root netem loss 100%
}

# Restore a single (node, isp, af) to default 1ms delay.
restore_link() {
    local node=$1 isp=$2 af=$3
    local dev="ei${isp}-${af}"
    ip netns exec "node-$node" tc qdisc del dev "$dev" root 2>/dev/null || true
    ip netns exec "node-$node" tc qdisc add dev "$dev" root netem delay 1ms
}

# Write a controller config with two channels per AF (v4: ISP1+ISP2, v6: ISP1+ISP2).
write_mc_controller_config() {
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
  probe_interval_s: 3
  probe_times: 5
  in_probe_interval_ms: 50
  probe_timeout_ms: 500
address_families:
  v4:
    ISP1:
      enable: true
      bind_addr: "${ISP1_V4}.${node}"
      bind_device: "ei1-v4"
      communication_port: ${COMM_PORT_V4}
      vxlan_vni: ${VNI}
      vxlan_dst_port: ${VXLAN_DSTPORT}
      vxlan_src_port_start: ${VXLAN_DSTPORT}
      vxlan_src_port_end: ${VXLAN_DSTPORT}
    ISP2:
      enable: true
      bind_addr: "${ISP2_V4}.${node}"
      bind_device: "ei2-v4"
      communication_port: ${COMM_PORT_V4_ISP2}
      vxlan_vni: ${VNI}
      vxlan_dst_port: $((VXLAN_DSTPORT + 1))
      vxlan_src_port_start: $((VXLAN_DSTPORT + 1))
      vxlan_src_port_end: $((VXLAN_DSTPORT + 1))
  v6:
    ISP1:
      enable: true
      bind_addr: "${ISP1_V6}${node}"
      bind_device: "ei1-v6"
      communication_port: ${COMM_PORT_V6}
      vxlan_vni: ${VNI}
      vxlan_dst_port: $((VXLAN_DSTPORT + 2))
      vxlan_src_port_start: $((VXLAN_DSTPORT + 2))
      vxlan_src_port_end: $((VXLAN_DSTPORT + 2))
    ISP2:
      enable: true
      bind_addr: "${ISP2_V6}${node}"
      bind_device: "ei2-v6"
      communication_port: ${COMM_PORT_V6_ISP2}
      vxlan_vni: ${VNI}
      vxlan_dst_port: $((VXLAN_DSTPORT + 3))
      vxlan_src_port_start: $((VXLAN_DSTPORT + 3))
      vxlan_src_port_end: $((VXLAN_DSTPORT + 3))
allowed_clients:
YAML
    for i in 1 2 3 4; do
        local pub_var="PUB_$i"
        cat >> "$f" << YAML
  - client_id: "${!pub_var}"
    client_name: "node-${i}"
YAML
    done
    echo "$f"
}

# Write a client config with optional bind_device overrides.
# Args:
#   $1 = node number
#   $2 = privkey
#   $3 = bind_method ("addr" | "device")
write_mc_client_config() {
    local node=$1 privkey=$2 method=${3:-addr}
    local f="$TMPDIR/client-${node}.yaml"

    cat > "$f" << YAML
private_key: "${privkey}"
bridge_name: "${BRIDGE_NAME}"
clamp_mss_to_mtu: false
neigh_suppress: false
vxlan_firewall: false
init_timeout: ${INIT_TIMEOUT}
probe_window_size: 5
af_switch_cost: 25
ntp_servers: []
address_families:
YAML

    write_mc_client_channel() {
        local af=$1 isp=$2 bind_addr=$3 probe_port=$4 comm_port=$5 vxlan_name=$6 vxlan_dst_port=$7 ctrl_addr=$8
        # Multi-channel AFs require bind_device (egress is destination-routed;
        # a bind IP alone cannot pin the uplink), so always emit it.
        local dev_line="      bind_device: \"ei${isp}-${af}\""
        cat << YAML
    ISP${isp}:
      enable: true
      bind_addr: "${bind_addr}"
${dev_line:+${dev_line}}
      probe_port: ${probe_port}
      communication_port: ${comm_port}
      vxlan_name: "${vxlan_name}"
      vxlan_vni: ${VNI}
      vxlan_mtu: ${VXLAN_MTU}
      vxlan_dst_port: ${vxlan_dst_port}
      vxlan_src_port_start: ${vxlan_dst_port}
      vxlan_src_port_end: ${vxlan_dst_port}
      priority: 10
      forward_cost: 20
      controllers:
        - pubkey: "${PUB_10}"
          addr: "${ctrl_addr}"
YAML
    }

    echo "  v4:" >> "$f"
    write_mc_client_channel v4 1 "${ISP1_V4}.${node}" $PROBE_PORT_V4   $COMM_PORT_V4      "vxlan-v4-ISP1" $VXLAN_DSTPORT          "${ISP1_V4}.10:${COMM_PORT_V4}" >> "$f"
    write_mc_client_channel v4 2 "${ISP2_V4}.${node}" $PROBE_PORT_V4_ISP2 $COMM_PORT_V4_ISP2 "vxlan-v4-ISP2" $((VXLAN_DSTPORT + 1)) "${ISP2_V4}.10:${COMM_PORT_V4_ISP2}" >> "$f"
    echo "  v6:" >> "$f"
    write_mc_client_channel v6 1 "${ISP1_V6}${node}" $PROBE_PORT_V6   $COMM_PORT_V6      "vxlan-v6-ISP1" $((VXLAN_DSTPORT + 2)) "[${ISP1_V6}10]:${COMM_PORT_V6}" >> "$f"
    write_mc_client_channel v6 2 "${ISP2_V6}${node}" $PROBE_PORT_V6_ISP2 $COMM_PORT_V6_ISP2 "vxlan-v6-ISP2" $((VXLAN_DSTPORT + 3)) "[${ISP2_V6}10]:${COMM_PORT_V6_ISP2}" >> "$f"

    echo "$f"
}

generate_mc_configs() {
    local method=${1:-addr}
    CTRL_10_CONF=$(write_mc_controller_config 10 "$PRIV_10")
    CLIENT_1_CONF=$(write_mc_client_config 1 "$PRIV_1" "$method")
    CLIENT_2_CONF=$(write_mc_client_config 2 "$PRIV_2" "$method")
    CLIENT_3_CONF=$(write_mc_client_config 3 "$PRIV_3" "$method")
    CLIENT_4_CONF=$(write_mc_client_config 4 "$PRIV_4" "$method")
}

mc_start_process() {
    local ns=$1 mode=$2 config=$3 logname=$4
    ip netns exec "$ns" "$PROJECT_DIR/vxlan-controller" -mode "$mode" -config "$config" -log-level verbose > "$TMPDIR/${logname}.log" 2>&1 &
    local pid=$!
    CLEANUP_PIDS+=("$pid")
    echo "  $logname started (PID=$pid)"
}

mc_start_controllers() {
    echo "=== Starting controllers ==="
    mc_start_process node-10 controller "$CTRL_10_CONF" "ctrl-10"
    sleep 1.5
}

mc_start_clients() {
    echo "=== Starting clients ==="
    mc_start_process node-1 client "$CLIENT_1_CONF" "client-1"
    mc_start_process node-2 client "$CLIENT_2_CONF" "client-2"
    mc_start_process node-3 client "$CLIENT_3_CONF" "client-3"
    mc_start_process node-4 client "$CLIENT_4_CONF" "client-4"
}

mc_wait_converge() {
    local wait=${1:-12}
    echo "=== Waiting ${wait}s for convergence ==="
    sleep "$wait"
}

mc_run_test() {
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

mc_print_results() {
    echo ""
    echo "==========================================="
    echo "  Results: ${test_pass}/${test_total} passed, ${test_fail} failed"
    echo "==========================================="

    if [ $test_fail -gt 0 ]; then
        echo ""
        echo "=== Recent logs (last 25 lines each) ==="
        for f in "$TMPDIR"/*.log; do
            echo "--- $(basename $f) ---"
            tail -25 "$f" 2>/dev/null || true
        done
    fi
}
