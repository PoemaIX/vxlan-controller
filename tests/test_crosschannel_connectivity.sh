#!/bin/bash
# Cross-channel (per-node ISP labels) test.
#
# Every node names its uplinks differently (kskbix style) — no channel name
# is shared between any two nodes. Verifies:
#   - client-client probing pairs channels across names (full AF cross-product)
#   - routing picks the lowest-latency (local, peer) pair and switches when
#     latencies change
#   - FDB entries use the peer channel's endpoint + vxlan_dst_port override
#   - controller connections rotate to the next address when the first
#     controller uplink is unreachable
#
# Topology (reuses the mc bridges):
#   node-1: n1a = br-isp1 10.1.1.1 (vxlan 4789), n1b = br-isp2 10.2.1.1 (4790)
#   node-2: n2a = br-isp1 10.1.1.2 (vxlan 4791), n2b = br-isp2 10.2.1.2 (4793)
#   node-3: n3b = br-isp2 10.2.1.3 (vxlan 4792) ONLY; its br-isp1 link is down
#   node-10 (controller): c1 = 10.1.1.10:6000, c2 = 10.2.1.10:6010

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/multichannel_helpers.sh"

trap mc_cleanup EXIT

build_binaries
generate_keys
setup_topology_mc
set_default_delays

# node-3 is single-homed on br-isp2: take its ISP1 links down entirely.
ip netns exec node-3 ip link set ei1-v4 down
ip netns exec node-3 ip link set ei1-v6 down

# Start with br-isp1 slow between node-1 and node-2 so the first preferred
# pair is (n1b > n2b) over br-isp2.
set_link_delay 1 1 v4 30
set_link_delay 2 1 v4 30

write_cc_controller_config() {
    local f="$TMPDIR/controller-10.yaml"
    cat > "$f" << YAML
private_key: "${PRIV_10}"
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
    c1:
      enable: true
      bind_addr: "${ISP1_V4}.10"
      communication_port: ${COMM_PORT_V4}
      vxlan_vni: ${VNI}
      vxlan_dst_port: ${VXLAN_DSTPORT}
      vxlan_src_port_start: ${VXLAN_DSTPORT}
      vxlan_src_port_end: ${VXLAN_DSTPORT}
    c2:
      enable: true
      bind_addr: "${ISP2_V4}.10"
      communication_port: ${COMM_PORT_V4_ISP2}
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
YAML
    CTRL_10_CONF="$f"
}

# write_cc_channel CHNAME BIND_ADDR PROBE_PORT VXLAN_NAME VXLAN_PORT
write_cc_channel() {
    local chname=$1 bind_addr=$2 probe_port=$3 vxlan_name=$4 vxlan_port=$5
    cat << YAML
    ${chname}:
      enable: true
      bind_addr: "${bind_addr}"
      probe_port: ${probe_port}
      communication_port: 0
      vxlan_name: "${vxlan_name}"
      vxlan_vni: ${VNI}
      vxlan_mtu: ${VXLAN_MTU}
      vxlan_dst_port: ${vxlan_port}
      vxlan_src_port_start: ${vxlan_port}
      vxlan_src_port_end: ${vxlan_port}
      priority: 10
      forward_cost: 20
      controllers:
        - pubkey: "${PUB_10}"
          addr: "${ISP1_V4}.10:${COMM_PORT_V4}"
        - pubkey: "${PUB_10}"
          addr: "${ISP2_V4}.10:${COMM_PORT_V4_ISP2}"
YAML
}

write_cc_client_config() {
    local node=$1 privkey=$2
    local f="$TMPDIR/client-${node}.yaml"
    cat > "$f" << YAML
private_key: "${privkey}"
bridge_name: "${BRIDGE_NAME}"
clamp_mss_to_mtu: false
neigh_suppress: false
vxlan_firewall: false
init_timeout: ${INIT_TIMEOUT}
controller_idle_timeout: 12
probe_window_size: 5
af_switch_cost: 25
ntp_servers: []
address_families:
  v4:
YAML
    case "$node" in
        1)
            write_cc_channel n1a "${ISP1_V4}.1" $PROBE_PORT_V4      vx-n1a 4789 >> "$f"
            write_cc_channel n1b "${ISP2_V4}.1" $PROBE_PORT_V4_ISP2 vx-n1b 4790 >> "$f"
            ;;
        2)
            write_cc_channel n2a "${ISP1_V4}.2" $PROBE_PORT_V4      vx-n2a 4791 >> "$f"
            write_cc_channel n2b "${ISP2_V4}.2" $PROBE_PORT_V4_ISP2 vx-n2b 4793 >> "$f"
            ;;
        3)
            write_cc_channel n3b "${ISP2_V4}.3" $PROBE_PORT_V4_ISP2 vx-n3b 4792 >> "$f"
            ;;
    esac
    eval "CLIENT_${node}_CONF=\$f"
}

write_cc_controller_config
write_cc_client_config 1 "$PRIV_1"
write_cc_client_config 2 "$PRIV_2"
write_cc_client_config 3 "$PRIV_3"

mc_start_controllers
echo "=== Starting clients ==="
mc_start_process node-1 client "$CLIENT_1_CONF" "client-1"
mc_start_process node-2 client "$CLIENT_2_CONF" "client-2"
mc_start_process node-3 client "$CLIENT_3_CONF" "client-3"

# Cross-channel pairing probes every (local, peer) combo and the first probe
# round serializes session handshakes — allow extra convergence headroom.
mc_wait_converge 30

leaf_mac() { printf "02:cc:ee:00:00:%02x" "$1"; }

# fdb_uses NODE DEV MAC DST [PORT]
fdb_uses() {
    local node=$1 dev=$2 mac=$3 dst=$4 port=${5:-}
    local out
    out=$(ip netns exec "node-$node" bridge fdb show dev "$dev" 2>/dev/null | grep -i "^$mac" | grep "dst $dst") || return 1
    if [ -n "$port" ]; then
        echo "$out" | grep -q "port $port" || return 1
    fi
    return 0
}

# fdb_uses_dst NODE MAC DST PORT — like fdb_uses but on any local vxlan
# device. Without bind_device the kernel routes by dst, so which LOCAL channel
# the entry lives on is an arbitrary tie-break; the dst endpoint (peer channel
# + its vxlan port) is what determines the path taken.
fdb_uses_dst() {
    local node=$1 mac=$2 dst=$3 port=$4
    ip netns exec "node-$node" bridge fdb show 2>/dev/null \
        | grep -i "^$mac" | grep "dst $dst" | grep -q "port $port"
}

ping_leaf() {
    local from=$1 to=$2
    ip netns exec "leaf-$from" ping -c 2 -W 3 "${LEAF_V4}.${to}"
}

# Convergence time varies under load (cross-product probing serializes the
# first round of session handshakes), so initial checks retry with a deadline
# instead of asserting a snapshot after a guessed sleep.
wait_ping_leaf() {
    local from=$1 to=$2 timeout=${3:-60}
    local deadline=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if ping_leaf "$from" "$to" > /dev/null 2>&1; then
            return 0
        fi
        sleep 3
    done
    return 1
}

wait_fdb_uses_dst() {
    local node=$1 mac=$2 dst=$3 port=$4 timeout=${5:-60}
    local deadline=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if fdb_uses_dst "$node" "$mac" "$dst" "$port"; then
            return 0
        fi
        sleep 3
    done
    return 1
}

wait_fdb_uses() {
    local node=$1 dev=$2 mac=$3 dst=$4 port=$5 timeout=${6:-60}
    local deadline=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if fdb_uses "$node" "$dev" "$mac" "$dst" "$port"; then
            return 0
        fi
        sleep 3
    done
    return 1
}

echo ""
echo "=== Test: cross-name full-mesh connectivity ==="
mc_run_test "leaf-1 -> leaf-2" wait_ping_leaf 1 2
mc_run_test "leaf-1 -> leaf-3" wait_ping_leaf 1 3
mc_run_test "leaf-2 -> leaf-3" wait_ping_leaf 2 3

echo ""
echo "=== Test: node-3 rotated to the controller's second address ==="
# node-3's first configured controller address (10.1.1.10) is unreachable;
# the client must fail over to 10.2.1.10 and still sync.
mc_run_test "node-3 logged failure on first ctrl addr" \
    grep -q "addr=${ISP1_V4}.10:${COMM_PORT_V4}.*failed" "$TMPDIR/client-3.log"
mc_run_test "node-3 synced with controller" \
    grep -q "handshake completed with controller" "$TMPDIR/client-3.log"

echo ""
echo "=== Test: br-isp1 slow -> node-1/node-2 send toward the peer's br-isp2 endpoint ==="
# node-1 reaches leaf-2's MAC via node-2's n2b endpoint (10.2.1.2, vxlan port
# 4793 — a per-entry port override since no local device uses 4793).
mc_run_test "node-1 fdb: leaf-2 -> dst ${ISP2_V4}.2 port 4793 (n2b)" \
    wait_fdb_uses_dst 1 "$(leaf_mac 2)" "${ISP2_V4}.2" 4793
mc_run_test "node-2 fdb: leaf-1 -> dst ${ISP2_V4}.1 port 4790 (n1b)" \
    wait_fdb_uses_dst 2 "$(leaf_mac 1)" "${ISP2_V4}.1" 4790
# node-3 only has n3b; its route to node-1 must use node-1's n1b endpoint.
mc_run_test "node-3 fdb: leaf-1 via vx-n3b dst ${ISP2_V4}.1 port 4790" \
    wait_fdb_uses 3 vx-n3b "$(leaf_mac 1)" "${ISP2_V4}.1" 4790

echo ""
echo "=== Flipping delays: br-isp1 fast, br-isp2 slow ==="
restore_link 1 1 v4
restore_link 2 1 v4
set_link_delay 1 2 v4 30
set_link_delay 2 2 v4 30
mc_wait_converge 30

echo "=== Test: after flip -> node-1/node-2 switch to the peer's br-isp1 endpoint ==="
mc_run_test "node-1 fdb: leaf-2 -> dst ${ISP1_V4}.2 port 4791 (n2a)" \
    wait_fdb_uses_dst 1 "$(leaf_mac 2)" "${ISP1_V4}.2" 4791
mc_run_test "node-2 fdb: leaf-1 -> dst ${ISP1_V4}.1 port 4789 (n1a)" \
    wait_fdb_uses_dst 2 "$(leaf_mac 1)" "${ISP1_V4}.1" 4789
mc_run_test "leaf-1 -> leaf-2 still works" ping_leaf 1 2
# node-3 still reaches node-1 via br-isp2 (its only uplink), now slower but
# the only viable pair.
mc_run_test "leaf-1 -> leaf-3 still works" ping_leaf 1 3

echo ""
echo "=== Test: broadcast relay from the single-homed node ==="
# Flush leaf-3's ARP cache so the ping starts with a broadcast ARP. node-3's
# relay must target the controller address it is actually connected to
# (10.2.1.10), not the first configured (unreachable) one.
ip netns exec leaf-3 ip neigh flush all
mc_run_test "leaf-3 -> leaf-2 (fresh ARP via relay)" ping_leaf 3 2

echo ""
echo "=== Test: controller uplink dies mid-run -> clients rotate addresses ==="
# Take the controller's br-isp1 uplink down. Established conns to 10.1.1.10 go
# silent (no RST); clients must detect via write deadline / idle timeout and
# rotate to 10.2.1.10 on their br-isp2-bound channels. To prove the control
# plane is actually alive again (not just data-plane inertia), flip the link
# delays and require the routes to follow.
ip netns exec node-10 ip link set ei1-v4 down

# Current state: br1 fast (preferred), br2 slow. Flip: br1 slow, br2 fast.
restore_link 1 2 v4
restore_link 2 2 v4
set_link_delay 1 1 v4 30
set_link_delay 2 1 v4 30

mc_run_test "node-1 route follows flip via rotated ctrl conn (dst n2b)" \
    wait_fdb_uses_dst 1 "$(leaf_mac 2)" "${ISP2_V4}.2" 4793 150
mc_run_test "node-2 route follows flip via rotated ctrl conn (dst n1b)" \
    wait_fdb_uses_dst 2 "$(leaf_mac 1)" "${ISP2_V4}.1" 4790 150
mc_run_test "leaf-1 -> leaf-2 still works after ctrl uplink loss" \
    wait_ping_leaf 1 2
mc_run_test "leaf-1 -> leaf-3 still works after ctrl uplink loss" \
    wait_ping_leaf 1 3

mc_print_results

if [ $test_fail -gt 0 ]; then
    exit 1
fi
echo ""
echo "PASS: cross-channel pairing selects lowest-latency links"
