#!/bin/bash
# Latency-driven multi-hop reroute.
#
# Existing latency tests only exercise switching between DIRECT pairs. This
# one verifies the controller's Floyd-Warshall actually reroutes through a
# transit node when every direct pair between two nodes becomes slow:
#
#   - node-1 <-> node-2 direct edges: 100ms  (cost ~120 with forward_cost 20)
#   - node-1 <-> node-3 and node-3 <-> node-2: 1ms (2-hop cost ~42)
#   => route node-1 -> node-2 must go via node-3, and back to direct after
#      the delay is removed.
#
# Delays are keyed on DESTINATION addresses (u32 filters), because without
# bind_device the kernel picks the egress dev by dst — this also keeps the
# node-1 <-> node-4 edges slow so node-3 is the only attractive transit.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/multichannel_helpers.sh"
trap mc_cleanup EXIT

build_binaries
generate_keys
setup_topology_mc
set_default_delays

echo "=== Generating multi-channel configurations (bind_addr method) ==="
generate_mc_configs addr

mc_start_controllers
mc_start_clients
mc_wait_converge 25

leaf_mac() {
    ip netns exec "leaf-$1" cat /sys/class/net/veth-leaf-l-$1/address
}
get_fdb_dst() {
    ip netns exec "node-$1" bridge fdb show | awk -v m="$2" '
        $1 == m && /self/ { for (i=1;i<NF;i++) if ($i=="dst") print $(i+1) }' | head -1
}

LEAF1_MAC=$(leaf_mac 1)
LEAF2_MAC=$(leaf_mac 2)

# wait_fdb_dst_in NAME NODE MAC TIMEOUT PATTERN...
# Waits until the FDB dst for MAC matches one of the given shell patterns.
wait_fdb_dst_in() {
    local name=$1 node=$2 mac=$3 timeout=$4
    shift 4
    local deadline=$((SECONDS + timeout)) dst pat
    test_total=$((test_total + 1))
    while [ "$SECONDS" -lt "$deadline" ]; do
        dst=$(get_fdb_dst "$node" "$mac")
        for pat in "$@"; do
            # shellcheck disable=SC2254
            case "$dst" in
                $pat)
                    echo "  TEST: $name ... PASS (dst=$dst)"
                    test_pass=$((test_pass + 1))
                    return 0
                    ;;
            esac
        done
        sleep 3
    done
    echo "  TEST: $name ... FAIL (dst=${dst:-none})"
    test_fail=$((test_fail + 1))
    return 1
}

# slow_direct NODE PEER_A PEER_B
# On node NODE: v4 traffic to PEER_A/PEER_B hosts gets 100ms, everything else
# 1ms; v6 egress is blanket-slowed so v4 transit stays the winner.
slow_direct() {
    local node=$1 peer_a=$2 peer_b=$3
    local dev sub
    for dev in ei1-v4 ei2-v4; do
        sub="$ISP1_V4"
        [ "$dev" = "ei2-v4" ] && sub="$ISP2_V4"
        ip netns exec "node-$node" tc qdisc del dev "$dev" root 2>/dev/null || true
        ip netns exec "node-$node" tc qdisc add dev "$dev" root handle 1: prio bands 3 \
            priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
        ip netns exec "node-$node" tc qdisc add dev "$dev" parent 1:1 handle 10: netem delay 1ms
        ip netns exec "node-$node" tc qdisc add dev "$dev" parent 1:2 handle 20: netem delay 100ms
        ip netns exec "node-$node" tc qdisc add dev "$dev" parent 1:3 handle 30: netem delay 100ms
        ip netns exec "node-$node" tc filter add dev "$dev" parent 1:0 protocol ip prio 1 \
            u32 match ip dst "${sub}.${peer_a}/32" flowid 1:2
        ip netns exec "node-$node" tc filter add dev "$dev" parent 1:0 protocol ip prio 2 \
            u32 match ip dst "${sub}.${peer_b}/32" flowid 1:2
    done
    set_link_delay "$node" 1 v6 120
    set_link_delay "$node" 2 v6 120
}

restore_node() {
    local node=$1 dev
    for dev in ei1-v4 ei2-v4; do
        ip netns exec "node-$node" tc qdisc del dev "$dev" root 2>/dev/null || true
        ip netns exec "node-$node" tc qdisc add dev "$dev" root netem delay 1ms
    done
    restore_link "$node" 1 v6
    restore_link "$node" 2 v6
}

echo ""
echo "=== Baseline: direct route node-1 <-> node-2 ==="
mc_run_test "baseline ping leaf-1 -> leaf-2" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2
wait_fdb_dst_in "node-1 -> leaf-2 baseline is direct (dst = node-2)" \
    1 "$LEAF2_MAC" 90 "${ISP1_V4}.2" "${ISP2_V4}.2" "${ISP1_V6}2" "${ISP2_V6}2"

echo ""
echo "=== Slowing every direct edge between node-1 and node-2 (and node-4 detour) ==="
slow_direct 1 2 4
slow_direct 2 1 4

echo "=== Expect reroute through node-3 ==="
wait_fdb_dst_in "node-1 -> leaf-2 reroutes via node-3" \
    1 "$LEAF2_MAC" 120 "${ISP1_V4}.3" "${ISP2_V4}.3"
wait_fdb_dst_in "node-2 -> leaf-1 reroutes via node-3" \
    2 "$LEAF1_MAC" 120 "${ISP1_V4}.3" "${ISP2_V4}.3"
mc_run_test "ping leaf-1 -> leaf-2 through transit still works" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2

echo ""
echo "=== Restoring direct edges ==="
restore_node 1
restore_node 2

wait_fdb_dst_in "node-1 -> leaf-2 returns to direct (dst = node-2)" \
    1 "$LEAF2_MAC" 120 "${ISP1_V4}.2" "${ISP2_V4}.2" "${ISP1_V6}2" "${ISP2_V6}2"
mc_run_test "ping leaf-1 -> leaf-2 after restore" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2

mc_print_results

if [ $test_fail -gt 0 ]; then
    exit 1
fi
echo ""
echo "PASS: latency change triggers multi-hop reroute and recovery"
