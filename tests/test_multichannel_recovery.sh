#!/bin/bash
# Multi-channel fastest-path and full-isolation recovery test.
#
# Covers two per-af-channels invariants that are easy to miss:
#   1. Different peers can use different fastest channels at the same time.
#   2. After a node loses all channels, restoring any single channel brings
#      it back online.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/multichannel_helpers.sh"
trap mc_cleanup EXIT

build_binaries
generate_keys
setup_topology_mc

echo "=== Generating multi-channel configurations (bind_addr method) ==="
generate_mc_configs addr

mc_start_controllers
mc_start_clients
mc_wait_converge 18

leaf_mac() {
    local n=$1
    ip netns exec "leaf-$n" cat /sys/class/net/veth-leaf-l-$n/address
}

get_fdb_iface() {
    local node=$1 mac=$2
    ip netns exec "node-$node" bridge fdb show | awk -v m="$mac" '
        $1 == m && /self/ { print $3 }' | head -1
}

# FDB dst address for a MAC. With channel-pair routing the local device is an
# arbitrary tie-break (no bind_device -> kernel routes by dst); the dst
# address is what actually selects the underlay path, so assert on that.
get_fdb_dst() {
    local node=$1 mac=$2
    ip netns exec "node-$node" bridge fdb show | awk -v m="$mac" '
        $1 == m && /self/ { for (i=1;i<NF;i++) if ($i=="dst") print $(i+1) }' | head -1
}

# Peer node-N's address on a given (isp, af) LAN.
peer_addr_for() {
    local isp=$1 af=$2 peer=$3
    if [ "$af" = "v4" ]; then
        if [ "$isp" = "1" ]; then echo "${ISP1_V4}.${peer}"; else echo "${ISP2_V4}.${peer}"; fi
    else
        if [ "$isp" = "1" ]; then echo "${ISP1_V6}${peer}"; else echo "${ISP2_V6}${peer}"; fi
    fi
}

restore_node1_all_channels() {
    local loop_isp loop_af
    for loop_isp in 1 2; do
        for loop_af in v4 v6; do
            restore_link 1 "$loop_isp" "$loop_af"
        done
    done
}

set_node1_all_channels_down() {
    local loop_isp loop_af
    for loop_isp in 1 2; do
        for loop_af in v4 v6; do
            set_link_down 1 "$loop_isp" "$loop_af"
        done
    done
}

assert_fdb_iface() {
    local name=$1 node=$2 mac=$3 want=$4
    local got
    got=$(get_fdb_iface "$node" "$mac")
    test_total=$((test_total + 1))
    if [ "$got" = "$want" ]; then
        echo "  TEST: $name ... PASS"
        test_pass=$((test_pass + 1))
    else
        echo "  TEST: $name ... FAIL (got ${got:-none}, want $want)"
        test_fail=$((test_fail + 1))
    fi
}

wait_fdb_iface() {
    local name=$1 node=$2 mac=$3 want=$4 timeout=${5:-70}
    local deadline=$((SECONDS + timeout))
    local got=""

    test_total=$((test_total + 1))
    while [ "$SECONDS" -lt "$deadline" ]; do
        got=$(get_fdb_iface "$node" "$mac")
        if [ "$got" = "$want" ]; then
            echo "  TEST: $name ... PASS"
            test_pass=$((test_pass + 1))
            return
        fi
        sleep 2
    done

    echo "  TEST: $name ... FAIL (got ${got:-none}, want $want)"
    test_fail=$((test_fail + 1))
}

assert_fdb_dst() {
    local name=$1 node=$2 mac=$3 want=$4
    local got
    got=$(get_fdb_dst "$node" "$mac")
    test_total=$((test_total + 1))
    if [ "$got" = "$want" ]; then
        echo "  TEST: $name ... PASS"
        test_pass=$((test_pass + 1))
    else
        echo "  TEST: $name ... FAIL (got ${got:-none}, want $want)"
        test_fail=$((test_fail + 1))
    fi
}

wait_fdb_dst() {
    local name=$1 node=$2 mac=$3 want=$4 timeout=${5:-70}
    local deadline=$((SECONDS + timeout))
    local got=""

    test_total=$((test_total + 1))
    while [ "$SECONDS" -lt "$deadline" ]; do
        got=$(get_fdb_dst "$node" "$mac")
        if [ "$got" = "$want" ]; then
            echo "  TEST: $name ... PASS"
            test_pass=$((test_pass + 1))
            return
        fi
        sleep 2
    done

    echo "  TEST: $name ... FAIL (got ${got:-none}, want $want)"
    test_fail=$((test_fail + 1))
}

assert_ping_fails() {
    local name=$1; shift
    test_total=$((test_total + 1))
    echo -n "  TEST: $name ... "
    if "$@" > /dev/null 2>&1; then
        echo "FAIL"
        test_fail=$((test_fail + 1))
    else
        echo "PASS"
        test_pass=$((test_pass + 1))
    fi
}

wait_ping_succeeds() {
    local name=$1 timeout=$2
    shift 2
    local deadline=$((SECONDS + timeout))

    test_total=$((test_total + 1))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if "$@" > /dev/null 2>&1; then
            echo "  TEST: $name ... PASS"
            test_pass=$((test_pass + 1))
            return
        fi
        sleep 2
    done

    echo "  TEST: $name ... FAIL"
    test_fail=$((test_fail + 1))
}

set_node1_peer_specific_delays() {
    # node-1 -> node-2 fastest on v4/ISP1.
    # node-1 -> node-3 fastest on v4/ISP2.
    # v6 is kept slow so the assertion is deterministic.
    restore_node1_all_channels

    ip netns exec node-1 tc qdisc del dev ei1-v4 root 2>/dev/null || true
    ip netns exec node-1 tc qdisc add dev ei1-v4 root handle 1: prio bands 3 \
        priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    ip netns exec node-1 tc qdisc add dev ei1-v4 parent 1:1 handle 10: netem delay 1ms
    ip netns exec node-1 tc qdisc add dev ei1-v4 parent 1:2 handle 20: netem delay 90ms
    ip netns exec node-1 tc qdisc add dev ei1-v4 parent 1:3 handle 30: netem delay 90ms
    ip netns exec node-1 tc filter add dev ei1-v4 parent 1:0 protocol ip prio 1 \
        u32 match ip dst "${ISP1_V4}.2/32" flowid 1:1
    ip netns exec node-1 tc filter add dev ei1-v4 parent 1:0 protocol ip prio 2 \
        u32 match ip dst "${ISP1_V4}.3/32" flowid 1:2

    ip netns exec node-1 tc qdisc del dev ei2-v4 root 2>/dev/null || true
    ip netns exec node-1 tc qdisc add dev ei2-v4 root handle 1: prio bands 3 \
        priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    ip netns exec node-1 tc qdisc add dev ei2-v4 parent 1:1 handle 10: netem delay 1ms
    ip netns exec node-1 tc qdisc add dev ei2-v4 parent 1:2 handle 20: netem delay 90ms
    ip netns exec node-1 tc qdisc add dev ei2-v4 parent 1:3 handle 30: netem delay 90ms
    ip netns exec node-1 tc filter add dev ei2-v4 parent 1:0 protocol ip prio 1 \
        u32 match ip dst "${ISP2_V4}.3/32" flowid 1:1
    ip netns exec node-1 tc filter add dev ei2-v4 parent 1:0 protocol ip prio 2 \
        u32 match ip dst "${ISP2_V4}.2/32" flowid 1:2

    set_link_delay 1 1 v6 120
    set_link_delay 1 2 v6 120
}

LEAF2_MAC=$(leaf_mac 2)
LEAF3_MAC=$(leaf_mac 3)

echo ""
echo "=== Baseline connectivity ==="
mc_run_test "baseline ping leaf-1 -> leaf-2" \
    ip netns exec leaf-1 ping -c 3 -W 5 "${LEAF_V4}.2"
mc_run_test "baseline ping leaf-1 -> leaf-3" \
    ip netns exec leaf-1 ping -c 3 -W 5 "${LEAF_V4}.3"

echo ""
echo "=== Scenario 1: per-peer fastest channel selection ==="
set_node1_peer_specific_delays
sleep 30
mc_run_test "per-peer fastest ping leaf-1 -> leaf-2" \
    ip netns exec leaf-1 ping -c 3 -W 5 "${LEAF_V4}.2"
mc_run_test "per-peer fastest ping leaf-1 -> leaf-3" \
    ip netns exec leaf-1 ping -c 3 -W 5 "${LEAF_V4}.3"
assert_fdb_dst "node-1 -> leaf-2 uses node-2's ISP1 addr" 1 "$LEAF2_MAC" "${ISP1_V4}.2"
assert_fdb_dst "node-1 -> leaf-3 uses node-3's ISP2 addr" 1 "$LEAF3_MAC" "${ISP2_V4}.3"

restore_node1_all_channels
sleep 18

echo ""
echo "=== Scenario 2: recovery after all node-1 channels are down ==="
for spec in "2 v6" "1 v4" "2 v4" "1 v6"; do
    isp=${spec%% *}
    af=${spec##* }
    want_dst=$(peer_addr_for "$isp" "$af" 2)

    echo ""
    echo "--- Restoring only ${af}/ISP${isp} ---"
    set_node1_all_channels_down
    sleep 15

    assert_ping_fails "leaf-1 isolated when all channels are down" \
        ip netns exec leaf-1 ping -c 2 -W 3 "${LEAF_V4}.2"

    restore_link 1 "$isp" "$af"
    wait_fdb_dst "node-1 -> leaf-2 converges to only restored ${af}/ISP${isp}" \
        1 "$LEAF2_MAC" "$want_dst" 150

    wait_ping_succeeds "leaf-1 -> leaf-2 with only ${af}/ISP${isp} restored" 80 \
        ip netns exec leaf-1 ping -c 3 -W 5 "${LEAF_V4}.2"
    wait_ping_succeeds "leaf-1 -> leaf-3 with only ${af}/ISP${isp} restored" 80 \
        ip netns exec leaf-1 ping -c 3 -W 5 "${LEAF_V4}.3"
done

restore_node1_all_channels

mc_print_results
exit $test_fail
