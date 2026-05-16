#!/bin/bash
# Multi-channel failover & sticky routing test.
#
# Scenarios:
#   1. Baseline: all 4 channels healthy; pick best (lowest latency).
#   2. Latency micro-jitter on the currently-selected channel: routing
#      should NOT flap (median-of-N debounce + af_switch_cost hysteresis).
#   3. Sustained large latency on the selected (af, channel): routing
#      SHOULD switch to the formerly-slower channel.
#   4. Full outage of one ISP (100% loss): traffic continues on the other.
#   5. ISP recovery: traffic stays on the chosen channel unless it's
#      sufficiently better (hysteresis honored).
#   6. Node down: peer learns the offline node and prunes routes.
#   7. Controller down: clients keep last known routes; ping still works
#      until LastSeen ages out.

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

# Probe interval is 3s and window_size=5; we need ~5 probes to fill the window
# (~15s). Use 18s for the first stabilization, then 12s windows for changes.
mc_wait_converge 18

# Helper: report which (af, channel) is being used in node-N FDB for a given dst MAC.
get_fdb_iface() {
    local node=$1 mac=$2
    ip netns exec "node-$node" bridge fdb show | awk -v m="$mac" '
        $1 == m && /self/ { print $3 }' | head -1
}

# Helper: get the MAC of leaf-N on its veth.
leaf_mac() {
    local n=$1
    ip netns exec "leaf-$n" cat /sys/class/net/veth-leaf-l-$n/address
}

LEAF2_MAC=$(leaf_mac 2)
LEAF3_MAC=$(leaf_mac 3)

echo ""
echo "=== Scenario 1: Baseline (all 4 channels healthy) ==="
mc_run_test "baseline ping leaf-1 -> leaf-2" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2
mc_run_test "baseline ping leaf-1 -> leaf-3" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.3
init_iface_n1_to_n2=$(get_fdb_iface 1 "$LEAF2_MAC")
echo "  node-1 FDB to leaf-2 MAC ($LEAF2_MAC) uses: $init_iface_n1_to_n2"

echo ""
echo "=== Scenario 2: Sticky to small latency jitter (≤ af_switch_cost) ==="
# Add small jitter (~5ms) on node-1's currently-selected path. Switch_cost=25,
# so 5ms swing should not cause a flap.
if [ -n "$init_iface_n1_to_n2" ]; then
    case "$init_iface_n1_to_n2" in
        vxlan-v4-ISP1) jitter_dev="ei1-v4" ;;
        vxlan-v4-ISP2) jitter_dev="ei2-v4" ;;
        vxlan-v6-ISP1) jitter_dev="ei1-v6" ;;
        vxlan-v6-ISP2) jitter_dev="ei2-v6" ;;
        *) jitter_dev="" ;;
    esac
    if [ -n "$jitter_dev" ]; then
        ip netns exec node-1 tc qdisc change dev "$jitter_dev" root netem delay 6ms || \
        ip netns exec node-1 tc qdisc add dev "$jitter_dev" root netem delay 6ms
        sleep 20
        cur_iface=$(get_fdb_iface 1 "$LEAF2_MAC")
        echo "  after +5ms jitter on $jitter_dev: FDB iface = $cur_iface"
        test_total=$((test_total + 1))
        if [ "$cur_iface" = "$init_iface_n1_to_n2" ]; then
            echo "  TEST: small jitter sticky (no flap) ... PASS"
            test_pass=$((test_pass + 1))
        else
            echo "  TEST: small jitter sticky (no flap) ... FAIL (changed $init_iface_n1_to_n2 -> $cur_iface)"
            test_fail=$((test_fail + 1))
        fi
        # Restore default delay
        ip netns exec node-1 tc qdisc change dev "$jitter_dev" root netem delay 1ms || true
    fi
fi

echo ""
echo "=== Scenario 3: Sustained large latency triggers switch ==="
# Add 80ms delay on the currently-selected path. Switch_cost=25, so a 50ms+
# swing should flip the preferred channel after enough probes.
if [ -n "$init_iface_n1_to_n2" ] && [ -n "${jitter_dev:-}" ]; then
    ip netns exec node-1 tc qdisc change dev "$jitter_dev" root netem delay 80ms || \
    ip netns exec node-1 tc qdisc add dev "$jitter_dev" root netem delay 80ms
    # Need ≥ ceil(window_size/2) probes at the new latency to push the median.
    # window_size=5, probe_interval_s=3 -> ~9s to push the median.
    sleep 25
    new_iface=$(get_fdb_iface 1 "$LEAF2_MAC")
    echo "  after +80ms on $jitter_dev: FDB iface = $new_iface"
    test_total=$((test_total + 1))
    if [ "$new_iface" != "$init_iface_n1_to_n2" ] && [ -n "$new_iface" ]; then
        echo "  TEST: large latency triggers switch ... PASS"
        test_pass=$((test_pass + 1))
    else
        echo "  TEST: large latency triggers switch ... FAIL (still $init_iface_n1_to_n2)"
        test_fail=$((test_fail + 1))
    fi
    # Restore default delay
    ip netns exec node-1 tc qdisc change dev "$jitter_dev" root netem delay 1ms || true
    sleep 20  # let it settle back
fi

echo ""
echo "=== Scenario 4: Full ISP outage — traffic continues on the other ISP ==="
# Cut ISP1 on node-1: it must continue via ISP2.
set_link_down 1 1 v4
set_link_down 1 1 v6
sleep 25
mc_run_test "ping leaf-1 -> leaf-2 (ISP1 down on node-1)" \
    ip netns exec leaf-1 ping -c 5 -W 5 ${LEAF_V4}.2
mc_run_test "ping leaf-1 -> leaf-3 (ISP1 down on node-1)" \
    ip netns exec leaf-1 ping -c 5 -W 5 ${LEAF_V4}.3
restore_link 1 1 v4
restore_link 1 1 v6
sleep 15

echo ""
echo "=== Scenario 5: Node down — peers detect and prune ==="
# Stop client-3, others should still talk to each other.
kill $(ps -o pid,cmd | grep "client-3.yaml" | grep -v grep | awk '{print $1}') 2>/dev/null || true
sleep 12  # client_offline_timeout is 8s
mc_run_test "ping leaf-1 -> leaf-2 (node-3 down)" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2
mc_run_test "ping leaf-1 -> leaf-4 (node-3 down)" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.4
test_total=$((test_total + 1))
# leaf-3 should be unreachable. Use ! to invert ping success.
if ! ip netns exec leaf-1 ping -c 2 -W 3 ${LEAF_V4}.3 > /dev/null 2>&1; then
    echo "  TEST: leaf-1 -> leaf-3 unreachable after node-3 down ... PASS"
    test_pass=$((test_pass + 1))
else
    echo "  TEST: leaf-1 -> leaf-3 unreachable after node-3 down ... FAIL"
    test_fail=$((test_fail + 1))
fi

echo ""
echo "=== Scenario 6: Controller down — clients keep last view, FDB persists ==="
kill $(ps -o pid,cmd | grep "controller-10.yaml" | grep -v grep | awk '{print $1}') 2>/dev/null || true
sleep 5  # FDB shouldn't expire immediately
mc_run_test "ping leaf-1 -> leaf-2 (controller down)" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2
mc_run_test "ping leaf-1 -> leaf-4 (controller down)" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.4

mc_print_results
exit $test_fail
