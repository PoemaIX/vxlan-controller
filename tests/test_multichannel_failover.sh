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
# (~15s). Cross-channel pairing probes every (local, peer) combo and the first
# round serializes probe-session handshakes, so allow extra headroom for the
# debounce window to fill with steady-state samples before capturing baseline.
mc_wait_converge 30

# Helper: report which (af, channel) is being used in node-N FDB for a given dst MAC.
get_fdb_iface() {
    local node=$1 mac=$2
    ip netns exec "node-$node" bridge fdb show | awk -v m="$mac" '
        $1 == m && /self/ { print $3 }' | head -1
}

# Helper: report the FDB dst address for a given dst MAC. With channel-pair
# routing the local device no longer pins the egress path — the dst address
# (which peer uplink we send to) is what determines the underlay used.
get_fdb_dst() {
    local node=$1 mac=$2
    ip netns exec "node-$node" bridge fdb show | awk -v m="$mac" '
        $1 == m && /self/ { for (i=1;i<NF;i++) if ($i=="dst") print $(i+1) }' | head -1
}

# Helper: get the MAC of leaf-N on its veth.
leaf_mac() {
    local n=$1
    ip netns exec "leaf-$n" cat /sys/class/net/veth-leaf-l-$n/address
}

LEAF2_MAC=$(leaf_mac 2)
LEAF3_MAC=$(leaf_mac 3)

# Wait until node-1's route to leaf-2 is DIRECT (dst is one of node-2's own
# addresses) and stable across two samples. Early probe rounds can leave a
# transient multi-hop route (dst = some other node); capturing that as the
# baseline makes the later stickiness comparison meaningless.
wait_direct_stable_n1_to_n2() {
    local mac=$1 deadline=$((SECONDS + 90)) prev="" cur=""
    while [ "$SECONDS" -lt "$deadline" ]; do
        cur=$(get_fdb_dst 1 "$mac")
        case "$cur" in
            "${ISP1_V4}.2"|"${ISP2_V4}.2"|"${ISP1_V6}2"|"${ISP2_V6}2")
                if [ -n "$prev" ] && [ "$cur" = "$prev" ]; then
                    return 0
                fi
                prev="$cur"
                ;;
            *) prev="" ;;
        esac
        sleep 3
    done
    echo "  WARN: node-1 -> node-2 route never stabilized to a direct path"
    return 1
}

echo ""
echo "=== Scenario 1: Baseline (all 4 channels healthy) ==="
mc_run_test "baseline ping leaf-1 -> leaf-2" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2
mc_run_test "baseline ping leaf-1 -> leaf-3" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.3
wait_direct_stable_n1_to_n2 "$LEAF2_MAC" || true
init_iface_n1_to_n2=$(get_fdb_iface 1 "$LEAF2_MAC")
init_dst_n1_to_n2=$(get_fdb_dst 1 "$LEAF2_MAC")
echo "  node-1 FDB to leaf-2 MAC ($LEAF2_MAC) uses: $init_iface_n1_to_n2 dst $init_dst_n1_to_n2"

echo ""
echo "=== Scenario 2: Sticky to small latency jitter (≤ af_switch_cost) ==="
# Add small jitter (~5ms) on node-1's currently-selected path. Switch_cost=25,
# so 5ms swing should not cause a flap. The delayed device is derived from the
# FDB dst (the peer uplink in use), since that's what picks the egress LAN.
if [ -n "$init_dst_n1_to_n2" ]; then
    case "$init_dst_n1_to_n2" in
        ${ISP1_V4}.*) jitter_dev="ei1-v4" ;;
        ${ISP2_V4}.*) jitter_dev="ei2-v4" ;;
        fd1:*)        jitter_dev="ei1-v6" ;;
        fd2:*)        jitter_dev="ei2-v6" ;;
        *) jitter_dev="" ;;
    esac
    if [ -n "$jitter_dev" ]; then
        ip netns exec node-1 tc qdisc change dev "$jitter_dev" root netem delay 6ms || \
        ip netns exec node-1 tc qdisc add dev "$jitter_dev" root netem delay 6ms
        sleep 20
        cur_dst=$(get_fdb_dst 1 "$LEAF2_MAC")
        echo "  after +5ms jitter on $jitter_dev: FDB dst = $cur_dst"
        test_total=$((test_total + 1))
        if [ "$cur_dst" = "$init_dst_n1_to_n2" ]; then
            echo "  TEST: small jitter sticky (no flap) ... PASS"
            test_pass=$((test_pass + 1))
        else
            echo "  TEST: small jitter sticky (no flap) ... FAIL (changed $init_dst_n1_to_n2 -> $cur_dst)"
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
if [ -n "$init_dst_n1_to_n2" ] && [ -n "${jitter_dev:-}" ]; then
    ip netns exec node-1 tc qdisc change dev "$jitter_dev" root netem delay 80ms || \
    ip netns exec node-1 tc qdisc add dev "$jitter_dev" root netem delay 80ms
    # Need ≥ ceil(window_size/2) probes at the new latency to push the median.
    # window_size=5, probe_interval_s=3 -> ~9s to push the median.
    sleep 25
    new_dst=$(get_fdb_dst 1 "$LEAF2_MAC")
    echo "  after +80ms on $jitter_dev: FDB dst = $new_dst"
    test_total=$((test_total + 1))
    if [ "$new_dst" != "$init_dst_n1_to_n2" ] && [ -n "$new_dst" ]; then
        echo "  TEST: large latency triggers switch ... PASS"
        test_pass=$((test_pass + 1))
    else
        echo "  TEST: large latency triggers switch ... FAIL (still $init_dst_n1_to_n2)"
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
echo "=== Scenario 5b: Node restart — rejoins with the same key, routes restored ==="
mc_start_process node-3 client "$CLIENT_3_CONF" "client-3-restarted"
test_total=$((test_total + 1))
rejoin_deadline=$((SECONDS + 90))
rejoined=false
while [ "$SECONDS" -lt "$rejoin_deadline" ]; do
    if ip netns exec leaf-1 ping -c 2 -W 3 ${LEAF_V4}.3 > /dev/null 2>&1; then
        rejoined=true
        break
    fi
    sleep 3
done
if $rejoined; then
    echo "  TEST: leaf-1 -> leaf-3 reachable after node-3 rejoin ... PASS"
    test_pass=$((test_pass + 1))
else
    echo "  TEST: leaf-1 -> leaf-3 reachable after node-3 rejoin ... FAIL"
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
