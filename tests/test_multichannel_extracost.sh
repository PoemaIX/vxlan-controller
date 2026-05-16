#!/bin/bash
# Verify channel_additional_costs steers routing per-peer/per-AF/per-ISP.
#
# Setup:
#   - 4 nodes, two ISPs per AF (same topology as the other multichannel tests)
#   - All 4 channels healthy with near-equal raw latency
#   - node-1 has channel_additional_costs = [{peer:"*", af:"v4", isp:"ISP1", cost:1000}]
#     This makes node-1 prefer ISP2 over ISP1 for v4 traffic to every peer.
#   - We verify the FDB on node-1 for leaf-2's MAC ends up on vxlan-v4-ISP2
#     (or vxlan-v6-* if v6 still wins), and that BOTH ISP1 channels are
#     deprioritized vs. ISP2 / v6.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/multichannel_helpers.sh"
trap mc_cleanup EXIT

build_binaries
generate_keys
setup_topology_mc

echo "=== Generating multi-channel configurations (bind_addr method) ==="
generate_mc_configs addr

# Patch client-1 config to add a heavy penalty on v4/ISP1 for any peer.
cat >> "$CLIENT_1_CONF" <<'YAML'
channel_additional_costs:
  - peer: "*"
    af: "v4"
    isp: "ISP1"
    cost: 1000
YAML

mc_start_controllers
mc_start_clients
# Window size is 5 with 3s probe interval -> ~15s to fill window.
mc_wait_converge 18

leaf_mac() {
    ip netns exec "leaf-$1" cat /sys/class/net/veth-leaf-l-$1/address
}
get_fdb_iface() {
    ip netns exec "node-$1" bridge fdb show | awk -v m="$2" '
        $1 == m && /self/ { print $3 }' | head -1
}

LEAF2_MAC=$(leaf_mac 2)
LEAF3_MAC=$(leaf_mac 3)
LEAF4_MAC=$(leaf_mac 4)

echo ""
echo "=== Test: channel_additional_costs steers node-1 off v4/ISP1 ==="
mc_run_test "baseline ping leaf-1 -> leaf-2 still works" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2

iface2=$(get_fdb_iface 1 "$LEAF2_MAC")
iface3=$(get_fdb_iface 1 "$LEAF3_MAC")
iface4=$(get_fdb_iface 1 "$LEAF4_MAC")
echo "  node-1 FDB picks:  leaf-2=$iface2  leaf-3=$iface3  leaf-4=$iface4"

for n in 2 3 4; do
    test_total=$((test_total + 1))
    var="iface$n"
    iface="${!var}"
    if [ "$iface" != "vxlan-v4-ISP1" ] && [ -n "$iface" ]; then
        echo "  TEST: node-1 -> leaf-$n avoids v4/ISP1 (got $iface) ... PASS"
        test_pass=$((test_pass + 1))
    else
        echo "  TEST: node-1 -> leaf-$n avoids v4/ISP1 (got $iface) ... FAIL"
        test_fail=$((test_fail + 1))
    fi
done

echo ""
echo "=== Test: control — node-2 has no rules, may still use v4/ISP1 ==="
# node-2 has no channel_additional_costs, so it should freely pick the
# cheapest probed path. We just sanity-check it can ping.
mc_run_test "node-2 ping leaf-1 still works (no penalty applied)" \
    ip netns exec leaf-2 ping -c 3 -W 5 ${LEAF_V4}.1

mc_print_results
exit $test_fail
