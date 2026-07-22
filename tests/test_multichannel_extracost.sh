#!/bin/bash
# Verify channel_additional_costs steers routing per-peer/per-AF/per-ISP.
#
# Setup:
#   - 4 nodes, two ISPs per AF (same topology as the other multichannel tests)
#   - All 4 channels healthy with near-equal raw latency
#   - node-1 has channel_additional_costs = [{peer:"*", af:"v4", isp:"ISP1", cost:1000}]
#     The isp field matches the PEER side of a channel pair, so this steers
#     node-1's v4 traffic away from every peer's ISP1 uplink.
#   - We verify node-1's FDB dst for each leaf MAC is NOT on the ISP1 v4
#     subnet (the local vxlan device is an arbitrary tie-break without
#     bind_device — the dst address is what selects the underlay).

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
get_fdb_dst() {
    ip netns exec "node-$1" bridge fdb show | awk -v m="$2" '
        $1 == m && /self/ { for (i=1;i<NF;i++) if ($i=="dst") print $(i+1) }' | head -1
}

LEAF2_MAC=$(leaf_mac 2)
LEAF3_MAC=$(leaf_mac 3)
LEAF4_MAC=$(leaf_mac 4)

echo ""
echo "=== Test: channel_additional_costs steers node-1 off v4/ISP1 ==="
mc_run_test "baseline ping leaf-1 -> leaf-2 still works" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2

dst2=$(get_fdb_dst 1 "$LEAF2_MAC")
dst3=$(get_fdb_dst 1 "$LEAF3_MAC")
dst4=$(get_fdb_dst 1 "$LEAF4_MAC")
echo "  node-1 FDB picks:  leaf-2=$dst2  leaf-3=$dst3  leaf-4=$dst4"

for n in 2 3 4; do
    test_total=$((test_total + 1))
    var="dst$n"
    dst="${!var}"
    case "$dst" in
        "")
            echo "  TEST: node-1 -> leaf-$n avoids peers' v4/ISP1 (no fdb entry) ... FAIL"
            test_fail=$((test_fail + 1))
            ;;
        ${ISP1_V4}.*)
            echo "  TEST: node-1 -> leaf-$n avoids peers' v4/ISP1 (got dst $dst) ... FAIL"
            test_fail=$((test_fail + 1))
            ;;
        *)
            echo "  TEST: node-1 -> leaf-$n avoids peers' v4/ISP1 (got dst $dst) ... PASS"
            test_pass=$((test_pass + 1))
            ;;
    esac
done

echo ""
echo "=== Test: control — node-2 has no rules, may still use v4/ISP1 ==="
# node-2 has no channel_additional_costs, so it should freely pick the
# cheapest probed path. We just sanity-check it can ping.
mc_run_test "node-2 ping leaf-1 still works (no penalty applied)" \
    ip netns exec leaf-2 ping -c 3 -W 5 ${LEAF_V4}.1

mc_print_results
exit $test_fail
