#!/bin/bash
# Multi-channel basic connectivity test.
#
# Topology: 4 nodes, each on two v4 ISP LANs and two v6 ISP LANs, talking
# to a single controller (also dual-ISP, dual-AF).
# Verifies that every (af, channel) shows up in peer.list and that leaf-to-leaf
# ping over the VXLAN fabric works in all directions.

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
mc_wait_converge 15

echo ""
echo "=== Test: leaf-to-leaf connectivity over VXLAN ==="
for src in 1 2 3 4; do
    for dst in 1 2 3 4; do
        [ "$src" = "$dst" ] && continue
        mc_run_test "leaf-$src -> leaf-$dst" \
            ip netns exec "leaf-$src" ping -c 3 -W 5 "${LEAF_V4}.${dst}"
    done
done

echo ""
echo "=== Test: each client sees both ISP1 and ISP2 endpoints for every peer ==="
verify_endpoints() {
    local node=$1
    local sock="/var/run/vxlan-client.sock"
    local route_json
    route_json=$(ip netns exec "node-$node" "$PROJECT_DIR/vxlan-controller" \
        -mode vxccli -sock "$sock" peer list 2>&1) || true
    # Must include both v4/ISP1 and v4/ISP2 (we have v6 too but v4 is the
    # minimal acceptance criterion).
    if echo "$route_json" | grep -q "v4/ISP1" && \
       echo "$route_json" | grep -q "v4/ISP2" && \
       echo "$route_json" | grep -q "v6/ISP1" && \
       echo "$route_json" | grep -q "v6/ISP2"; then
        return 0
    fi
    return 1
}
for src in 1 2 3 4; do
    mc_run_test "node-$src sees all (af, channel) endpoints" verify_endpoints "$src"
done

echo ""
echo "=== Test: FDB uses one of the configured vxlan devices ==="
verify_fdb_on_vxlan() {
    local node=$1
    local found=0
    for dev in vxlan-v4-ISP1 vxlan-v4-ISP2 vxlan-v6-ISP1 vxlan-v6-ISP2; do
        local n
        n=$(ip netns exec "node-$node" bridge fdb show dev "$dev" 2>/dev/null | grep -c "dst" || true)
        [ "$n" -gt 0 ] && found=1
    done
    [ "$found" -eq 1 ]
}
for src in 1 2 3 4; do
    mc_run_test "node-$src has at least one VXLAN FDB entry" verify_fdb_on_vxlan "$src"
done

mc_print_results
exit $test_fail
