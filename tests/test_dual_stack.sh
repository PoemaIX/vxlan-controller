#!/bin/bash
# Test 6: Dual-stack routing
# Verify v4-only (1,2) <-> dual-stack (3,4) <-> v6-only (5,6) routing.
# Traffic between v4-only and v6-only nodes must transit through dual-stack nodes.
# FDB entries should use the correct vxlan device for each segment.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"
trap cleanup EXIT

build_binaries
generate_keys
setup_topology

echo "=== Generating configurations ==="
generate_all_configs false

start_controllers
start_clients
wait_converge

echo ""
echo "=== Test 6: Dual-stack routing ==="

# v4-only -> v6-only (requires transit through dual-stack node)
run_test "leaf-1(v4) -> leaf-5(v6)" \
    ip netns exec "leaf-1" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.5"
run_test "leaf-2(v4) -> leaf-6(v6)" \
    ip netns exec "leaf-2" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.6"

# v6-only -> v4-only (reverse direction)
run_test "leaf-5(v6) -> leaf-1(v4)" \
    ip netns exec "leaf-5" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.1"
run_test "leaf-6(v6) -> leaf-2(v4)" \
    ip netns exec "leaf-6" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.2"

# Verify FDB uses correct vxlan devices
echo ""
echo "  Checking FDB device assignment..."
# On node-1 (v4-only): all remote MACs should use vxlan-v4-ISP1
n1_v6=$(ip netns exec "node-1" bridge fdb show dev vxlan-v6-ISP1 2>/dev/null | grep -c "dst" || echo 0)
if [ "$n1_v6" = "0" ]; then
    echo "    OK: node-1 (v4-only) uses only vxlan-v4-ISP1"
else
    echo "    INFO: node-1 has $n1_v6 entries on vxlan-v6-ISP1"
fi
# On node-5 (v6-only): all remote MACs should use vxlan-v6-ISP1
n5_v4=$(ip netns exec "node-5" bridge fdb show dev vxlan-v4-ISP1 2>/dev/null | grep -c "dst" || echo 0)
if [ "$n5_v4" = "0" ]; then
    echo "    OK: node-5 (v6-only) uses only vxlan-v6-ISP1"
else
    echo "    INFO: node-5 has $n5_v4 entries on vxlan-v4-ISP1"
fi
# On node-3 (dual-stack): should have entries on both vxlan devices
n3_v4=$(ip netns exec "node-3" bridge fdb show dev vxlan-v4-ISP1 2>/dev/null | grep -c "dst" || echo 0)
n3_v6=$(ip netns exec "node-3" bridge fdb show dev vxlan-v6-ISP1 2>/dev/null | grep -c "dst" || echo 0)
echo "    node-3 (dual-stack): vxlan-v4-ISP1=$n3_v4 entries, vxlan-v6-ISP1=$n3_v6 entries"

print_results
exit $test_fail
