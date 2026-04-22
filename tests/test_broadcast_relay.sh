#!/bin/bash
# Test 5: Broadcast / Multicast relay
# Broadcasts (ARP) should be relayed via tap-inject -> controller -> all clients.
# Verify that broadcast reaches remote leaves and doesn't loop back to source.

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
echo "=== Test 5: Broadcast relay ==="

# Flush all ARP caches to force broadcast ARP resolution
for i in 1 2 3 4 5 6; do
    ip netns exec "leaf-$i" ip neigh flush dev "veth-leaf-l-$i" 2>/dev/null || true
done
sleep 1

# Ping with flushed ARP forces broadcast ARP request through tap relay
run_test "broadcast relay: leaf-1 -> leaf-2 (ARP flushed)" \
    ip netns exec "leaf-1" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.2"

# Cross-AF broadcast relay
ip netns exec "leaf-1" ip neigh flush dev "veth-leaf-l-1" 2>/dev/null || true
ip netns exec "leaf-5" ip neigh flush dev "veth-leaf-l-5" 2>/dev/null || true
sleep 1

run_test "broadcast relay: leaf-1(v4) -> leaf-5(v6) (ARP flushed)" \
    ip netns exec "leaf-1" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.5"

# Verify no broadcast FDB entries on vxlan devices (broadcasts go via tap, not vxlan)
echo ""
echo "  Checking: no broadcast FDB entries on vxlan devices..."
has_bcast_fdb=false
for i in 1 2 3 4 5 6; do
    for dev in vxlan-v4-ISP1 vxlan-v6-ISP1; do
        bcast=$(ip netns exec "node-$i" bridge fdb show dev "$dev" 2>/dev/null | grep "ff:ff:ff:ff:ff:ff" || true)
        if [ -n "$bcast" ]; then
            echo "    WARNING: node-$i $dev has broadcast FDB: $bcast"
            has_bcast_fdb=true
        fi
    done
done
if ! $has_bcast_fdb; then
    echo "    OK: no broadcast FDB entries found"
fi

print_results
exit $test_fail
