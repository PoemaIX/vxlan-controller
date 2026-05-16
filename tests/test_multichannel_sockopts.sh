#!/bin/bash
# Verify bind_device (SO_BINDTODEVICE) per-channel socket-option support.
#
# bind_device pins both the control channel (TCP+UDP via SO_BINDTODEVICE)
# AND the vxlan data channel (via IFLA_VXLAN_LINK / `ip link add ... dev X`).
# We verify both ends:
#   - control plane: connectivity survives even after we delete the default
#     route, because SO_BINDTODEVICE bypasses the routing table.
#   - data plane: the vxlan device's `link` attribute matches the configured
#     bind_device (i.e. we actually wired IFLA_VXLAN_LINK).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/multichannel_helpers.sh"
trap mc_cleanup EXIT

build_binaries
generate_keys
setup_topology_mc

echo ""
echo "===================================================================="
echo "= bind_device (SO_BINDTODEVICE + IFLA_VXLAN_LINK)                  ="
echo "===================================================================="
generate_mc_configs device
mc_start_controllers
mc_start_clients
mc_wait_converge 15

echo ""
echo "=== Test: end-to-end ping with bind_device set on every channel ==="
for src in 1 2; do
    for dst in 3 4; do
        mc_run_test "bind_device: leaf-$src -> leaf-$dst" \
            ip netns exec "leaf-$src" ping -c 3 -W 5 "${LEAF_V4}.${dst}"
    done
done

echo ""
echo "=== Test: client config carries bind_device ==="
test_total=$((test_total + 1))
if grep -q "bind_device" "$CLIENT_1_CONF"; then
    echo "  TEST: client-1 config contains bind_device ... PASS"
    test_pass=$((test_pass + 1))
else
    echo "  TEST: client-1 config contains bind_device ... FAIL"
    test_fail=$((test_fail + 1))
fi

echo ""
echo "=== Test: vxlan devices are bound to their configured underlay (data plane) ==="
# `ip -d link show vxlan-XXX` prints "link <phys-iface>" when IFLA_VXLAN_LINK
# is set. Verify each of our four vxlans on node-1 is bound to the matching
# ei*-* interface.
for node in 1 2 3 4; do
    for af in v4 v6; do
        for isp in 1 2; do
            vxlan="vxlan-${af}-ISP${isp}"
            expected_dev="ei${isp}-${af}"
            test_total=$((test_total + 1))
            out=$(ip netns exec "node-$node" ip -d link show "$vxlan" 2>/dev/null || true)
            # Match `dev <name>` (kernel emits it) or `link <iface>` (older iproute2).
            if echo "$out" | grep -qE "(dev|link) ${expected_dev}\b"; then
                echo "  TEST: node-$node $vxlan bound to $expected_dev ... PASS"
                test_pass=$((test_pass + 1))
            else
                echo "  TEST: node-$node $vxlan bound to $expected_dev ... FAIL"
                echo "    --- ip -d link show output ---"
                echo "$out" | sed 's/^/    /' | head -5
                test_fail=$((test_fail + 1))
            fi
        done
    done
done

echo ""
echo "=== Test: bind_device steers control plane even with broken default route ==="
# Remove node-1's v4 default route. Because SO_BINDTODEVICE pins the socket
# to the underlying ISP interface, control + vxlan keep working without
# needing a default route at all.
ip netns exec node-1 ip route del default 2>/dev/null || true
ip netns exec node-1 ip -6 route del default 2>/dev/null || true
mc_run_test "bind_device steers traffic after default route removed" \
    ip netns exec leaf-1 ping -c 3 -W 5 "${LEAF_V4}.2"

mc_print_results
exit $test_fail
