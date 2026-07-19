#!/bin/bash
# Verify vxlan_rate_limit applies tc qdisc tbf to each vxlan device based on
# min(my_up_kbps, min over peers' down_kbps) per (af, channel).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/multichannel_helpers.sh"
trap mc_cleanup EXIT

build_binaries
generate_keys
setup_topology_mc

echo "=== Generating multi-channel configurations with rate-limit ==="
generate_mc_configs addr

# Patch each client config: enable rate limit, set per-channel up/down BW.
# Layout:
#   node-1 up=10000 kbit/s on every channel
#   node-2..4 down=5000 kbit/s on every channel
# Expected applied cap on node-1's vxlan-*-* devices = min(10000, 5000) = 5000.
patch_client_bw() {
    local f=$1 my_up=$2 my_down=$3
    # Insert isp_name + bandwidth two lines below each "ISPn:" line, and
    # prepend vxlan_rate_limit at top. The YAML the helper emits is
    # regular enough that a couple of sed passes suffice.
    sed -i "1i vxlan_rate_limit: true" "$f"
    awk -v up="$my_up" -v down="$my_down" '
        { print }
        /^    ISP[0-9]+:$/ {
            isp=$1; sub(":", "", isp)
            print "      isp_name: \"" isp "\""
            print "      up_bw_kbps: " up
            print "      down_bw_kbps: " down
        }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

patch_client_bw "$CLIENT_1_CONF" 10000 50000
patch_client_bw "$CLIENT_2_CONF" 20000 5000
patch_client_bw "$CLIENT_3_CONF" 20000 5000
patch_client_bw "$CLIENT_4_CONF" 20000 5000

mc_start_controllers
mc_start_clients
mc_wait_converge 18

echo ""
echo "=== Test: connectivity survives with rate limit on ==="
mc_run_test "rate-limit on: leaf-1 -> leaf-2" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2
mc_run_test "rate-limit on: leaf-1 -> leaf-3" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.3

echo ""
echo "=== Test: tc qdisc tbf installed on each vxlan device ==="
for dev in vxlan-v4-ISP1 vxlan-v4-ISP2 vxlan-v6-ISP1 vxlan-v6-ISP2; do
    test_total=$((test_total + 1))
    out=$(ip netns exec node-1 tc qdisc show dev "$dev" 2>/dev/null || true)
    if echo "$out" | grep -q "tbf"; then
        # Expected cap = min(10000, 5000) = 5000 kbit
        # tc shows rates in their natural unit; "5Mbit" or "5000Kbit".
        if echo "$out" | grep -Ei "(5000Kbit|5Mbit)"; then
            echo "  TEST: node-1 $dev tbf @5Mbit ... PASS"
            test_pass=$((test_pass + 1))
        else
            echo "  TEST: node-1 $dev tbf @5Mbit ... FAIL (got: $out)"
            test_fail=$((test_fail + 1))
        fi
    else
        echo "  TEST: node-1 $dev tbf installed ... FAIL (no tbf)"
        echo "    qdisc: $out"
        test_fail=$((test_fail + 1))
    fi
done

mc_print_results
exit $test_fail
