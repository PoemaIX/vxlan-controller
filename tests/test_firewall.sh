#!/bin/bash
# Test: VXLAN firewall (vxlan_firewall)
# Verifies:
# 1. Normal VXLAN connectivity works with firewall enabled
# 2. Rogue VXLAN injection SUCCEEDS on node without firewall (control group)
# 3. Rogue VXLAN injection BLOCKED on node with firewall
# 4. After IP change, firewall rules update and connectivity restored
# 5. Firewall rules are per-AF (each AF has its own allowed set)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"
trap cleanup EXIT

build_binaries
generate_keys
setup_topology

echo "=== Generating configurations ==="
# node-4: firewall=false (control group for injection test)
# all others: firewall=true
CTRL_4_CONF=$(write_controller_config 4 "$PRIV_4")
CTRL_10_CONF=$(write_controller_config 10 "$PRIV_10")
CLIENT_1_CONF=$(write_client_config 1 "$PRIV_1" false true true)
CLIENT_2_CONF=$(write_client_config 2 "$PRIV_2" false false true)
CLIENT_3_CONF=$(write_client_config 3 "$PRIV_3" false true true)
CLIENT_4_CONF=$(write_client_config 4 "$PRIV_4" false false false)  # firewall OFF
CLIENT_5_CONF=$(write_client_config 5 "$PRIV_5" false true true)
CLIENT_6_CONF=$(write_client_config 6 "$PRIV_6" false false true)

start_controllers
start_clients
wait_converge

# Helper: send a valid VXLAN-encapsulated Ethernet frame from rogue to a target
# Usage: send_vxlan_inject <target_ip> <vni>
# The inner frame has src MAC de:ad:be:ef:00:01 (rogue), dst MAC ff:ff:ff:ff:ff:ff
send_vxlan_inject() {
    local target_ip=$1 vni=$2
    ip netns exec rogue python3 -c "
import socket, struct

# VXLAN header: flags=0x08 (VNI present), VNI=${vni}
flags_rsvd = 0x08000000
vni_rsvd = ${vni} << 8
vxlan_hdr = struct.pack('!II', flags_rsvd, vni_rsvd)

# Inner Ethernet: broadcast dst, rogue src MAC, ARP ethertype, minimal ARP payload
dst_mac = b'\xff\xff\xff\xff\xff\xff'
src_mac = b'\xde\xad\xbe\xef\x00\x01'
ethertype = struct.pack('!H', 0x0806)
# Minimal ARP: hw=ethernet, proto=ipv4, hwlen=6, protolen=4, op=request
arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
arp += b'\xde\xad\xbe\xef\x00\x01'   # sender MAC
arp += socket.inet_aton('${V4_SUBNET}.200')  # sender IP
arp += b'\x00\x00\x00\x00\x00\x00'   # target MAC
arp += socket.inet_aton('${V4_SUBNET}.99')   # target IP (dummy)

pkt = vxlan_hdr + dst_mac + src_mac + ethertype + arp

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(pkt, ('${target_ip}', ${VXLAN_DSTPORT}))
s.close()
" 2>/dev/null
}

# Helper: get RX packet count on a vxlan device
# Usage: get_vxlan_rx <namespace> <dev_name>
get_vxlan_rx() {
    local ns=$1 dev=$2
    ip netns exec "$ns" ip -s link show "$dev" 2>/dev/null \
        | awk '/RX:/{getline; print $2}' | head -1
}

echo ""
echo "=== Test: VXLAN firewall ==="

# --- Section 1: Baseline connectivity ---
run_test "baseline: leaf-1 -> leaf-3" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.3"
run_test "baseline: leaf-3 -> leaf-5" \
    ip netns exec "leaf-3" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"
run_test "baseline: leaf-1 -> leaf-5" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"
run_test "baseline: leaf-2 -> leaf-4" \
    ip netns exec "leaf-2" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.4"

# --- Section 2: Verify firewall table ---
echo ""
echo "  Checking nftables on node-2 (firewall=true)..."
nft_out=$(ip netns exec "node-2" nft list table inet vxlan_fw 2>&1)
if echo "$nft_out" | grep -q "af_"; then
    echo "  node-2: vxlan_fw table present: OK"
else
    echo "  node-2: vxlan_fw table MISSING!"
fi

echo "  Checking nftables on node-4 (firewall=false)..."
nft_out_4=$(ip netns exec "node-4" nft list table inet vxlan_fw 2>&1 || true)
if echo "$nft_out_4" | grep -q "af_"; then
    echo "  node-4: vxlan_fw table present (unexpected!)"
else
    echo "  node-4: no vxlan_fw table: OK"
fi

# --- Section 3: Setup rogue ---
echo ""
echo "  Adding rogue node (${V4_SUBNET}.200) to v4 LAN..."
ip link add veth-rogue-r type veth peer name veth-rogue-ns
ip netns add rogue
CLEANUP_NS+=("rogue")
ip link set veth-rogue-ns netns rogue
ip link set veth-rogue-r master br-lan-v4
ip link set veth-rogue-r up
ip netns exec rogue ip link set veth-rogue-ns up
ip netns exec rogue ip addr add "${V4_SUBNET}.200/24" dev veth-rogue-ns
sleep 0.5

# Verify rogue L3 reachability
run_test "rogue -> node-2 ICMP (control plane unaffected)" \
    ip netns exec rogue ping -c 1 -W 2 "${V4_SUBNET}.2"
run_test "rogue -> node-4 ICMP (control plane unaffected)" \
    ip netns exec rogue ping -c 1 -W 2 "${V4_SUBNET}.4"

# --- Section 4: Injection test — firewall OFF (node-4) ---
echo ""
echo "  === Injection test: firewall OFF (node-4) ==="
rx_before=$(get_vxlan_rx "node-4" "vxlan-v4-ISP1")
send_vxlan_inject "${V4_SUBNET}.4" "$VNI"
sleep 0.5
rx_after=$(get_vxlan_rx "node-4" "vxlan-v4-ISP1")

test_total=$((test_total + 1))
echo -n "  TEST: rogue VXLAN inject to node-4 (no firewall) reaches vxlan device ... "
if [ "$rx_after" -gt "$rx_before" ]; then
    echo "PASS (rx: $rx_before -> $rx_after)"
    test_pass=$((test_pass + 1))
else
    echo "FAIL (rx: $rx_before -> $rx_after)"
    test_fail=$((test_fail + 1))
fi

# --- Section 5: Injection test — firewall ON (node-2) ---
echo ""
echo "  === Injection test: firewall ON (node-2) ==="
rx_before=$(get_vxlan_rx "node-2" "vxlan-v4-ISP1")
drops_before=$(ip netns exec "node-2" nft list table inet vxlan_fw 2>/dev/null \
    | grep -oP 'counter packets \K[0-9]+' | head -1 || echo 0)

send_vxlan_inject "${V4_SUBNET}.2" "$VNI"
sleep 0.5

rx_after=$(get_vxlan_rx "node-2" "vxlan-v4-ISP1")
drops_after=$(ip netns exec "node-2" nft list table inet vxlan_fw 2>/dev/null \
    | grep -oP 'counter packets \K[0-9]+' | head -1 || echo 0)

test_total=$((test_total + 1))
echo -n "  TEST: rogue VXLAN inject to node-2 (firewall) blocked by nftables ... "
if [ "$drops_after" -gt "$drops_before" ] && [ "$rx_after" -eq "$rx_before" ]; then
    echo "PASS (drops: $drops_before -> $drops_after, rx unchanged: $rx_before)"
    test_pass=$((test_pass + 1))
else
    echo "FAIL (drops: $drops_before -> $drops_after, rx: $rx_before -> $rx_after)"
    test_fail=$((test_fail + 1))
    echo "  nftables state:"
    ip netns exec "node-2" nft list table inet vxlan_fw 2>&1 | head -20
fi

# --- Section 6: Connectivity unaffected after injection attempts ---
echo ""
run_test "leaf-1 -> leaf-3 (after injection tests)" \
    ip netns exec "leaf-1" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.3"
run_test "leaf-2 -> leaf-4 (after injection tests)" \
    ip netns exec "leaf-2" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.4"
run_test "leaf-3 -> leaf-5 (after injection tests)" \
    ip netns exec "leaf-3" ping -c 2 -W 5 "${LEAF_SUBNET_V4}.5"

# --- Section 7: IP change + firewall update ---
echo ""
echo "  Changing node-1 v4 IP: ${V4_SUBNET}.1 -> ${V4_SUBNET}.101"
ip netns exec "node-1" ip addr del "${V4_SUBNET}.1/24" dev eth-v4 2>/dev/null || true
ip netns exec "node-1" ip addr add "${V4_SUBNET}.101/24" dev eth-v4

echo "  Waiting 15s for auto-detect, reconnection and firewall update..."
sleep 15

run_test "leaf-1 -> leaf-3 (after IP change, with firewall)" \
    ip netns exec "leaf-1" ping -c 3 -W 10 "${LEAF_SUBNET_V4}.3"

# Verify new IP in firewall allowed set on node-2
new_ip_in_fw=$(ip netns exec "node-2" nft list set inet vxlan_fw af_v4 2>/dev/null | grep -c "101" || echo 0)
test_total=$((test_total + 1))
echo -n "  TEST: new IP ${V4_SUBNET}.101 in node-2 firewall set ... "
if [ "$new_ip_in_fw" -gt 0 ]; then
    echo "PASS"
    test_pass=$((test_pass + 1))
else
    echo "FAIL"
    test_fail=$((test_fail + 1))
    ip netns exec "node-2" nft list set inet vxlan_fw af_v4 2>&1
fi

# --- Section 8: Per-AF set isolation ---
echo "  Checking per-AF set isolation on node-3 (dual-stack)..."
v4_set=$(ip netns exec "node-3" nft list set inet vxlan_fw af_v4 2>/dev/null || echo "")
v6_set=$(ip netns exec "node-3" nft list set inet vxlan_fw af_v6 2>/dev/null || echo "")

test_total=$((test_total + 1))
echo -n "  TEST: node-3 has separate v4 and v6 firewall sets ... "
if echo "$v4_set" | grep -q "ipv4_addr" && echo "$v6_set" | grep -q "ipv6_addr"; then
    echo "PASS"
    test_pass=$((test_pass + 1))
else
    echo "FAIL"
    test_fail=$((test_fail + 1))
fi

# Cleanup rogue
ip netns del rogue 2>/dev/null || true
ip link del veth-rogue-r 2>/dev/null || true

print_results
exit $test_fail
