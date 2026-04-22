#!/bin/bash
# Compare static VXLAN setup vs vxlan-controller setup.
#
# Topology:
#   leaf-a -- [node-a] --v4-- [node-b] --v6-- [node-c] -- leaf-c
#                                |
#                             leaf-b
#
# a,b: v4 underlay only (10.0.4.0/24)
# b,c: v6 underlay only (fd00::0/64)
# All leaves on 192.168.100.0/24 overlay
#
# Fixed MACs:
#   leaf-a: 02:aa:00:00:00:0a   leaf-b: 02:aa:00:00:00:0b   leaf-c: 02:aa:00:00:00:0c
#
# Test: send L2 unicast (EtherType 0x88b5) from leaf-a to leaf-c
#       (must relay through node-b, hairpin: vxlan-v4 in -> bridge -> vxlan-v6 out)

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SEND_SCRIPT="/root/gitrs/vxlanController/vxlan-test/send_l2_unicast.py"

VNI=100
DSTPORT=4789
MTU=1400
BR=br-vxlan

MAC_A="02:aa:00:00:00:0a"
MAC_B="02:aa:00:00:00:0b"
MAC_C="02:aa:00:00:00:0c"

V4_A="10.0.4.1"
V4_B="10.0.4.2"
V6_B="fd00::2"
V6_C="fd00::3"

LEAF_IP_A="192.168.100.1"
LEAF_IP_B="192.168.100.2"
LEAF_IP_C="192.168.100.3"

TMPDIR=$(mktemp -d)
echo "TMPDIR=$TMPDIR"

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    for ns in node-a node-b node-c leaf-a leaf-b leaf-c; do
        ip netns del "$ns" 2>/dev/null || true
    done
    for dev in br-lan-v4 br-lan-v6; do
        ip link del "$dev" 2>/dev/null || true
    done
    for x in a b c; do
        ip link del "veth-r-v4-$x" 2>/dev/null || true
        ip link del "veth-r-v6-$x" 2>/dev/null || true
        ip link del "veth-leaf-$x" 2>/dev/null || true
    done
    pkill -9 -f "vxlan-controller|vxlan-client" 2>/dev/null || true
    echo "Logs in $TMPDIR"
}
trap cleanup EXIT

# ── helpers ─────────────────────────────────────────────
create_topology() {
    echo "=== Creating topology ==="

    for ns in node-a node-b node-c leaf-a leaf-b leaf-c; do
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
    done

    # v4 LAN: a <-> b
    ip link add br-lan-v4 type bridge
    ip link set br-lan-v4 up
    for pair in "a:$V4_A" "b:$V4_B"; do
        node=${pair%%:*}; addr=${pair#*:}
        ip link add "veth-r-v4-$node" type veth peer name eth-v4
        ip link set eth-v4 netns "node-$node"
        ip link set "veth-r-v4-$node" master br-lan-v4
        ip link set "veth-r-v4-$node" up
        ip netns exec "node-$node" ip link set eth-v4 address "02:04:00:00:00:0$node"
        ip netns exec "node-$node" ip link set eth-v4 up
        ip netns exec "node-$node" ip addr add "${addr}/24" dev eth-v4
    done

    # v6 LAN: b <-> c
    ip link add br-lan-v6 type bridge
    ip link set br-lan-v6 up
    for pair in "b:$V6_B" "c:$V6_C"; do
        node=${pair%%:*}; addr=${pair#*:}
        ip link add "veth-r-v6-$node" type veth peer name eth-v6
        ip link set eth-v6 netns "node-$node"
        ip link set "veth-r-v6-$node" master br-lan-v6
        ip link set "veth-r-v6-$node" up
        ip netns exec "node-$node" ip link set eth-v6 address "02:06:00:00:00:0$node"
        ip netns exec "node-$node" ip link set eth-v6 up
        ip netns exec "node-$node" ip addr add "${addr}/64" dev eth-v6
    done

    # leaf connections
    for x in a b c; do
        ip link add "veth-leaf-$x" type veth peer name "veth-l"
        ip link set "veth-leaf-$x" netns "node-$x"
        ip link set "veth-l" netns "leaf-$x"
    done

    eval "leaf_mac_a=$MAC_A; leaf_mac_b=$MAC_B; leaf_mac_c=$MAC_C"
    eval "leaf_ip_a=$LEAF_IP_A; leaf_ip_b=$LEAF_IP_B; leaf_ip_c=$LEAF_IP_C"
    for x in a b c; do
        eval "mac=\$leaf_mac_$x; lip=\$leaf_ip_$x"
        ip netns exec "leaf-$x" ip link set veth-l address "$mac"
        ip netns exec "leaf-$x" ip link set veth-l up
        ip netns exec "leaf-$x" ip addr add "${lip}/24" dev veth-l

        ip netns exec "node-$x" ip link add $BR type bridge
        ip netns exec "node-$x" ip link set $BR up
        ip netns exec "node-$x" ip link set "veth-leaf-$x" master $BR
        ip netns exec "node-$x" ip link set "veth-leaf-$x" up
    done

    sleep 2  # DAD
    echo "  v4 a->b: $(ip netns exec node-a ping -c1 -W2 $V4_B >/dev/null 2>&1 && echo OK || echo FAIL)"
    echo "  v6 b->c: $(ip netns exec node-b ping6 -c1 -W2 $V6_C >/dev/null 2>&1 && echo OK || echo FAIL)"
}

dump_state() {
    local label=$1
    echo ""
    echo "========================================"
    echo "  STATE DUMP: $label"
    echo "========================================"
    for x in a b c; do
        echo "--- node-$x ---"
        echo "  bridge fdb:"
        ip netns exec "node-$x" bridge fdb show br $BR 2>/dev/null | grep -v "33:33\|01:00:5e" | sed 's/^/    /'
        echo "  vxlan details:"
        for vx in vxlan-v4 vxlan-v6; do
            ip netns exec "node-$x" ip -d link show "$vx" 2>/dev/null | grep -E "vxlan|mtu|bridge_slave|hairpin|learning|fan" | sed 's/^/    /' || true
        done
        echo "  link stats:"
        for vx in vxlan-v4 vxlan-v6; do
            local stats=$(ip netns exec "node-$x" ip -s link show "$vx" 2>/dev/null | grep -A1 "TX:" | tail -1 | awk '{printf "TX: bytes=%s pkts=%s err=%s drop=%s", $1,$2,$3,$4}')
            [ -n "$stats" ] && echo "    $vx $stats"
        done
    done
}

send_unicast_test() {
    local label=$1
    echo ""
    echo "========================================"
    echo "  SEND TEST: $label"
    echo "========================================"

    # Reset TX counters by reading before
    for x in a b c; do
        for vx in vxlan-v4 vxlan-v6; do
            ip netns exec "node-$x" ip -s link show "$vx" 2>/dev/null > "$TMPDIR/before_${x}_${vx}" || true
        done
    done

    # Start tcpdump on underlay + vxlan devices
    for x in a b c; do
        for dev in eth-v4 eth-v6 vxlan-v4 vxlan-v6; do
            ip netns exec "node-$x" timeout 5 tcpdump -i "$dev" -c 50 -nn -e 2>"$TMPDIR/tcpdump_${label}_${x}_${dev}.txt" &
        done 2>/dev/null
    done
    sleep 0.5

    echo "  Sending 10 frames: leaf-a($MAC_A) -> leaf-c($MAC_C)"
    ip netns exec leaf-a python3 "$SEND_SCRIPT" \
        --iface veth-l --dst-mac "$MAC_C" --count 10 --interval-ms 100

    echo "  Sending 10 frames: leaf-c($MAC_C) -> leaf-a($MAC_A)"
    ip netns exec leaf-c python3 "$SEND_SCRIPT" \
        --iface veth-l --dst-mac "$MAC_A" --count 10 --interval-ms 100

    echo "  Sending 10 frames: leaf-a($MAC_A) -> leaf-b($MAC_B)"
    ip netns exec leaf-a python3 "$SEND_SCRIPT" \
        --iface veth-l --dst-mac "$MAC_B" --count 10 --interval-ms 100

    sleep 3
    wait 2>/dev/null || true

    echo ""
    echo "  -- TX/RX stats after send --"
    for x in a b c; do
        for vx in vxlan-v4 vxlan-v6; do
            local tx_line=$(ip netns exec "node-$x" ip -s link show "$vx" 2>/dev/null | grep -A1 "TX:" | tail -1)
            local rx_line=$(ip netns exec "node-$x" ip -s link show "$vx" 2>/dev/null | grep -A1 "RX:" | tail -1)
            if [ -n "$tx_line" ]; then
                echo "    node-$x/$vx TX=$(echo $tx_line | awk '{printf "pkts=%s drop=%s",$2,$4}') RX=$(echo $rx_line | awk '{printf "pkts=%s drop=%s",$2,$4}')"
            fi
        done
    done

    echo ""
    echo "  -- tcpdump summaries --"
    for f in "$TMPDIR"/tcpdump_${label}_*.txt; do
        local name=$(basename "$f" .txt | sed "s/tcpdump_${label}_//")
        local count=$(wc -l < "$f" 2>/dev/null || echo 0)
        [ "$count" -gt 0 ] && echo "    $name: $count lines" && head -3 "$f" | sed 's/^/      /'
    done
}

# ════════════════════════════════════════════════════════
#  PART 1: STATIC SETUP
# ════════════════════════════════════════════════════════

echo ""
echo "########################################"
echo "#  PART 1: FULLY STATIC               #"
echo "########################################"

create_topology

echo "=== Creating static vxlan devices ==="

# node-a: vxlan-v4 only
ip netns exec node-a ip link add vxlan-v4 type vxlan id $VNI local $V4_A dstport $DSTPORT nolearning ttl 255
ip netns exec node-a ip link set vxlan-v4 mtu $MTU
ip netns exec node-a ip link set vxlan-v4 master $BR
ip netns exec node-a ip link set vxlan-v4 type bridge_slave hairpin on learning off
ip netns exec node-a ip link set vxlan-v4 up

# node-b: vxlan-v4 + vxlan-v6
ip netns exec node-b ip link add vxlan-v4 type vxlan id $VNI local $V4_B dstport $DSTPORT nolearning ttl 255
ip netns exec node-b ip link set vxlan-v4 mtu $MTU
ip netns exec node-b ip link set vxlan-v4 master $BR
ip netns exec node-b ip link set vxlan-v4 type bridge_slave hairpin on learning off
ip netns exec node-b ip link set vxlan-v4 up

ip netns exec node-b ip link add vxlan-v6 type vxlan id $VNI local $V6_B dstport $DSTPORT nolearning ttl 255
ip netns exec node-b ip link set vxlan-v6 mtu $MTU
ip netns exec node-b ip link set vxlan-v6 master $BR
ip netns exec node-b ip link set vxlan-v6 type bridge_slave hairpin on learning off
ip netns exec node-b ip link set vxlan-v6 up

# node-c: vxlan-v6 only
ip netns exec node-c ip link add vxlan-v6 type vxlan id $VNI local $V6_C dstport $DSTPORT nolearning ttl 255
ip netns exec node-c ip link set vxlan-v6 mtu $MTU
ip netns exec node-c ip link set vxlan-v6 master $BR
ip netns exec node-c ip link set vxlan-v6 type bridge_slave hairpin on learning off
ip netns exec node-c ip link set vxlan-v6 up

echo "=== Adding static FDB entries ==="

# node-a: leaf-b -> node-b(v4), leaf-c -> node-b(v4) (relay via b)
ip netns exec node-a bridge fdb append $MAC_B dev vxlan-v4 self dst $V4_B
ip netns exec node-a bridge fdb append $MAC_B dev vxlan-v4 master
ip netns exec node-a bridge fdb append $MAC_C dev vxlan-v4 self dst $V4_B
ip netns exec node-a bridge fdb append $MAC_C dev vxlan-v4 master

# node-b: leaf-a -> node-a(v4), leaf-c -> node-c(v6)
ip netns exec node-b bridge fdb append $MAC_A dev vxlan-v4 self dst $V4_A
ip netns exec node-b bridge fdb append $MAC_A dev vxlan-v4 master
ip netns exec node-b bridge fdb append $MAC_C dev vxlan-v6 self dst $V6_C
ip netns exec node-b bridge fdb append $MAC_C dev vxlan-v6 master

# node-c: leaf-a -> node-b(v6), leaf-b -> node-b(v6) (relay via b)
ip netns exec node-c bridge fdb append $MAC_A dev vxlan-v6 self dst $V6_B
ip netns exec node-c bridge fdb append $MAC_A dev vxlan-v6 master
ip netns exec node-c bridge fdb append $MAC_B dev vxlan-v6 self dst $V6_B
ip netns exec node-c bridge fdb append $MAC_B dev vxlan-v6 master

dump_state "STATIC"
send_unicast_test "static"

# ════════════════════════════════════════════════════════
#  PART 2: VXLAN-CONTROLLER SETUP (same topology)
# ════════════════════════════════════════════════════════

echo ""
echo "########################################"
echo "#  PART 2: VXLAN-CONTROLLER            #"
echo "########################################"

echo "=== Tearing down static vxlan devices ==="
for x in a b c; do
    ip netns exec "node-$x" ip link del vxlan-v4 2>/dev/null || true
    ip netns exec "node-$x" ip link del vxlan-v6 2>/dev/null || true
    ip netns exec "node-$x" ip link del tap-inject 2>/dev/null || true
done

echo "=== Building binaries ==="
cd "$PROJECT_DIR"
go build -o vxlan-controller ./cmd/controller/
go build -o vxlan-client ./cmd/client/

echo "=== Generating keys ==="
PRIV_A=$(wg genkey); PUB_A=$(echo "$PRIV_A" | wg pubkey)
PRIV_B=$(wg genkey); PUB_B=$(echo "$PRIV_B" | wg pubkey)
PRIV_C=$(wg genkey); PUB_C=$(echo "$PRIV_C" | wg pubkey)
PRIV_CTRL=$(wg genkey); PUB_CTRL=$(echo "$PRIV_CTRL" | wg pubkey)

# Use node-b as controller (it has both v4 and v6)
echo "=== Writing controller config (node-b) ==="
cat > "$TMPDIR/controller.yaml" << YAML
private_key: "${PRIV_CTRL}"
client_offline_timeout: 30
sync_new_client_debounce: 2
sync_new_client_debounce_max: 5
topology_update_debounce: 1
topology_update_debounce_max: 3
probing:
  probe_interval_s: 10
  probe_times: 3
  in_probe_interval_ms: 100
  probe_timeout_ms: 2000
address_families:
  v4:
    ISP1:
      enable: true
      bind_addr: "${V4_B}"
      communication_port: 5000
      vxlan_vni: ${VNI}
      vxlan_dst_port: ${DSTPORT}
  v6:
    ISP1:
      enable: true
      bind_addr: "${V6_B}"
      communication_port: 5001
      vxlan_vni: ${VNI}
      vxlan_dst_port: ${DSTPORT}
allowed_clients:
  - client_id: "${PUB_A}"
    client_name: "node-a"

  - client_id: "${PUB_B}"
    client_name: "node-b"

  - client_id: "${PUB_C}"
    client_name: "node-c"

YAML

echo "=== Writing client configs ==="
# node-a: v4 only
cat > "$TMPDIR/client-a.yaml" << YAML
private_key: "${PRIV_A}"
bridge_name: "${BR}"
clamp_mss_to_mtu: false
neigh_suppress: false
init_timeout: 5
ntp_servers: []
address_families:
  v4:
    ISP1:
      enable: true
      bind_addr: "${V4_A}"
      probe_port: 5010
      communication_port: 5000
      vxlan_name: "vxlan-v4-ISP1"
      vxlan_vni: ${VNI}
      vxlan_mtu: ${MTU}
      vxlan_dst_port: ${DSTPORT}
      priority: 10
      controllers:
        - pubkey: "${PUB_CTRL}"
          addr: "${V4_B}:5000"
YAML

# node-b: v4 + v6
cat > "$TMPDIR/client-b.yaml" << YAML
private_key: "${PRIV_B}"
bridge_name: "${BR}"
clamp_mss_to_mtu: false
neigh_suppress: false
init_timeout: 5
ntp_servers: []
address_families:
  v4:
    ISP1:
      enable: true
      bind_addr: "${V4_B}"
      probe_port: 5010
      communication_port: 5000
      vxlan_name: "vxlan-v4-ISP1"
      vxlan_vni: ${VNI}
      vxlan_mtu: ${MTU}
      vxlan_dst_port: ${DSTPORT}
      priority: 10
      controllers:
        - pubkey: "${PUB_CTRL}"
          addr: "${V4_B}:5000"
  v6:
    ISP1:
      enable: true
      bind_addr: "${V6_B}"
      probe_port: 5011
      communication_port: 5001
      vxlan_name: "vxlan-v6-ISP1"
      vxlan_vni: ${VNI}
      vxlan_mtu: ${MTU}
      vxlan_dst_port: ${DSTPORT}
      priority: 10
      controllers:
        - pubkey: "${PUB_CTRL}"
          addr: "[${V6_B}]:5001"
YAML

# node-c: v6 only
cat > "$TMPDIR/client-c.yaml" << YAML
private_key: "${PRIV_C}"
bridge_name: "${BR}"
clamp_mss_to_mtu: false
neigh_suppress: false
init_timeout: 5
ntp_servers: []
address_families:
  v6:
    ISP1:
      enable: true
      bind_addr: "${V6_C}"
      probe_port: 5011
      communication_port: 5001
      vxlan_name: "vxlan-v6-ISP1"
      vxlan_vni: ${VNI}
      vxlan_mtu: ${MTU}
      vxlan_dst_port: ${DSTPORT}
      priority: 10
      controllers:
        - pubkey: "${PUB_CTRL}"
          addr: "[${V6_B}]:5001"
YAML

echo "=== Starting controller (node-b) ==="
ip netns exec node-b "$PROJECT_DIR/vxlan-controller" -config "$TMPDIR/controller.yaml" > "$TMPDIR/ctrl.log" 2>&1 &
sleep 2

echo "=== Starting clients ==="
ip netns exec node-a "$PROJECT_DIR/vxlan-client" -config "$TMPDIR/client-a.yaml" > "$TMPDIR/client-a.log" 2>&1 &
ip netns exec node-b "$PROJECT_DIR/vxlan-client" -config "$TMPDIR/client-b.yaml" > "$TMPDIR/client-b.log" 2>&1 &
ip netns exec node-c "$PROJECT_DIR/vxlan-client" -config "$TMPDIR/client-c.yaml" > "$TMPDIR/client-c.log" 2>&1 &

echo "=== Waiting 25s for convergence ==="
sleep 25

echo "=== Controller FDB state check ==="
grep "FDB added\|FDB route:" "$TMPDIR/client-a.log" 2>/dev/null | tail -10
echo "---"
grep "FDB added\|FDB route:" "$TMPDIR/client-b.log" 2>/dev/null | tail -10
echo "---"
grep "FDB added\|FDB route:" "$TMPDIR/client-c.log" 2>/dev/null | tail -10

dump_state "CONTROLLER"
send_unicast_test "controller"

# ════════════════════════════════════════════════════════
#  COMPARISON
# ════════════════════════════════════════════════════════

echo ""
echo "########################################"
echo "#  DIFF SUMMARY                        #"
echo "########################################"
echo ""
echo "Compare tcpdump files in $TMPDIR:"
echo "  ls $TMPDIR/tcpdump_*.txt"
echo ""
echo "Key files to diff:"
echo "  diff $TMPDIR/tcpdump_static_b_vxlan-v4.txt $TMPDIR/tcpdump_controller_b_vxlan-v4.txt"
echo "  diff $TMPDIR/tcpdump_static_b_vxlan-v6.txt $TMPDIR/tcpdump_controller_b_vxlan-v6.txt"
echo ""
echo "Client logs:"
echo "  $TMPDIR/client-{a,b,c}.log"
echo "  $TMPDIR/ctrl.log"
