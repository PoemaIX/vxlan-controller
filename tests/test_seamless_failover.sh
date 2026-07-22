#!/bin/bash
# Seamlessness quantification: a continuous ping (0.2s interval) runs ACROSS
# each disruptive event and the measured packet loss must stay under a
# threshold. Existing failover tests only ping after the event settles; this
# asserts the data plane never meaningfully stalls DURING:
#
#   1. controller kill + restart      (FDB must persist, loss ~0%)
#   2. link-latency-driven path switch (old path still carries until the
#      switch lands, loss ~0%)
#   3. short latency blips             (debounce: no route change at all)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/multichannel_helpers.sh"
trap mc_cleanup EXIT

build_binaries
generate_keys
setup_topology_mc
set_default_delays

echo "=== Generating multi-channel configurations (bind_addr method) ==="
generate_mc_configs addr

mc_start_controllers
mc_start_clients
mc_wait_converge 25

leaf_mac() {
    ip netns exec "leaf-$1" cat /sys/class/net/veth-leaf-l-$1/address
}
get_fdb_dst() {
    ip netns exec "node-$1" bridge fdb show | awk -v m="$2" '
        $1 == m && /self/ { for (i=1;i<NF;i++) if ($i=="dst") print $(i+1) }' | head -1
}

LEAF2_MAC=$(leaf_mac 2)

# Wait until node-1's route to leaf-2 is direct and stable (two identical
# samples), so each scenario starts from a converged state.
wait_direct_stable() {
    local deadline=$((SECONDS + 90)) prev="" cur=""
    while [ "$SECONDS" -lt "$deadline" ]; do
        cur=$(get_fdb_dst 1 "$LEAF2_MAC")
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
    echo "  WARN: node-1 -> node-2 never stabilized to a direct route"
    return 1
}

# Map the current FDB dst to the netem device carrying it (node-1 egress).
dev_for_dst() {
    case "$1" in
        ${ISP1_V4}.*) echo "ei1-v4" ;;
        ${ISP2_V4}.*) echo "ei2-v4" ;;
        fd1:*)        echo "ei1-v6" ;;
        fd2:*)        echo "ei2-v6" ;;
        *)            echo "" ;;
    esac
}

# run_ping_bg DURATION_S -> starts leaf-1 -> leaf-2 ping at 0.2s interval,
# writing output to $TMPDIR/ping_run.txt.
run_ping_bg() {
    local dur=$1
    rm -f "$TMPDIR/ping_run.txt"
    ip netns exec leaf-1 ping -i 0.2 -w "$dur" -q "${LEAF_V4}.2" > "$TMPDIR/ping_run.txt" 2>&1 &
    PING_PID=$!
}

# assert_ping_loss NAME MAX_LOSS_PERCENT — waits for the ping to finish.
assert_ping_loss() {
    local name=$1 max=$2
    wait "$PING_PID" 2>/dev/null || true
    local loss
    loss=$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' "$TMPDIR/ping_run.txt" | grep -oE '^[0-9]+(\.[0-9]+)?' | head -1)
    test_total=$((test_total + 1))
    if [ -z "$loss" ]; then
        echo "  TEST: $name ... FAIL (no ping summary)"
        test_fail=$((test_fail + 1))
        return 1
    fi
    if awk -v l="$loss" -v m="$max" 'BEGIN { exit !(l <= m) }'; then
        echo "  TEST: $name ... PASS (loss=${loss}%)"
        test_pass=$((test_pass + 1))
    else
        echo "  TEST: $name ... FAIL (loss=${loss}% > ${max}%)"
        test_fail=$((test_fail + 1))
    fi
}

echo ""
echo "=== Baseline ==="
mc_run_test "baseline ping leaf-1 -> leaf-2" \
    ip netns exec leaf-1 ping -c 3 -W 5 ${LEAF_V4}.2
wait_direct_stable || true

echo ""
echo "=== Scenario 1: controller kill + restart under continuous ping ==="
run_ping_bg 20
sleep 5
kill $(ps -o pid,cmd | grep "controller-10.yaml" | grep -v grep | awk '{print $1}') 2>/dev/null || true
echo "  controller killed at t=5s"
assert_ping_loss "no loss while controller is down" 5

echo "  restarting controller"
mc_start_process node-10 controller "$CTRL_10_CONF" "ctrl-10-restarted"
# The restarted controller pushes an empty route matrix until its first probe
# cycle completes; clients must keep their FDB across that window.
run_ping_bg 25
assert_ping_loss "no loss across controller restart resync" 5
wait_direct_stable || true

echo ""
echo "=== Scenario 2: latency-driven path switch under continuous ping ==="
cur_dst=$(get_fdb_dst 1 "$LEAF2_MAC")
slow_dev=$(dev_for_dst "$cur_dst")
if [ -z "$slow_dev" ]; then
    echo "  TEST: path switch seamlessness ... FAIL (no usable baseline dst: ${cur_dst:-none})"
    test_total=$((test_total + 1)); test_fail=$((test_fail + 1))
else
    echo "  current path dst=$cur_dst dev=$slow_dev; slowing it mid-ping"
    run_ping_bg 40
    sleep 5
    ip netns exec node-1 tc qdisc change dev "$slow_dev" root netem delay 80ms || \
        ip netns exec node-1 tc qdisc add dev "$slow_dev" root netem delay 80ms
    assert_ping_loss "no loss across latency-driven switch" 10

    new_dst=$(get_fdb_dst 1 "$LEAF2_MAC")
    test_total=$((test_total + 1))
    if [ -n "$new_dst" ] && [ "$new_dst" != "$cur_dst" ]; then
        echo "  TEST: route switched off the slowed path ... PASS ($cur_dst -> $new_dst)"
        test_pass=$((test_pass + 1))
    else
        echo "  TEST: route switched off the slowed path ... FAIL (still ${new_dst:-none})"
        test_fail=$((test_fail + 1))
    fi
    ip netns exec node-1 tc qdisc change dev "$slow_dev" root netem delay 1ms || true
fi

sleep 15
wait_direct_stable || true

echo ""
echo "=== Scenario 3: short latency blips do not flap the route (debounce) ==="
base_dst=$(get_fdb_dst 1 "$LEAF2_MAC")
blip_dev=$(dev_for_dst "$base_dst")
if [ -z "$blip_dev" ]; then
    echo "  TEST: blip stability ... FAIL (no usable baseline dst: ${base_dst:-none})"
    test_total=$((test_total + 1)); test_fail=$((test_fail + 1))
else
    echo "  baseline dst=$base_dst dev=$blip_dev; injecting 4x 3s blips of 80ms"
    run_ping_bg 50
    changes=0
    for i in 1 2 3 4; do
        ip netns exec node-1 tc qdisc change dev "$blip_dev" root netem delay 80ms
        sleep 3
        ip netns exec node-1 tc qdisc change dev "$blip_dev" root netem delay 1ms
        # sample during the quiet period
        for _ in 1 2 3; do
            sleep 3
            cur=$(get_fdb_dst 1 "$LEAF2_MAC")
            if [ -n "$cur" ] && [ "$cur" != "$base_dst" ]; then
                changes=$((changes + 1))
                base_dst="$cur"
            fi
        done
    done
    assert_ping_loss "no loss across latency blips" 5
    test_total=$((test_total + 1))
    if [ "$changes" -eq 0 ]; then
        echo "  TEST: route never flapped across blips ... PASS"
        test_pass=$((test_pass + 1))
    else
        echo "  TEST: route never flapped across blips ... FAIL ($changes changes)"
        test_fail=$((test_fail + 1))
    fi
fi

mc_print_results

if [ $test_fail -gt 0 ]; then
    exit 1
fi
echo ""
echo "PASS: data plane stays up through controller loss, path switches, and blips"
