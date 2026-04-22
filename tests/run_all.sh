#!/bin/bash
# Run all VXLAN controller integration tests.
# Each test sets up its own topology and cleans up after itself.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TESTS=(
    "test_multichannel_autogen.sh"
    "test_connectivity.sh"
    "test_neigh_suppress.sh"
    "test_controller_failover.sh"
    "test_transit_failure.sh"
    "test_broadcast_relay.sh"
    "test_dual_stack.sh"
    "test_ip_change.sh"
    "test_no_flood.sh"
    "test_firewall.sh"
)

total=0
passed=0
failed=0
failed_tests=()

# Allow running a subset: ./run_all.sh test_connectivity.sh test_dual_stack.sh
if [ $# -gt 0 ]; then
    TESTS=("$@")
fi

for test in "${TESTS[@]}"; do
    total=$((total + 1))
    echo ""
    echo "################################################################"
    echo "# Running: $test"
    echo "################################################################"

    if bash "$SCRIPT_DIR/$test"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        failed_tests+=("$test")
    fi
done

echo ""
echo "================================================================"
echo "  Overall: ${passed}/${total} test suites passed, ${failed} failed"
echo "================================================================"

if [ ${#failed_tests[@]} -gt 0 ]; then
    echo ""
    echo "  Failed suites:"
    for t in "${failed_tests[@]}"; do
        echo "    - $t"
    done
fi

exit $failed
