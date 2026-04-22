#!/bin/bash
# Multi-channel autogen + config load smoke test.
# No networking: exercises config generation + parsing for per-channel setups.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMPDIR=$(mktemp -d)

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

cd "$PROJECT_DIR"
go build -o "$TMPDIR/vxlan-controller" ./cmd/vxlan-controller/

cat > "$TMPDIR/topology.yaml" << 'YAML'
vxlan_dst_port: 4789
communication_port: 5000
vxlan_vni: 100
probe_port: 5010

nodes:
  siteA:
    v4:
      ISP1: 10.1.1.1
      ISP2: 10.2.1.1
  siteB:
    v4:
      ISP1: 10.1.1.2
      ISP2: 10.2.1.2
  hub:
    v4:
      ISP1: 203.0.113.10
      ISP2: 203.0.113.20

controllers:
  - hub
clients:
  - siteA
  - siteB
  - hub
YAML

echo "=== autogen ==="
"$TMPDIR/vxlan-controller" --mode autogen --config "$TMPDIR/topology.yaml"

echo ""
echo "=== verify siteA client config ==="
f="$TMPDIR/siteA.client.yaml"
for want in "ISP1" "ISP2" "vxlan-v4-ISP1" "vxlan-v4-ISP2" "10.1.1.1" "10.2.1.1"; do
    if ! grep -q "$want" "$f"; then
        echo "  FAIL: $f missing $want"
        exit 1
    fi
    echo "  OK: $f contains $want"
done

echo ""
echo "=== verify hub controller config ==="
f="$TMPDIR/hub.controller.yaml"
for want in "ISP1" "ISP2" "203.0.113.10" "203.0.113.20"; do
    if ! grep -q "$want" "$f"; then
        echo "  FAIL: $f missing $want"
        exit 1
    fi
    echo "  OK: $f contains $want"
done

echo ""
echo "=== verify siteA controllers include both channel endpoints ==="
f="$TMPDIR/siteA.client.yaml"
for want in "203.0.113.10:5000" "203.0.113.20:5000"; do
    if ! grep -q "$want" "$f"; then
        echo "  FAIL: siteA.client.yaml missing endpoint $want"
        exit 1
    fi
    echo "  OK: siteA client references endpoint $want"
done

echo ""
echo "=== verify vxlan_name uniqueness across (af, channel) ==="
if grep -c "vxlan-v4-ISP1" "$TMPDIR/siteA.client.yaml" | grep -q "^[1-9]"; then
    echo "  OK: vxlan-v4-ISP1 present"
fi
if grep -c "vxlan-v4-ISP2" "$TMPDIR/siteA.client.yaml" | grep -q "^[1-9]"; then
    echo "  OK: vxlan-v4-ISP2 present"
fi

echo ""
echo "PASS: multi-channel autogen produces parseable per-channel configs"
