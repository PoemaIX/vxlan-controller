#!/bin/sh
# vxlan-controller installer.
#
#   curl -fsSL https://raw.githubusercontent.com/PoemaIX/vxlan-controller/main/install.sh | sh
#
# Downloads the binary from GitHub releases (default: the rolling "dev"
# prerelease; set VXLAN_RELEASE=v1.0.38 for a tagged version), installs the
# systemd units, and creates /etc/vxlan-controller/. It does NOT enable or
# start anything — put your config in place first, then enable manually.

set -eu

REPO="PoemaIX/vxlan-controller"
RELEASE="${VXLAN_RELEASE:-dev}"
BIN_DIR="${VXLAN_BIN_DIR:-/usr/local/bin}"
CONF_DIR="/etc/vxlan-controller"
UNIT_DIR="/etc/systemd/system"
UNITS="vxlan-controller-client.service vxlan-controller-server.service"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root (installs to $BIN_DIR, $UNIT_DIR, $CONF_DIR)" >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64)          suffix="amd64" ;;
    aarch64 | arm64) suffix="arm64" ;;
    armv7l)          suffix="armv7" ;;
    *)
        echo "error: unsupported architecture $(uname -m)" >&2
        exit 1
        ;;
esac

base="https://github.com/${REPO}/releases/download/${RELEASE}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "==> Downloading vxlan-controller-${suffix} (release: ${RELEASE})"
curl -fSL -o "$tmp/vxlan-controller" "${base}/vxlan-controller-${suffix}"

echo "==> Verifying checksum"
curl -fsSL -o "$tmp/checksums.txt" "${base}/checksums.txt"
want=$(awk -v f="vxlan-controller-${suffix}" '$2 == f { print $1 }' "$tmp/checksums.txt")
got=$(sha256sum "$tmp/vxlan-controller" | awk '{print $1}')
if [ -z "$want" ] || [ "$want" != "$got" ]; then
    echo "error: checksum mismatch (want ${want:-none}, got ${got})" >&2
    exit 1
fi

install -m 0755 "$tmp/vxlan-controller" "${BIN_DIR}/vxlan-controller"
echo "==> Installed ${BIN_DIR}/vxlan-controller ($("${BIN_DIR}/vxlan-controller" --version 2>/dev/null || echo unknown))"

echo "==> Installing systemd units"
script_dir=$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)
for unit in $UNITS; do
    if [ -n "$script_dir" ] && [ -f "${script_dir}/systemd/${unit}" ]; then
        install -m 0644 "${script_dir}/systemd/${unit}" "${UNIT_DIR}/${unit}"
    else
        curl -fsSL -o "$tmp/$unit" \
            "https://raw.githubusercontent.com/${REPO}/main/systemd/${unit}"
        install -m 0644 "$tmp/$unit" "${UNIT_DIR}/${unit}"
    fi
done
systemctl daemon-reload

mkdir -p "$CONF_DIR"

cat <<EOF

Done. Nothing has been enabled or started.

Next steps:
  1. Put your config(s) in place:
       ${CONF_DIR}/client.yaml       (every node)
       ${CONF_DIR}/controller.yaml   (controller nodes only)
     Generate them from a topology file with:
       vxlan-controller --mode autogen --config <topology.yaml>
  2. Enable what this node runs:
       systemctl enable --now vxlan-controller-client
       systemctl enable --now vxlan-controller-server   # controller nodes only
EOF
