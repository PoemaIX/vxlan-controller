#!/bin/bash
# vxlan-controller sync watchdog.
#
# A client holds every controller's view of the mesh, so `vxccli show diff`
# can compare them locally and exit non-zero when any client's state differs
# between controllers. By design the controllers should always converge to the
# same state; a persistent divergence is a bug to investigate.
#
# This watchdog polls that check and only alerts when the divergence PERSISTS
# across ALERT_THRESHOLD consecutive polls — a single mismatch right after a
# controller (re)joins or a topology change is a normal transient and is
# ignored.
#
# Config via environment (all optional):
#   WATCHDOG_INTERVAL   seconds between polls        (default 30)
#   WATCHDOG_THRESHOLD  consecutive mismatches to alert (default 3)
#   WATCHDOG_SOCK       vxccli socket path override
#   WATCHDOG_ALERT_CMD  shell command run once on alert; the diff detail is
#                       piped to its stdin (e.g. post to a webhook / send mail).
#                       If unset, the alert only goes to syslog + stderr.

set -u

BIN="${WATCHDOG_BIN:-/usr/local/bin/vxlan-controller}"
INTERVAL="${WATCHDOG_INTERVAL:-30}"
THRESHOLD="${WATCHDOG_THRESHOLD:-3}"
SOCK_ARGS=()
[ -n "${WATCHDOG_SOCK:-}" ] && SOCK_ARGS=(--sock "$WATCHDOG_SOCK")

log() { echo "$(date -Is) $*" >&2; logger -t vxlan-watchdog "$*" 2>/dev/null || true; }

consecutive=0
alerted=false

log "started (interval=${INTERVAL}s threshold=${THRESHOLD})"

while true; do
	detail="$("$BIN" --mode vxccli "${SOCK_ARGS[@]}" show diff 2>&1)"
	rc=$?
	case "$rc" in
		0)
			# consistent
			if $alerted; then
				log "RECOVERED: controllers consistent again"
			fi
			consecutive=0
			alerted=false
			;;
		2)
			# mismatch
			consecutive=$((consecutive + 1))
			if [ "$consecutive" -ge "$THRESHOLD" ] && ! $alerted; then
				secs=$((consecutive * INTERVAL))
				log "ALERT: controllers out of sync for >=${secs}s (${consecutive} consecutive checks)"
				echo "$detail" >&2
				if [ -n "${WATCHDOG_ALERT_CMD:-}" ]; then
					printf '%s\n' "$detail" | sh -c "$WATCHDOG_ALERT_CMD" || log "alert command failed"
				fi
				alerted=true
			fi
			;;
		*)
			# rc 1 (socket unreachable / no client running) or other — not a
			# divergence; note it but don't count toward the alert threshold.
			log "check unavailable (rc=$rc): ${detail%%$'\n'*}"
			consecutive=0
			;;
	esac
	sleep "$INTERVAL"
done
