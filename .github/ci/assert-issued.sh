#!/usr/bin/env bash
# Starts CoreDNS and waits until a check command succeeds (a certificate was issued).
# Usage: assert-issued.sh <coredns-bin> <corefile> <check-cmd> [timeout-seconds]
set -euo pipefail

BIN="${1:?coredns binary}"
COREFILE="${2:?corefile}"
CHECK="${3:?check command}"
TIMEOUT="${4:-90}"

LOG="$(mktemp)"
"$BIN" -conf "$COREFILE" >"$LOG" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true' EXIT

for ((i = 0; i < TIMEOUT; i++)); do
  if eval "$CHECK"; then
    echo "issued after ${i}s"
    exit 0
  fi
  sleep 1
done

echo "TIMEOUT after ${TIMEOUT}s: check never passed: $CHECK" >&2
echo "----- coredns log -----" >&2
cat "$LOG" >&2
exit 1
