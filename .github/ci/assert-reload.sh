#!/usr/bin/env bash
set -euo pipefail

BIN="${1:?coredns binary}"
TEMPLATE="${2:?corefile template}"
TIMEOUT="${3:-60}"

WORK="$(mktemp -d)"
COREFILE="$WORK/Corefile"
LOG="$WORK/coredns.log"
sed -e "s#__CERT_DIR__#$WORK/certs#" -e "s#__ACCT_DIR__#$WORK/acme#" "$TEMPLATE" > "$COREFILE"

"$BIN" -conf "$COREFILE" >"$LOG" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

dump() { echo "----- coredns log -----" >&2; cat "$LOG" >&2; }
sha_count() { grep -c 'Running configuration SHA512' "$LOG" || true; }

for ((i = 0; i < TIMEOUT; i++)); do
  [ "$(sha_count)" -ge 1 ] && break
  sleep 1
done
if [ "$(sha_count)" -lt 1 ]; then
  echo "TIMEOUT after ${TIMEOUT}s: server never started" >&2; dump; exit 1
fi
FIRST="$(sha_count)"
echo "started (sha512 lines=$FIRST)"

sed 's/renewBeforeDays 120/renewBeforeDays 90/' "$COREFILE" > "$COREFILE.new" && mv "$COREFILE.new" "$COREFILE"

for ((i = 0; i < TIMEOUT; i++)); do
  if grep -q 'reload failed' "$LOG"; then
    echo "reload FAILED:" >&2; grep -E 'reload failed|acmechallenge' "$LOG" >&2; dump; exit 1
  fi
  if [ "$(sha_count)" -gt "$FIRST" ]; then
    echo "reloaded cleanly after ${i}s (sha512 lines=$(sha_count))"
    exit 0
  fi
  sleep 1
done

echo "TIMEOUT after ${TIMEOUT}s: server never reloaded" >&2; dump; exit 1
