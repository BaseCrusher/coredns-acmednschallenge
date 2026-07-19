#!/usr/bin/env bash
# Proves issuance, then renewal: run CoreDNS to issue a cert, stop it, run it
# again against the same storage. The Corefile sets renewBeforeDays above the
# issued cert's lifetime, so the second boot renews it -> the cert serial changes.
# Usage: assert-renewed.sh <coredns-bin> <corefile> <cert-pem-path> [timeout-per-phase]
set -euo pipefail

BIN="${1:?coredns binary}"
COREFILE="${2:?corefile}"
PEM="${3:?cert .pem path}"
TIMEOUT="${4:-90}"

serial() { openssl x509 -in "$PEM" -noout -serial 2>/dev/null | cut -d= -f2; }

# run_coredns_until <predicate-cmd> : start CoreDNS, poll predicate, then stop it.
run_coredns_until() {
  local pred="$1" log pid i
  log="$(mktemp)"
  "$BIN" -conf "$COREFILE" >"$log" 2>&1 &
  pid=$!
  for ((i = 0; i < TIMEOUT; i++)); do
    if eval "$pred"; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT after ${TIMEOUT}s waiting for: $pred" >&2
  echo "----- coredns log -----" >&2
  cat "$log" >&2
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 1
}

# Phase 1: issue.
run_coredns_until 'test -s "$PEM"'
S1="$(serial)"
echo "issued: serial=$S1"

# Phase 2: renew (serial must change).
run_coredns_until '[ -n "$(serial)" ] && [ "$(serial)" != "'"$S1"'" ]'
echo "renewed: serial=$(serial)"
