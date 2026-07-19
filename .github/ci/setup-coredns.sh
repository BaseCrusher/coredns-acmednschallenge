#!/usr/bin/env bash
# Drops this plugin into a CoreDNS checkout and prepares it for build/test.
# Usage: setup-coredns.sh <coredns-checkout-dir>
set -euo pipefail

COREDNS_DIR="${1:?usage: setup-coredns.sh <coredns-checkout-dir>}"
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Drop the plugin in (skip its own git dir and the CI harness under .github).
mkdir -p "$COREDNS_DIR/plugin/acmednschallenge"
rsync -a --delete --exclude '.git' --exclude '.github' \
  "$PLUGIN_DIR/" "$COREDNS_DIR/plugin/acmednschallenge/"

# Register the plugin so `go generate` wires it into CoreDNS. It must be ordered
# BEFORE `file`/`forward`: CoreDNS chains plugins in plugin.cfg order, and this
# plugin only intercepts `_acme-challenge` TXT queries and passes everything else
# to the next plugin — so it has to run before whatever answers the zone.
if ! grep -q '^acmednschallenge:' "$COREDNS_DIR/plugin.cfg"; then
  awk '/^file:file/ && !ins {print "acmednschallenge:acmednschallenge"; ins=1} {print}' \
    "$COREDNS_DIR/plugin.cfg" > "$COREDNS_DIR/plugin.cfg.tmp"
  mv "$COREDNS_DIR/plugin.cfg.tmp" "$COREDNS_DIR/plugin.cfg"
fi

cd "$COREDNS_DIR"
go generate
go mod tidy
