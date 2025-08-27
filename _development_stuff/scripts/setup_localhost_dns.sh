#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

HOSTNAME="ns1.example.com"
IP="127.0.0.1"

make_regex() {
    echo "$1" | sed 's/\./\\./g'
}

GREP_REGEX="^$(make_regex $IP)[[:space:]]+$(make_regex $HOSTNAME)$"

if grep -qE $GREP_REGEX /etc/hosts; then
    echo "Entry already exists: $IP $HOSTNAME"
else
    echo "Adding entry: $IP $HOSTNAME"
    echo "$IP $HOSTNAME" | sudo tee -a /etc/hosts > /dev/null
fi

if [[ "$(uname)" == "Darwin" ]]; then
    sudo dscacheutil -flushcache
    sudo killall -HUP mDNSResponder
else
    if command -v systemd-resolve >/dev/null 2>&1; then
        sudo systemd-resolve --flush-caches
    fi
fi

echo "Testing resolution for $HOSTNAME..."
ping -c 1 "$HOSTNAME" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "$HOSTNAME resolves successfully to $IP"
else
    echo "Resolution failed. Try 'ping $HOSTNAME' manually."
fi