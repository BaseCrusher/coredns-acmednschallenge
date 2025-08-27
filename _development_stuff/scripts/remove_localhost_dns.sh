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
    echo "Removing entry: $IP $HOSTNAME"
    SED_REGEX="/^$(make_regex $IP)[[:space:]]+$(make_regex $HOSTNAME)[[:space:]]*$/d"
    if [[ "$(uname)" == "Darwin" ]]; then
      sudo sed -i '' -E $SED_REGEX /etc/hosts
    else
      sudo sed -i $SED_REGEX /etc/hosts
    fi
else
    echo "No matching entry found: $IP $HOSTNAME"
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
    echo "$HOSTNAME still resolves. Entry may not have been removed properly."
else
    echo "$HOSTNAME no longer resolves (expected)."
fi