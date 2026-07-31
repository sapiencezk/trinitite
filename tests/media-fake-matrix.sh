#!/usr/bin/env bash
# Exercise the production cold append/selection path at every fake-media
# transfer boundary without holding up the ordinary single-session suite.

set -euo pipefail
cd "$(dirname "$0")/.."

TIMEOUT_BIN=$(command -v timeout || command -v gtimeout || true)
if [[ -z "$TIMEOUT_BIN" ]]; then
    echo "ERROR: need timeout or gtimeout (brew install coreutils)" >&2
    exit 1
fi

# The M7 deployment matrix covers every transfer boundary, A/B parity, nine
# controller fault classes, and six corruption byte positions. It completes in
# roughly 60 seconds under QEMU; retain bounded headroom rather than truncating
# the test before MEDM3 reports its result.
RAW=$({ printf '%s\n' "MEDB3 ." "MEDM3 ."; sleep 90; printf '\001x'; } | \
    "$TIMEOUT_BIN" 120 qemu-system-aarch64 -machine raspi4b -m 2G \
        -kernel kernel8.img -display none -nographic || true)

RESULTS=$(printf '%s\n' "$RAW" |
    tr -d '\r' |
    grep -Ec '^0000000000000000[[:space:]]+ok' || true)
if [[ "$RESULTS" -eq 2 ]]; then
    echo "fake-media smoke and transfer-boundary matrix passed"
    exit 0
fi

echo "ERROR: fake-media transfer-boundary matrix failed or timed out" >&2
printf '%s\n' "$RAW" | tail -40 >&2
exit 1
