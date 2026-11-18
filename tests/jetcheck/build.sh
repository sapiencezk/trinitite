#!/usr/bin/env bash
# Rebuild tests/jetcheck/jetcheck.jam.gz from tests/jetcheck/jetcheck.hoon with
# honk, on a 1499kernel checkout's staged deps root (its `make stage`:
# build/kernel/hoon, the nockchain pin's hoon/common plus the kernel's
# hoon/lib), the same way 1499kernel builds its own apps.
#
#   tests/jetcheck/build.sh KERNEL_ROOT HONK
set -euo pipefail

TT="$(cd "$(dirname "$0")/../.." && pwd)"
K="$(cd "$1" && pwd)"
HONK="$2"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

cp -R "$K/build/kernel/hoon" "$W/deps"
mkdir -p "$W/deps/apps/jetcheck"
cp "$TT/tests/jetcheck/jetcheck.hoon" "$W/deps/apps/jetcheck/jetcheck.hoon"
python3 "$K/tools/stage_entry.py" "$W/deps" apps/jetcheck/jetcheck.hoon \
    common/hoon.hoon "$W/entry"
"$HONK" --new --no-dbug --output "$W/jetcheck.jam" \
    --prelude "$W/entry/common/hoon.hoon" "$W/entry/apps/jetcheck/jetcheck.hoon" "$W/entry"
gzip -9n -c "$W/jetcheck.jam" > "$TT/tests/jetcheck/jetcheck.jam.gz"
echo "jetcheck.jam bytes=$(wc -c < "$W/jetcheck.jam" | tr -d ' ') sha256=$(shasum -a 256 "$W/jetcheck.jam" | cut -d' ' -f1)"
