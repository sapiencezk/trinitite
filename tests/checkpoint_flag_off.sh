#!/usr/bin/env bash
# Row 212 PR 1a/1b: with I3_CHECKPOINT_EVERY unset neither the checkpoint
# writer (1a) nor the checkpoint boot (1b) may change the image. Builds BASE (default: the row 200 reserve fix, 9927b88c)
# and the working tree without the flag in the same configs and requires
# byte-identical kernel8.img; then checks the flag-on build compiles and
# differs, and that the 1b boot-test writer knobs compile.
# Usage: tests/checkpoint_flag_off.sh [BASE]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=${1:-${BASE:-9927b88c}}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ckpt-off.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
git -C "$ROOT" archive "$BASE" | tar -x -C "$WORK" --one-top-level=base
mkdir "$WORK/head"
(cd "$ROOT" && git ls-files -co --exclude-standard -z | xargs -0 -I{} cp --parents {} "$WORK/head/")
# MEM_MIN_KB=N: wait before each make until MemAvailable >= N kB (box rule; unset = no wait).
memwait() {
    [ -n "${MEM_MIN_KB:-}" ] || return 0
    while [ "$(awk '/MemAvailable/{print $2}' /proc/meminfo)" -lt "$MEM_MIN_KB" ]; do sleep 30; done
}
build() { # dir tag args...
    local d=$1 tag=$2; shift 2
    memwait
    printf '\0%.0s' $(seq 16) > "$d/pill.bin"
    make -C "$d" "$@" all >"$WORK/$tag.log" 2>&1 || { tail -20 "$WORK/$tag.log"; exit 1; }
    cp "$d/kernel8.img" "$WORK/$tag.img"
}
fail=0
CONFIGS=("PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=semihost"
         "PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=semihost I3_PERSIST_HEADROOM_CELLS=6000"
         "")
i=0
for cfg in "${CONFIGS[@]}"; do
    # shellcheck disable=SC2086
    build "$WORK/base" "b$i" $cfg
    # shellcheck disable=SC2086
    build "$WORK/head" "h$i" $cfg
    if cmp -s "$WORK/b$i.img" "$WORK/h$i.img"; then
        echo "PASS flag-off identical [${cfg:-default}] sha256=$(sha256sum "$WORK/h$i.img" | cut -c1-16)"
    else
        echo "FAIL flag-off differs [${cfg:-default}]"; fail=1
    fi
    i=$((i+1))
done
build "$WORK/head" on PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=semihost I3_CHECKPOINT_EVERY=2000
if cmp -s "$WORK/h0.img" "$WORK/on.img"; then
    echo "FAIL flag-on image equals flag-off image"; fail=1
else
    echo "PASS flag-on build compiles and differs"
fi
build "$WORK/head" knob PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=semihost \
    I3_CHECKPOINT_EVERY=2 I3_CKPT_TEST=hdrd I3_CKPT_TEST_FROM=3
echo "PASS flag-on boot-test knob build compiles"
exit $fail
