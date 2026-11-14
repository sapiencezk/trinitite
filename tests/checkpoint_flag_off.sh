#!/usr/bin/env bash
# Row 212 PR 1a/1b: with I3_CHECKPOINT_EVERY= (empty) neither the checkpoint
# writer (1a) nor the checkpoint boot (1b) may change the image. Builds BASE (default: 8d287abd, i3/cue-input-16m with 1a, trinitite#10)
# and the working tree with the flag off in the same configs and requires
# byte-identical kernel8.img; then checks the flag-on build compiles and
# differs, and that the 1b boot-test writer knobs compile.
# Row 317 (3): an I3_HOST build with no flag is the K=2000 build (the writer
# is on by default), so the flag-off head builds pass I3_CHECKPOINT_EVERY=.
# Usage: tests/checkpoint_flag_off.sh [BASE]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=${1:-${BASE:-8d287abd}}
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
    off=""; case "$cfg" in *I3_HOST=1*) off="I3_CHECKPOINT_EVERY=";; esac
    # shellcheck disable=SC2086
    build "$WORK/head" "h$i" $cfg $off
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
build "$WORK/head" dflt PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=semihost
if cmp -s "$WORK/on.img" "$WORK/dflt.img"; then
    echo "PASS no flag is K=2000 (row 317 (3)) sha256=$(sha256sum "$WORK/dflt.img" | cut -c1-16)"
else
    echo "FAIL an I3_HOST build with no flag is not the K=2000 build"; fail=1
fi
build "$WORK/head" knob PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=semihost \
    I3_CHECKPOINT_EVERY=2 I3_CKPT_TEST=hdrd I3_CKPT_TEST_FROM=3
echo "PASS flag-on boot-test knob build compiles"
exit $fail
