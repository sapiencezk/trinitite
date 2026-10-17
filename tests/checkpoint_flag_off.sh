#!/usr/bin/env bash
# Row 212 PR 1a/1b/1c: with I3_CHECKPOINT_EVERY unset neither the checkpoint
# writer (1a), the checkpoint boot (1b) nor the running log and recorder ring
# (1c) may change the image. Builds BASE (default: 8d287abd, i3/cue-input-16m with 1a, trinitite#10)
# and the working tree without the flag in the same configs and requires
# byte-identical kernel8.img; then checks the flag-on build compiles and
# differs, and that the 1b boot-test writer knobs compile.
# 1c: with ONBASE set (e.g. 6613d3b6, feat/lite-checkpoint-boot = 1b), the 1b flag-on
# image (I3_CHECKPOINT_EVERY without I3_LITE_LOG) must also be byte-identical to ONBASE's,
# and the I3_LITE_LOG=1 builds (qemu semihost, ram and fake, rpi4b rpi4-sd, small-ring
# and the crash, fault, torn and rebasefault test knobs) must compile, and the semihost
# one must differ from the 1b flag-on image.
# Usage: tests/checkpoint_flag_off.sh [BASE [ONBASE]]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=${1:-${BASE:-8d287abd}}
ONBASE=${2:-${ONBASE:-}}
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
if [ -n "$ONBASE" ]; then
    git -C "$ROOT" archive "$ONBASE" | tar -x -C "$WORK" --one-top-level=onbase
    for cfg in "PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=semihost I3_CHECKPOINT_EVERY=2000" \
               "I3_HOST=1 COLD_MEDIA=rpi4-sd I3_CHECKPOINT_EVERY=2000"; do
        # shellcheck disable=SC2086
        build "$WORK/onbase" ob $cfg
        # shellcheck disable=SC2086
        build "$WORK/head" oh $cfg
        if cmp -s "$WORK/ob.img" "$WORK/oh.img"; then
            echo "PASS 1b flag-on identical to $ONBASE [$cfg] sha256=$(sha256sum "$WORK/oh.img" | cut -c1-16)"
        else
            echo "FAIL 1b flag-on differs from $ONBASE [$cfg]"; fail=1
        fi
    done
    build "$WORK/head" ll PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=semihost I3_CHECKPOINT_EVERY=2000 I3_LITE_LOG=1
    if cmp -s "$WORK/on.img" "$WORK/ll.img"; then
        echo "FAIL I3_LITE_LOG=1 image equals the 1b flag-on image"; fail=1
    else
        echo "PASS I3_LITE_LOG=1 build compiles and differs from 1b flag-on"
    fi
    build "$WORK/head" llram PLATFORM=qemu-virt I3_HOST=1 COLD_MEDIA=ram I3_CHECKPOINT_EVERY=2000 I3_LITE_LOG=1
    build "$WORK/head" llsd I3_HOST=1 COLD_MEDIA=rpi4-sd I3_CHECKPOINT_EVERY=2000 I3_LITE_LOG=1
    build "$WORK/head" llknob PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=semihost \
        I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 I3_RING_EVERY=2 I3_RING_BYTES=16384 I3_CKPT_TEST=crash I3_CKPT_TEST_FROM=6
    build "$WORK/head" llfake PLATFORM=qemu-virt I3_HOST=1 COLD_MEDIA=fake \
        I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 I3_RING_EVERY=2 I3_RING_BYTES=16384
    build "$WORK/head" llfault PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=fake \
        I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 I3_RING_EVERY=2 I3_RING_BYTES=16384 I3_RING_TEST=fault I3_RING_TEST_AT=8
    build "$WORK/head" lltorn PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=semihost \
        I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 I3_RING_EVERY=2 I3_RING_BYTES=16384 I3_RING_TEST=torn
    build "$WORK/head" llrbf PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 COLD_MEDIA=fake \
        I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 I3_RING_EVERY=2 I3_RING_BYTES=16384 I3_CKPT_TEST=rebasefault
    echo "PASS I3_LITE_LOG=1 builds compile [qemu ram, rpi4b rpi4-sd, qemu fake, small ring + crash, fault, torn and rebasefault knobs]"
fi
exit $fail
