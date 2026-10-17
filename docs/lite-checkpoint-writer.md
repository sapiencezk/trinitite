# Row 212 lite checkpoint writer: plan (PR 1a and after)

Base: trinitite `i3/cue-input-16m` @ 9927b88c (trinitite#9 merged: row 200 amendment / PLAN row 213; trinitite#8's `jam_hoon_checked`).
Branch: trinitite `feat/lite-checkpoint-writer`. Sources: PLAN row 212 (in #254), Dwarf's read §7-10
(`/workspace/research/lite-replay-dwarf-read.md`).

## Scope of PR 1a (this branch)
- Compile-time flag `I3_CHECKPOINT_EVERY=K` (Makefile knob, requires `I3_HOST=1`, adds `-i3ckK` to CONFIG_KEY).
  Unset = off = default. With it off no checkpoint code is compiled; `tests/checkpoint_flag_off.sh`
  shows byte-identical `kernel8.img` against 9927b88c in three configs.
- Writer only. Boot does not read checkpoints, nothing is rotated, nothing is dropped. So rotation is
  "suspended" in the row 212 (4) sense for the whole PR, and row 200/213 replay-from-entry-1 is unchanged.

## Format (1a)
After a committed live step (normal poke and the %crud re-poke path; never during replay, never once stopped)
when N = event_num-1 is a multiple of K:
1. Wrapper check: the core's sample (axis 6) must be `[%0 desk-hash internal]`, i.e. axis 12 is the atom 0
   and axis 13 is a cell (so axes 26 and 27 exist); the walk never crashes on an atom. Otherwise
   `I3H ckpt skip reason=wrapper`. Then `state` = axis 27, internal.outer, which is exactly what `/state-hash` jams.
2. Bounds: skip when the state has **> 65,536** distinct cells (65,536 itself is accepted; same walk and
   limit as `job_cells`, `I2_CUE_MAX_CELLS`, a conservative stand-in for row 212's 128k-cell cue bound),
   or when the jam is > `JAM_MAX_BYTES` (128 KiB, the cold writer's buffer). Logs
   `I3H ckpt skip reason=cells|jam-size`. If the walk's stack would overflow it logs `reason=stack`, never
   `cells`; with the default bounds that cannot happen (each cell popped pushes at most two, so the stack
   holds at most cells + 1 ≤ 65,537 of its 131,072 slots); it is kept as its own reason so a cell count is
   never misreported.
3. `D = sha256(jam(state))` (bytes from `jam_hoon_checked`, the `++jam` writer of trinitite#8, so D is
   the kernel's `(shax (jam state))`).
4. `sid = cold_store(state)` (BLOB; cold's 62-bit BLAKE3 identity), then **verify**: `cold_load(sid)`, re-jam,
   re-hash, must equal D.
5. Header BLOB `[%i3-ckpt N sid D kernel-blake3]` stored, read back, and required to jam to the same bytes
   as the header written (all five fields; sha256 of both `jam_hoon_checked` encodings compared), else
   `reason=verify-header`. `kernel-blake3` is `g_jam_blake3` from `i3_host_boot`: BLAKE3-256 of the pill's
   kernel jam bytes exactly as read (all `jam_len` bytes, trailing zero bytes included). It is not a hash
   of `jam(cue(pill))` and not cold's 62-bit identity. 1a only records it; nothing compares it yet.
6. `nv_flush`, then `I3H ckpt ok event=N bytes=… sha256=D`. Any failure: `I3H ckpt skip event=N reason=…`;
   the step is already committed and unaffected.
All checkpoint allocation is in SCRATCH (the caller's scratch reset drops it); persist is untouched, so the
row 213 reserve accounting is unchanged.

## Tests
- `tests/checkpoint_flag_off.sh [BASE]`: flag off is byte-identical to BASE in three configs.
- `tests/checkpoint_axis.py`: flag-on QEMU run; every `ckpt ok` digest equals the full node's `/state-hash`.
- `tests/checkpoint_legs.py skip cells|jam|stack|wrapper`: each skip leg with a real state. The Makefile knob
  `I3_CKPT_TEST=` (test builds only, requires `I3_CHECKPOINT_EVERY`) shrinks one bound: cells 8, jam 8 bytes,
  walk stack 2, wrapper tag 1 instead of 0. Every step is still accepted.
- `tests/checkpoint_legs.py replay [--multiboot|--reserve|--reserve3]`: the 1499kernel row 200/213 leg with the
  flag on; it still passes, and no ckpt line appears during replay or after a stop.
The Python tests run from a 1499kernel checkout (they use its tools and full node).

## Rotation (later PR, 1c)
- Only after the newest checkpoint verified. Keep: newest verified checkpoint + the previous one until the
  next verifies, and every entry after the oldest kept one. Retention in entries, floor = 2-3 days at cycle rate.
- If a checkpoint cannot be written (skip), rotation stays suspended and the 141/198/213 stop applies when full.

## SD log and compaction (later PR, 1c/1d)
- Today `cold_log` is an append-only chain in the same cold image as blobs; there is no way to drop a prefix.
- Plan: a log "base" field in the superblock (first retained entry index + the checkpoint header id it
  follows). Rotation = one superblock write moving the base; replay starts at base. Compaction = copy kept
  blobs/entries into the other half of the media (two-region, A/B) and flip the superblock; the old region is
  only reused after the flip verifies. rpi4-sd per-step append cost and torn-write behaviour: not measured.
- Compaction also reclaims persist-reserve growth (row 213's lifetime limit) because replay then starts
  at the checkpoint, so the job sum restarts there.

## Boot (later PR, 1b)
Newest header whose sid loads, re-hashes to D and whose kernel-blake3 equals the booted pill's `g_jam_blake3`
(same bytes-as-read rule, so a pill re-jammed to different bytes does not match) → cue into the
versioned `+load` → replay entries after N. Fallback per row 212 (3). Never boot from an unverified image.

## Open questions
1. ~~Is sha256(jam(axis 6)) exactly `/state-hash` (row 199)?~~ **Answered** by the flag-on smoke run
   (`tests/checkpoint_axis.py`): the state is axis 27, not axis 6, and sha256(jam(axis 27)) with
   `jam_hoon_checked` equals the full node's `/state-hash` at N=2, 4, 6, 8, 10.
2. ~~Smoke run: D was identical at N=10/20/30 with R4 `[1 1]` events.~~ **Answered** by the same run: that
   digest covered axis 6. On axis 27 with events `1,1,1,1,0,1,0,1`, D moves exactly where `/state-hash`
   moves (3 distinct of 5: N=2; N=4=6; N=8=10).
3. Real cue bound: replace the 65,536 job counter with the 128k-cell cue bound check proper.
4. Does a checkpoint BLOB written during cold-store pressure need its own headroom rule (cold media full)?
5. Cadence on persist headroom ("or when headroom falls under one checkpoint plus margin") is not in 1a.
6. Cost of writing a checkpoint every K steps (time, cold bytes) is not measured; no board run.
