# Row 212 lite checkpoint writer: plan (PR 1a and after)

Base: trinitite `fix/persist-replay-reserve` @ e07fd2b (trinitite#9, row 200 amendment / PLAN row 213).
Branch: trinitite `feat/lite-checkpoint-writer`. Sources: PLAN row 212 (in #254), Dwarf's read §7-10
(`/workspace/research/lite-replay-dwarf-read.md`).

## Scope of PR 1a (this branch)
- Compile-time flag `I3_CHECKPOINT_EVERY=K` (Makefile knob, requires `I3_HOST=1`, adds `-i3ckK` to CONFIG_KEY).
  Unset = off = default. With it off no checkpoint code is compiled; `tests/checkpoint_flag_off.sh`
  shows byte-identical `kernel8.img` against e07fd2b in three configs.
- Writer only. Boot does not read checkpoints, nothing is rotated, nothing is dropped. So rotation is
  "suspended" in the row 212 (4) sense for the whole PR, and row 200/213 replay-from-entry-1 is unchanged.

## Format (1a)
After a committed live step (normal poke and the %crud re-poke path; never during replay, never once stopped)
when N = event_num-1 is a multiple of K:
1. `state` = axis 6 of the kernel core (the sample `persist_prepare` copies).
2. Bounds: distinct cells < 65,536 (`job_cells`, a conservative stand-in for row 212's 128k-cell cue bound)
   and jam ≤ `JAM_MAX_BYTES` (128 KiB, the cold writer's buffer). Otherwise `I3H ckpt skip reason=cells|jam-size`.
3. `D = sha256(jam(state))` (bytes from `jam_encode_bytes_checked`).
4. `sid = cold_store(state)` (BLOB; cold's 62-bit BLAKE3 identity), then **verify**: `cold_load(sid)`, re-jam,
   re-hash, must equal D.
5. Header BLOB `[%i3-ckpt N sid D kernel-blake3]` stored and read back. `kernel-blake3` is the boot kernel
   jam identity already computed in `i3_host_boot`.
6. `nv_flush`, then `I3H ckpt ok event=N bytes=… sha256=D`. Any failure: `I3H ckpt skip event=N reason=…`;
   the step is already committed and unaffected.
All checkpoint allocation is in SCRATCH (the caller's scratch reset drops it); persist is untouched, so the
row 213 reserve accounting is unchanged.

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
Newest header whose sid loads, re-hashes to D and whose kernel-blake3 matches the booted jam → cue into the
versioned `+load` → replay entries after N. Fallback per row 212 (3). Never boot from an unverified image.

## Open questions
1. Is sha256(jam(axis 6)) exactly `/state-hash` (row 199)? Needs the shax/jam jets of trinitite#8 and a
   comparison against the kernel peek. Byte order/trailing-zero handling of the jam atom must match `shax`.
2. Smoke run: D was identical at N=10/20/30 with R4 `[1 1]` events. Either the sample really is unchanged by
   those events or axis 6 is not the part that moves; to confirm against the /state-hash peek.
3. Real cue bound: replace the 65,536 job counter with the 128k-cell cue bound check proper.
4. Does a checkpoint BLOB written during cold-store pressure need its own headroom rule (cold media full)?
5. Cadence on persist headroom ("or when headroom falls under one checkpoint plus margin") is not in 1a.
6. Cost of writing a checkpoint every K steps (time, cold bytes) is not measured; no board run.
