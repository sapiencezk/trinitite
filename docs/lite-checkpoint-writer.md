# Row 212 lite checkpoint writer: plan (PR 1a, 1b and after)

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
4. `sid = cold_store(state)` (BLOB; cold's 62-bit BLAKE3 identity), then **verify**: `cold_load_scratch(sid)`,
   re-jam, re-hash, must equal D. `cold_load_scratch` (cold.c, compiled only with the flag) is `cold_load` decoding
   into SCRATCH: `cold_load` always decodes into PERSIST, and at 274d51e0 the two read-backs cost persist cells
   on every checkpoint (flag on, K=2: the row 200/213 legs stopped after 2/4/6 accepted steps instead of 32/33/68).
5. Header BLOB `[%i3-ckpt N sid D kernel-blake3]` stored, read back, and required to jam to the same bytes
   as the header written (all five fields; sha256 of both `jam_hoon_checked` encodings compared), else
   `reason=verify-header`. `kernel-blake3` is `g_jam_blake3` from `i3_host_boot`: BLAKE3-256 of the pill's
   kernel jam bytes exactly as read (all `jam_len` bytes, trailing zero bytes included). It is not a hash
   of `jam(cue(pill))` and not cold's 62-bit identity. 1a only records it; nothing compares it yet.
6. `nv_flush`, then `I3H ckpt ok event=N bytes=… sha256=D`. Any failure: `I3H ckpt skip event=N reason=…`;
   the step is already committed and unaffected.
All checkpoint allocation is in SCRATCH (the caller's scratch reset drops it); persist is untouched, so the
row 213 reserve accounting is unchanged. `tests/checkpoint_legs.py replay` checks it: with the flag on the
legs accept exactly as many steps as with it off.

## Tests
- `tests/checkpoint_flag_off.sh [BASE]`: flag off is byte-identical to BASE in three configs.
- `tests/checkpoint_axis.py`: flag-on QEMU run; every `ckpt ok` digest equals the full node's `/state-hash`.
- `tests/checkpoint_legs.py skip cells|jam|stack|wrapper`: each skip leg with a real state. The Makefile knob
  `I3_CKPT_TEST=` (test builds only, requires `I3_CHECKPOINT_EVERY`) shrinks one bound: cells 8, jam 8 bytes,
  walk stack 2, wrapper tag 1 instead of 0. Every step is still accepted.
- `tests/checkpoint_boot.py` (1b): boot from a checkpoint plus the log tail against a from-zero replay
  of the same cold image, the writer's own reads and the full node, at N=6 and N=7; and the fallback
  legs (shape, sid, D, kernel-blake3, no checkpoint, older checkpoint). Writer knobs for it:
  `I3_CKPT_TEST=hdrshape|hdrsid|hdrd` with `I3_CKPT_TEST_FROM=M` (bad header for every N >= M).
- `tests/checkpoint_legs.py replay [--multiboot|--reserve|--reserve3]`: the 1499kernel row 200/213 leg with the
  flag on; it still passes with the flag-off accepted count, and no ckpt line appears during replay or after a stop.
The Python tests run from a 1499kernel checkout (they use its tools and full node).

## PR 1b: boot from a checkpoint (branch `feat/lite-checkpoint-boot`)
Same flag (`I3_CHECKPOINT_EVERY`), off by default; with it off nothing below is compiled and
`tests/checkpoint_flag_off.sh` shows byte-identical images. At boot, after the kernel is kicked and
persisted and before replay (`ckpt_boot` in `src/i3_host.c`):
1. **Find.** `cold_blob_scan` (cold.c, flag only) walks the selected chain once and decodes every BLOB of
   at most 256 payload bytes into scratch; a header is a cell whose head is `%i3-ckpt` and whose second
   field is a direct atom N. The candidate is the header with the largest N below the current bound
   (ties: the later one in media order). Nothing is written.
2. **Verify**, in this order; the first failure rejects the header with
   `I3H ckpt boot reject event=N reason=R`:
   `shape` (not `[%i3-ckpt N sid D kernel-blake3]` with D and kernel-blake3 at most 32 bytes),
   `n` (N = 0 or N > the log length), `kernel` (kernel-blake3 ≠ this boot's `g_jam_blake3`, the
   BLAKE3-256 of the pill's kernel jam bytes as read), `sid` (`cold_load_scratch(sid)` is not a cell),
   `hash` (sha256 of `jam_hoon_checked(state)` ≠ D), `wrapper` (the booted core is not
   `[%0 desk-hash internal]`), `load` (the versioned `+load` crashed or hit a host bound), `load-hash`
   (the loaded core's axis 27 does not hash to D), `persist` (the persist copy failed).
3. **Load.** The state goes through the versioned `+load`: the NockApp wrapper's outer `+load` (arm 4,
   the web node's `LOAD_AXIS`) slammed with `[%0 desk-hash state]`, desk-hash = the booted core's axis 26.
   Same formula as the web node's `raw_slam`. Run as replay runs (decision 198): no op budget, the cell
   and stack limits stay. Logged as `I3H ckpt boot load event=N abort=… nock_ops_used=… nock_cells_used=…`.
   The loaded core must again hash to D; only then is it copied into persist and installed, and the
   event number set to N+1. **Never boots from an unverified image.**
4. **Replay** only the entries after N, through the same slam and failure reasons. Entries 1..N are
   decoded (to move the cursor and check their event numbers) and their job cells are counted into the
   row 213 sum, so the reserve is the one a from-zero replay of the same log keeps; they are not run.
5. **Fallback, row 212 (3):** "on mismatch try the next older kept checkpoint; if none is valid and the
   log still starts at entry 1, replay from zero; if none is valid and the log has been rotated, the
   node stops (row 141 stop) and reports it. It never boots from an unverified image." A rejected header
   lowers the bound to its N and the search repeats. With none left: `I3H ckpt boot none rejected=R
   fallback=zero` and replay from entry 1. There is no rotation before 1c, so the log always starts at
   entry 1 and the rotated-log stop cannot arise yet. A rejected attempt restores the booted core and
   event number and resets scratch; persist cells a failed persist copy took are not returned.

### Known blocker (1b): the wrapper's `+load` does not fit the lite heap
The wrapper's outer `+load` begins `~&  build-hash+hash` (hoon/lib/wrapper.hoon, vendored from
NockChain). Trinitite evaluates every dynamic hint's clue (src/nock.c op 11), and this `%slog` clue
renders the vase with `sell` (the type printer), unjetted. Measured on the box (QEMU, chain-5 app,
checkpoint at N=4): with the replay limits the load stops at the cell bound
(`abort=cells`, 128,000 cells, 440,489 ops); with no cell limit it crashes `%meme` (scratch exhausted)
after 1,395,186 cells and 4,689,346 ops. So today every header is rejected with `reason=load` and the
node falls back to replay from zero: safe, but it never boots from a checkpoint. A local experiment
that skips only the `%slog` clue (not in this branch) loads in 476 ops / 163 cells and the boot legs
pass (see the PR body). The fix is a decision outside this PR (kernel wrapper, lite hint policy, or
the load path).

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

## Boot (PR 1b)
Newest header whose sid loads, re-hashes to D and whose kernel-blake3 equals the booted pill's `g_jam_blake3`
(same bytes-as-read rule, so a pill re-jammed to different bytes does not match) → cue into the
versioned `+load` → replay entries after N. Fallback per row 212 (3). Never boot from an unverified image.
Implemented as above (PR 1b section), including its known blocker.

## Open questions
1. ~~Is sha256(jam(axis 6)) exactly `/state-hash` (row 199)?~~ **Answered** by the flag-on smoke run
   (`tests/checkpoint_axis.py`): the state is axis 27, not axis 6, and sha256(jam(axis 27)) with
   `jam_hoon_checked` equals the full node's `/state-hash` at N=2, 4, 6, 8, 10.
   **Settled on the lite node itself (1b)** by `tests/checkpoint_boot.py`: in the same QEMU boot, each
   writer digest D = sha256(jam(axis 27)) equals the lite node's own `/state-hash` peek (row 199,
   `i3_host_state_hash`) read right after the step that wrote it: N=4 `df590166…` (N=6 sequence, K=4),
   N=5 `d73a8797…` (N=6 sequence, K=5), N=4 `c47a0420…` (N=7 sequence, K=4). Equal in all three. The
   two are the same bytes hashed two ways: the host's `jam_hoon_checked` + sha256, and the kernel's
   `(shax (jam state))` through the lite `%jam`/`%shax` jets (row 211).
2. ~~Smoke run: D was identical at N=10/20/30 with R4 `[1 1]` events.~~ **Answered** by the same run: that
   digest covered axis 6. On axis 27 with events `1,1,1,1,0,1,0,1`, D moves exactly where `/state-hash`
   moves (3 distinct of 5: N=2; N=4=6; N=8=10).
3. Real cue bound: replace the 65,536 job counter with the 128k-cell cue bound check proper.
4. Does a checkpoint BLOB written during cold-store pressure need its own headroom rule (cold media full)?
5. Cadence on persist headroom ("or when headroom falls under one checkpoint plus margin") is not in 1a.
6. Cost of writing a checkpoint every K steps (time, cold bytes) is not measured; no board run.
