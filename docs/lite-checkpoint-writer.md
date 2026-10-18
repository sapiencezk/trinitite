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

### Former blocker (1b), resolved by row 219 (1499kernel #258)
The wrapper's outer `+load` began `~&  build-hash+hash` (hoon/lib/wrapper.hoon, vendored from
NockChain). Trinitite evaluates every dynamic hint's clue (src/nock.c op 11), and that `%slog` clue
rendered the vase with `sell` (the type printer), unjetted. With the pre-#258 kernel (box, QEMU, chain-5
app, checkpoint at N=4) the load stopped at the cell bound (`abort=cells`, 128,000 cells, 440,489 ops),
and with no cell limit it crashed `%meme` after 1,395,186 cells and 4,689,346 ops, so every header was
rejected with `reason=load` and the node replayed from zero. Row 219 (approved by Guillaume) removes the
trace from the kernel's `+load`; it lands with #258's re-pin (bff56583). Trinitite's `src/nock.c` is
unchanged. Measured with that kernel jam (same app, QEMU): `I3H ckpt boot load ... abort=none
nock_ops_used=475 nock_cells_used=163 nock_eval_stack_peak=19` at every checkpoint N tried (2, 4, 5),
and `tests/checkpoint_boot.py` passes against it. With the landing kernel jam (1499kernel main 3d100787):
`abort=none nock_ops_used=481 nock_cells_used=166 nock_eval_stack_peak=19`.

## Rotation (1c: see the PR 1c section)
- Amended row 212 (2) (1499kernel #263): the node keeps the last verified checkpoint plus every entry after
  it, and the previous checkpoint until the next one verifies. Entries before the kept checkpoint are dropped.
  There is no time-based retention floor on the node: long-term history lives in the SD recorder ring (a
  fixed byte budget, oldest segment overwritten first) and upstream.
- The base moves only after the newest checkpoint verified. If a checkpoint cannot be written (skip), the
  base does not move, and the 141/198/213 stop applies when the cold store is full.

## SD log and compaction (base and ring in 1c; compaction 1d)
- Today `cold_log` is an append-only chain in the same cold image as blobs; there is no way to drop a prefix.
- Plan: a log "base" field in the superblock (first retained entry index + the checkpoint header id it
  follows). Rotation = one superblock write moving the base; replay starts at base. Compaction = copy kept
  blobs/entries into the other half of the media (two-region, A/B) and flip the superblock; the old region is
  only reused after the flip verifies. rpi4-sd per-step append cost and torn-write behaviour: not measured.
- Compaction also reclaims persist-reserve growth (row 213's lifetime limit) because replay then starts
  at the checkpoint, so the job sum restarts there.

## PR 1c: running log + SD recorder ring (branch `feat/lite-recorder-ring`)
Amended row 212 (2), (3) and (4) (1499kernel main, amendment 5091bb19). Build with
`I3_CHECKPOINT_EVERY=K I3_LITE_LOG=1`; off by default. Flag-off images and 1b flag-on images
(`I3_CHECKPOINT_EVERY` without `I3_LITE_LOG`) are byte-identical to the base
(`tests/checkpoint_flag_off.sh 8d287abd 6613d3b6`).

**Running log.** The 32 reserved superblock bytes carry a log base
`{index B, off, job_sum, check}` (`check` = first 8 bytes of blake3(superblock[0..64] ‖ base[0..24]),
never 0; all zero = no base, so a flag-off image reads unchanged). Entry B+1 is the first LOG object at
or after `off`. When checkpoint N verifies (`I3H ckpt ok`), the previous verified checkpoint P becomes the
base: a small `[%i3-base P N]` BLOB is appended and its superblock carries base = P, with a row 213
job sum in `job_sum` (row 221 (7): the jobs of entries P+1..N; audit only, boot does not load it). So the node keeps checkpoint N, the previous checkpoint P until
the next one verifies, and every entry after P. Entries 1..P are dropped from replay and from
`log_len`. Boot looks only at checkpoints with n ≥ B and replays from `off`. If no checkpoint ≥ B is valid
and B > 0, the node stops: `I3H ckpt boot none ... fallback=stop base=B`, `I3H stop reason=rotated`
(row 212 (3), row 141 stop). A crash after a checkpoint is written but before it verifies leaves the base at
the earlier checkpoint, so boot falls back to it. If a checkpoint is skipped, the base does not move
(row 212 (4)).

*Base move faults.* A base move that fails before any sector is sent (for example a timeout on the
read-modify-write read) logs `I3H log base fail event=P ckpt=N`, drops nothing and keeps the prefix; the
next verified checkpoint moves the base. A fault after a sector of the move was sent sets the cold session's
reset-required state, so the node stops under the existing cold rule (rows 141/198/200), as for any cold
write. This is intended: the cold store's state on the media is then unknown. `tests/recorder_ring.py`
`rebase-fault` covers only the first case (a fault before anything is written).

*Based images and non-LITE images.* A cold image with a log base does not boot on a flag-off or 1b image:
their `super_validate` (`src/cold.c`, the `#else` arm of the reserved-bytes check) requires the reserved
superblock bytes to be zero and refuses the superblock (SUPERBLOCK). This is not fixed in 1c. That check is
the flag-off image's own code: accepting a base there changes the bytes of every flag-off and 1b image,
which must stay identical to the base, and images already built would refuse it anyway. Going back from a
LITE image needs a fresh cold store (or compaction later).

The drop is logical only. The dropped bytes stay in the 8 MiB cold chain until compaction (A/B media,
1d, not in this PR) reclaims them, so the cold store still fills and the row 141/198/200 stop applies.

**Recorder ring** (`src/i3_ring.c`). This is a fixed-size byte ring: `I3_RING_BYTES`, default 64 MiB, a
multiple of 512, at most 128 MiB. Its RAM window is at DRAM + 0x30000000 (`src/memory.h` checks it against
the heap, atom store, cold window, pill/plan/app slots and MMIO). Media: `rpi4-sd` writes through to its own
extent at LBA `COLD_MEDIA_START_LBA + 32768`, after the cold extent (`src/cold_media.h` checks at build time
that the two do not overlap, and at the first ring access that the card holds the whole extent); `fake` does
the same on the fake backend (RAM, for the fault tests); semihost writes `build/ring.img`; ram keeps it in RAM.
The plan names `cold_media_rpi4_sd.c` for the ring media code. It lives in `src/cold_media.c` instead
(`cold_media_ring_load` / `cold_media_ring_write`), because the session, owner lock and capacity live there,
and it serves both the rpi4-sd and fake backends; `cold_media_rpi4_sd.c` is unchanged.
It has two 128 B header slots (gen, head, tail, seqs, wraps, evicted, blake3) and 64 B records: genesis
(kernel blake3), ckpt (D ‖ kernel blake3 ‖ job_sum ‖ ++jam state), input (log entry jam) and wrap. A ring
checkpoint is written every `I3_RING_EVERY` events (default 2,000; must be a multiple of K) and reuses the
verified running checkpoint. When the ring is full, the oldest checkpoint and the inputs after it are
evicted together.

*Faults.* A ring media fault (boot load, write or barrier) is logged (`I3H ring media fault op=... status=...`)
and turns the ring off for the rest of the boot (`I3H ring off reason=media`; later ring checkpoints log
`I3H ring skip ... reason=off`). The ring keeps its own reset flag in `cold_media.c`: it never sets the cold
session's `g_reset_required`, so a ring fault never stops the cold log or the node. The boot load gets a
fresh 5 s deadline per 256 KiB chunk and stops after 60 s in total (then the ring is off for that boot); it
logs its time (`I3H ring load bytes=... ticks=... freq=...`).

*Torn writes.* Each change writes whole sectors from the window. Per record: free space (evict, wrap), and if
the tail or head moved: wrap marker, barrier, header commit; then the record, barrier, header commit. Each
commit goes to the other header slot. The writer never writes into the sector that holds the oldest live
record. The first sector of a new record can still hold the end of the last committed record, so a torn
write there can damage that record. At boot the node opens the newest valid header slot whose chain is
intact (`status=ok`), else the other slot (`status=torn-older`), else the longest valid prefix from the tail
of either slot, committed over the broken slot (`status=torn-prefix`). It never formats after a chain check
fails; with no valid prefix the ring stays off and the media is left as it is (`status=corrupt`).

*Foreign data.* With no valid header slot for this ring size the node formats only:
- an extent that is all zero (`status=fresh`), or
- an extent with a whole header of its own (magic, version and checksum right) for another ring size
  (`status=reformat`; it logs `I3H ring reformat old_bytes=X new_bytes=Y` and the generation continues
  above the highest one on the media).

Its own magic and version with no header to trust (bad checksums), or valid headers with no valid record
prefix, is `status=corrupt`: ring off, media left as it is, and once per boot `I3H ring off reason=corrupt`
plus an operator hint (`I3H ring hint: ...`). Anything else is refused: `I3H ring boot status=foreign`, ring
off, nothing written. The on-media layout descriptor does not name the ring extent; that needs a new
descriptor version, which current images refuse, so it is deferred. The build-time overlap check, the
capacity check and these refusals are the guard.

**GAP (Steward's ruling, row 212 (2)).** An all-zero range that belongs to another partition is still
formatted as a fresh ring (`src/cold_media.h` ring layout comment, `src/i3_ring.c` `status=fresh`). Ruling:
no rpi4-sd image with `I3_LITE_LOG` on is deployed until a layout descriptor version names the ring extent,
and the board run uses a card whose ring area was zeroed on purpose. Cards that read erased blocks as 0xFF
show `status=foreign` (the ring stays off) until the ring area is zeroed.

**Off-device exact replay.** `tools/ring_image.py show build/ring.img` lists segments. It opens the ring as
the node does: the newest intact slot, else the older slot, else the longest valid prefix from the tail of
either slot (`"prefix": true`); no valid prefix is an error (the node's `status=corrupt`).
`tools/ring_image.py cold build/ring.img out.img oldest` builds a cold image (checkpoint + inputs, base = N,
base job_sum from the ring checkpoint) that the same flag-on lite image boots.

On the full node: `tests/ring_full_replay.py RING FULL_NODE TARGET --zero CAUSES.json` writes a full-node host
snapshot (I3SNAP, `full-node run --ephemeral --snapshot`) from the ring's oldest checkpoint, boots the full
node from it, poke-jams the ring's inputs and reads `/state-hash` after each one. With `--zero` it also runs
the same causes from zero and asserts every step. No full-node or kernel change is needed.
`tests/recorder_ring.py` leg `fullreplay` runs it for the N=6, N=7 and wrap4 rings.

**Measured** (QEMU, probe events, K = ring cadence = 2, 16 KiB ring):
- ring ckpt record 5,960-5,976 B (8 B more than before for job_sum); input record 96 B per event;
- kept log bytes after a rebase 6,648-6,656 B (one checkpoint + 2 entries + marker).

At K=2000 that gives ≈ 5,976 + 2,000 × 96 ≈ 198 KB per segment for these events, so ≈ 339 segments fit in 64 MiB.
Real input sizes vary.

**Not measured:** SD append time, torn-write behaviour of real cards, SD wear, the rpi4 ring boot load time
(it reads the whole ring; the node now logs it), and the extra jam per step for ring inputs.

## Row 221 (row 212 (c)): compaction (branch `feat/lite-compaction`)
Compaction is host memory management. It frees the persist heap and the atom store after a verified
checkpoint, so a lite node can run for an unbounded time. It uses the row 212 flags: it is on when
`I3_HOST`, `I3_CHECKPOINT_EVERY` > 0 and `I3_LITE_LOG=1` are all set (`I3_COMPACT` in `src/memory.h`),
and off by default. Flag-off images are byte-identical (`tests/checkpoint_flag_off.sh`).

- **Code region.** 12 MiB at DRAM base + 0x0D000000. At boot the host builds the pill's kernel (cue),
  the poke and peek formulas and the kick into it, once. Build-time checks in `memory.h` keep it clear
  of the cue rub scratch, the cue cache, .bss, the pill, the ring window, MMIO and the 4 GiB pointer
  limit. If the build overflows, boot halts with `I3H terminal=code-region`. Boot logs
  `I3H code region bytes= cells= size=` and `I3H atom prefix bytes= atoms= persist_cells=`. Nothing
  writes to the region after the build, and the persist copier keeps its cells as they are.
- **When.** Only a running node compacts: after `I3H ckpt ok event=N` and after the step's effects
  are handed off (`i3_host_handoff`, called by the driver after the scratch reset). Effects are not a
  root. Replay, a stopped node and a skipped checkpoint never compact.
- **Flip.** A transaction on the other persist half: copy the core's sample, install it, check that
  axis 27 hashes to D, then commit. Any failure aborts. The node keeps the old half and logs
  `I3H compact skip event=N reason=code|root|copy|hash`. After the commit the
  atom store rebuild can still be skipped (`reason=rebuild-room|rebuild-walk|rebuild-index`); the node then
  runs on the new half with the store as it was.
- **Atom store.** After the commit, the host walks the state, the poke and peek formulas, the
  fast-hint registry and `g_mean` (`nock_host_roots`). The walk stops at code-region cells. The atoms
  from the boot cue stay as a fixed prefix. Live atoms slide down in allocation order and the index is
  rebuilt in place. Checks: the digest of the kept records before the slide equals the digest of the
  store after it, and a second walk re-hashes every live atom to its name (`missing=0`). The result is
  logged as `I3H compact walk ...` and `I3H compact ok event=N ...` with the tick counts.
- **Reserve, row 221 (7).** The job sum counts from the log base. The rebase writes the jobs of
  entries P+1..N into the base record (audit only), and the boot replay starts its sum at 0 at the
  base. It logs `I3H replay job_sum=N`.
- **Test knobs** (test builds, need `I3_LITE_LOG=1`): `I3_CKPT_TEST=cmpbefore|cmpcopy|cmpafter|cmpflip|
  cmprebuild` stop dead at that point (`I3H compact test crash event=N at=...`); `cmpskip` fails the
  copy so the transaction aborts. All use `I3_CKPT_TEST_FROM`.
- **Tests.** `tests/compaction.py` (running, the five crash points, skip). `tests/checkpoint_legs.py
  replay --reserve|--reserve3` with `CKPT_LEGS_EXTRA="I3_LITE_LOG=1"`: no persist stop comes, and the
  pinned counts are in `RESERVE_ON`.
- **Gap: kernel replacement.** The code region is built once from the pill. A new kernel needs a new
  image and a reboot, and then every kept checkpoint names the old kernel and is rejected. No path
  seeded from upstream exists yet.
- **IEC 61499.** Resources keep their operational state (Part 1 4.8; 6.3.3, Figure 24, Table 9), and no
  E_RESTART COLD or WARM fires (Part 1 6.3.2; Annex A, Table A.1). This is not a conformance claim.

## Boot (PR 1b)
Newest header whose sid loads, re-hashes to D and whose kernel-blake3 equals the booted pill's `g_jam_blake3`
(same bytes-as-read rule, so a pill re-jammed to different bytes does not match) → cue into the
versioned `+load` → replay entries after N. Fallback per row 212 (3). Never boot from an unverified image.
Implemented as above (PR 1b section); the `+load` blocker is resolved by row 219 (1499kernel #258).

## Open questions
1. ~~Is sha256(jam(axis 6)) exactly `/state-hash` (row 199)?~~ **Answered** by the flag-on smoke run
   (`tests/checkpoint_axis.py`): the state is axis 27, not axis 6, and sha256(jam(axis 27)) with
   `jam_hoon_checked` equals the full node's `/state-hash` at N=2, 4, 6, 8, 10.
   **Settled on the lite node itself (1b)** by `tests/checkpoint_boot.py`: in the same QEMU boot, each
   writer digest D = sha256(jam(axis 27)) equals the lite node's own `/state-hash` peek (row 199,
   `i3_host_state_hash`) read right after the step that wrote it: N=4 `df590166…` (N=6 sequence, K=4),
   N=5 `d73a8797…` (N=6 sequence, K=5), N=4 `c47a0420…` (N=7 sequence, K=4). Equal in all three
   (pre-#258 kernel; with the #258 kernel jam at bff56583: `9f64c2d2…`, `71fb60e5…`, `c5225f7a…`, equal
   again; with the landing kernel jam, 1499kernel main 3d100787: `f5764f6f…`, `0c36f958…`, `8eb95aa4…`,
   equal again). The
   two are the same bytes hashed two ways: the host's `jam_hoon_checked` + sha256, and the kernel's
   `(shax (jam state))` through the lite `%jam`/`%shax` jets (row 211).
2. ~~Smoke run: D was identical at N=10/20/30 with R4 `[1 1]` events.~~ **Answered** by the same run: that
   digest covered axis 6. On axis 27 with events `1,1,1,1,0,1,0,1`, D moves exactly where `/state-hash`
   moves (3 distinct of 5: N=2; N=4=6; N=8=10).
3. Real cue bound: replace the 65,536 job counter with the 128k-cell cue bound check proper.
4. Does a checkpoint BLOB written during cold-store pressure need its own headroom rule (cold media full)?
5. Cadence on persist headroom ("or when headroom falls under one checkpoint plus margin") is not in 1a.
6. Cost of writing a checkpoint every K steps (time, cold bytes) is not measured; no board run.
