# Trinitite host contract (IEC consumers)

**Status:** as built through canonical I2 Hybrid v1 Milestone 7 R&D baseline;
M6 remains a retained historical/recovery target
**Audience:** IEC 61499 Nock kernels / pills on this substrate  
**Normative product freeze:** `1499kernel/docs/I1.md` (do not reopen without user)  
**Epic log:** `1499kernel/docs/HOST-INDUSTRIAL.md`

Trinitite is a **time / I/O / Nock machine**. It has **no ECC**, **no FB network**, **no IEC type system**.

---

## 1. Product shape (Shrine)

```
event noun  →  slam gate  →  [effects [gate causes]]
                              │         │      └─ ENQL into host FIFO
                              │         └─ replace live gate
                              └─ DO-FX (effect dispatch)
```

| Item | Contract |
|------|----------|
| Shape | Shrine (`KSHAPE` / pill shape byte = 1) |
| Slam | `[9 2 [10 [6 [0 3]] [0 2]]]` — edit sample, call arm 2 |
| Causes | Append FIFO (`evq_enq_list`); same event ISA as UART events |
| Timer fire | Host → kernel: `[%ei id %TICK 0]` (slip: `next = now + period`) |

Arvo shape still exists; IEC uses **Shrine only**.

---

## 2. Effect tags (app → host)

Walk `[[tag data] rest]`. Known tags (cords, LSB-first ASCII):

| Tag | Data | Behaviour |
|-----|------|-----------|
| `%out` / `%blit` | atom | Print bytes to UART (see §2.1 payload policy) |
| `%timeout` | elapsed | Print `timeout`; used for **slam deadline and op-budget abort** |
| `%mmio` | `[addr val]` | 32-bit store |
| `%tmrarm` / `%tmrcan` | abs / — | Legacy **single** cooperative wall deadline (slam wall) |
| `%tset` / `%tcan` | `[id period]` / `id` | Multi-arm **IEC periods** (CNTVCT ticks; period 0 cancels) |
| `i2-timer-set` / `i2ts` | `[token delay-ns]` | One-shot I2 timer arm; full token → fire `[%i2-timer token fired-at]` then release the arm; bare atom owner is a test/legacy alias; ns→CNTVCT |
| `i2-timer-cancel` / `i2tc` | `token` | Cancel arm for token owner |
| `i2-service-request` / `i2sr` | service-req | Identity-authorized UART TX (`cap=1`) or fixed M6 digital bank (`cap=2`); exactly one pre-reserved completion (`status=0` success, `6` post-commit activation failure) |
| `i2-service-cancel` / `i2sc` | token | Strict unknown-cancel rejection: the current UART service completes synchronously and has no deferred driver entry to cancel |

Long I2 names (`i2-timer-set`, …) are **indirect atoms** (BLAKE3-62 identity). Dispatch matches them by precomputed hash62 (not only `cord_to_cstr`), so recognition does not depend on atom-store residency after long slam sessions.
| `%irq` | noun | Enqueue as event |
| `%swapped` | version | Hot-swap applied |
| `%wdt` | — | Soft WDT fired |
| `%etx` / `%mtx` / `%ctx` | … | Net stubs (loopback optional) |

### 2.0a Slam product shapes (shrine)

| Shape | Product | Host action |
|-------|---------|-------------|
| I1 | `[effects [gate causes]]` | promote gate, enqueue causes, `DO-FX` effects |
| I2 hybrid | `[%commit [effects [gate causes]]]` | preflight effects → persist gate/causes → dispatch |
| I2 hybrid | `[%abort fault]` | **no** promote, **no** effects |

**I2 transaction**: `prepare → validate → reserve → promote → activate`, with
abort permitted before promote. Preflight/reservation requires a proper effect
list and proper complete causes list; known I2 tags only; full lifecycle tokens
`[generation incarnation owner sequence]`; timer delay &gt; 0; timer count ≤ 16;
service shape + authorized exact cap/op/payload; deadline &gt; 0; and complete FIFO capacity for existing
backlog, every cause, and every instant service completion. Fail → keep gate,
FIFO, timer roots and effects unchanged; UART `preflight` once/session, no
effects. The queue's ordinary drop-newest policy is never applied to a
committed I2 cause list.

The device builds candidate gate/FIFO/timer-token roots and UART instant
completion FIFO events in the inactive semispace and publishes them once only after
those copies complete. Candidate copies use a status-returning 256-frame
depth-bounded copier. Over-depth, sharing-map, or semispace exhaustion rolls the
selector/pointer back to the old roots. The FIFO owns the exact reserved
completion noun whose status activation mutates. Promotion installs the
prepared timer roots and completions; post-publish activation is executed under
a no-allocation guard and only performs bounded UART emission and authorized
fixed-bank digital-output backend operations. It performs no allocation.
Generic asynchronous driver transactions are not claimed here.

### 2.0b M6 fixed digital-output bank

Host ABI/Deployment Schema `1.1` authorizes exactly cap `2`, op `1`, payload
`[P1_CMD [P2_CMD ALARM]]`, with three canonical BOOL atoms. ABI/schema `1.0`
does not authorize it. The PILL2 admission header additionally requires
capability profile byte `1` at offset 25 and the fixed 8-byte fingerprint
`26 48 2a ff fc 96 3f 59` at offsets 248–255. That fingerprint is
BLAKE3-64 over the domain `I2M6CAPv1\0` and canonical jam of the exact
package-request/deployment-grant pair. Baseline PILL2 keeps those bytes zero.
The target publishes this authorization only after the PILL gate and
RuntimeIdentity validate. The application supplies no pin, mask, or address.

The target-private mapping is active-high/safe-low:

| Logical channel | BCM GPIO |
|---|---:|
| `P1_CMD` | 17 |
| `P2_CMD` | 27 |
| `ALARM` | 22 |

These ordinary-output selections do not overlap the deployed UART0 GPIO14/15
or EMMC2/SD1 GPIO34–39 groups. GPIO22/27 do have unused SD alternate-function
choices in the BCM2711 table; selecting ordinary output is therefore part of
the fixed deployment contract, not a promise that arbitrary firmware pinmux
can coexist.

After promote, a changed bank writes `GPCLR0` for the full fixed mask, then
`GPSET0` for the desired-high subset. An identical enabled shadow is a no-op.
The production backend uses BCM2838 base `0xFE200000`; the fake backend has
bounded audit/failure injection. `%mmio` remains a retained legacy effect and
is not the M6 application API.

BCM2838 MMIO writes are ordered with an AArch64 `DSB SY` after each register
write. The backend can confirm only that the MMIO instruction completed; it
cannot diagnose electrical state or a device-side write failure. Injected
post-commit failure evidence therefore uses the deterministic fake backend.

Boot, pill refusal/install, checkpoint restore, crash recovery, and backend
failure request safe-low. Checkpoint restore leaves output inhibited: restored
logical high state or queued work cannot energize it. Only a later accepted
framed external process sample arms one reconciliation request. This is a
QEMU-functional register claim, not physical/electrical/safety evidence.

**Unknown tags:** not silent — `trace_rec(T_UFX)` + one-shot UART `unkfx` per session. Apps should not rely on unknown tags.

**Not an app effect today:** queue overflow is host-side (`overflow` UART + `T_OVF` + `QOVF@`). No `%overflow` tag in the effect list (avoids effect→queue re-entry storms). Documented for possible later ISA bump.

### 2.1 OUT / `%out` payload policy (EP8, 1499kernel)

IEC `OUT` SIFB product places an **atom** in `%out` data. Host prints that atom as raw bytes (no decoding).

| `di.Q` (after WITH/dwire) | `%out` data atom | Typical UART |
|---------------------------|------------------|--------------|
| missing / no Q | cord `OK` | `OK` |
| `0` | cord `Q0` | `Q0` |
| `1` | cord `Q1` | `Q1` |
| other atom | that atom | host-dependent |

**Law:** Python `out_payload_from_di` and pure `f_handle_out` dual-match.  
**Field demo:** `apps/pipeline` dwire `src.Q→out.Q` → cascade expects UART **`Q1`**.  
**Scripts:** `bash tests/field-demo.sh` or `bash tests/app-poke.sh pipeline`.

### 2.2 As-built cascade measurements (EP8 offline dual)

Cold `[%ei restart COLD]` chain (Python step + pure dual lockstep; inject TICK on `%tset`):

| App | Steps | `%tset` | `%out` | Notes |
|-----|------:|--------:|-------:|-------|
| demo | 5 | 1 | 1×`OK` | linear cascade |
| fanout | 6 | 1 | 2×`OK` | multi-sink OUT |
| pipeline | 6 | 1 | 1×`Q1` | dwire+WITH; UART field demo |

Multi-arm `%tset` → host enqueues `[%ei id %TICK 0]` while idle (**no second UART poke**). Queue cap **256** drop-newest; metrics `QLEN` `QHWM@` `QOVF@`. Slam budget default **1e6** ops/event.

---

## 3. Scheduling

| Situation | Behaviour |
|-----------|-----------|
| Queue non-empty | `DEQ` → slam |
| Queue empty | I2 consumes at most 32 framed-RX bytes, then polls timers + soft WDT; legacy I1 alone uses its old length frame |
| Timer due | Enqueue `[%ei id %TICK 0]` (independent arms, max 16) |
| Slam budget | Default **1e6** Nock ops per event (`slam_budget_set` / `BUDGET!`); mid-eval wall polls `%tmrarm` every 256 ops |
| Budget / wall fire | No product commit; **tarms kept**; emit `%timeout`; UART `budget` |

`%tmrarm` = slam wall-clock ceiling.  
`%tset` = IEC period (E_CYCLE). Do not conflate them.

---

## 4. Event queue

| Item | Value |
|------|-------|
| Cap | **256** (`EVQ_CAP`) |
| Overflow | **drop-newest** (refuse enqueue) |
| Metrics | `QLEN` `QCAP@` `QHWM@` `QOVF@`; `QMETR` resets counters |

---

## 5. Fault recovery

| Path | Queue / IRQ | Timers | Gate |
|------|-------------|--------|------|
| `nock_crash` (hard, default) | clear | **clear all** | last good `g_kernel` kept; M6 bank safe-low/inhibited |
| `nock_crash` (soft, `SOFT!`) | clear | **keep** | last good kept; M6 bank safe-low/inhibited |
| Budget / mid-eval wall | unchanged | **keep** | no product commit |
| Post-hoc `%tmrarm` after slam | — | — | product discarded |
| Heap / atom-store exhaustion | via `nock_crash` | per crash policy | last good kept |

Hard clear of tarms: after a structural crash, re-arm periods from Nock state on the next cold event rather than firing TICKs into a half-broken gate.

### 5.1 Noun heap / atom store ceilings

| Region | Range | On exhaust |
|--------|-------|------------|
| **Persist** cells | 2×16MB semispace within `HEAP_BASE`..`HEAP_PERSIST_TOP` | `nock_crash("heap exhausted")` |
| **Scratch** cells | `HEAP_SCRATCH_BASE` .. `HEAP_TOP` (32MB) | `nock_crash("scratch exhausted")` |
| Atom data | `ATOM_DATA_BASE` .. `ATOM_DATA_TOP` | `nock_crash("atom store exhausted")` |
| Atom index | 64k open-address slots | `nock_crash("atom index full")` |

Per event: slam product in **scratch**. On successful promote, **semispace flip + root copy**: allocate into the other persist half, deep-copy live roots (gate, queue, timer tokens, causes) while the previous half stays readable (shared battery cells), then abandon the old half. Slam formula is rebuilt after compact. Scratch is then reset. Bounds long-lived memory to one gate + queue + tokens.

### 5.2 Identity-bound checkpoint (power-cycle path)

Live roots can be **jammed into the cold store** (RAM region today; SD later):

```text
checkpoint ::= [%i2-ckpt 2 [152 runtime-identity-record] 1 gate queue tarms]
tarms      ::= * [id period remain-ticks token]
```

| Word / API | Role |
|------------|------|
| `CKPT!` / `checkpoint_save` | Capture live gate + queue + tarms → `cold_snap_save` |
| `CKLOAD` / `checkpoint_load` | Bounded-decode and fully validate snap → build candidate semispace → publish once |
| `CKAUTO!` *n* | Auto-save every *n* successful I2 commits (`0` = off) |
| `KGATE!` / `KGATE@` | Set/get live gate without entering `KERNEL` loop |

**Law:** checkpoint is a **host transaction boundary** image, not a trace of
every Nock intermediate. Its full RuntimeIdentity must exactly equal the
admitted PILL2 anchor. Queue/timer lists, capacities, event shapes, full unique
lifecycle tokens, and gate identity validate before candidate allocation.
Failure leaves all live roots and allocator selection unchanged.

**Working storage:** `COLD_BASE` 8MB RAM window (always).  
**NV path (QEMU):** after each snap, `cold_nv_flush()` writes the window to host file `cold.img` via ARM semihosting (`-semihosting`). Next boot reloads with:

```text
-device loader,file=cold.img,addr=0x07100000,force-raw=on
```

**Boot policy** (`BOOTPOL!` / `KERNEL`):

| Policy | Value | Behaviour |
|--------|------:|-----------|
| pill only | 0 | Load pill gate (default) |
| snap else pill | 1 | Accept exact snapshot, else record reason and install clean PILL2 roots |
| snap only | 2 | Accept exact snapshot, else install nothing and return to safe REPL |

UART marks: `boot: snap` plus identity/generation evidence, `boot: pill`,
`boot: snap reject <reason> -> pill`, `boot: no snap <reason>`, `boot: no pill`.

Cold v2 uses dual checksummed superblocks and append-only committed objects;
selection validates the full contiguous generation/object chain, log count,
and latest snapshot pointer. Divergent equal-generation superblocks and
nonblank corrupt/unsupported media fail closed and are never auto-formatted.
Exact byte layout, digest domains, diagnostic codes, PILL2, framed ingress,
bounded cue, and boot fallback rules are normative in
`1499kernel/docs/I2-M2-CONTRACT.md`.
Semihost `cold.img` is a lab/fault-injection transport only, not filesystem,
fsync/rename, physical-media, or power-cut durability evidence.

### 5.3 M3 bounded measurements and Pi 4 media surface

M3 adds one fixed, allocation-free `runtime_stats` block. It uses saturating
64-bit counters/ticks and fixed 64-bin log2 histograms; reset never allocates.
Queue residence uses a fixed 256-entry sidecar aligned with the FIFO and is
not part of event identity or checkpoint nouns. `RSTON`, `RSTOFF`, `RSTCLR`,
and `M3STAT` control and emit one stable `M3STAT1` summary. No timed event
emits telemetry.

The phase/counter schema, reset boundary, workload/tier rules, and claim
classes are normative in `1499kernel/docs/I2-M3-PROFILE.md`. QEMU counter
ticks are virtual timing and can earn only `qemu-functional`.
Target boot-load timing is captured before the harness can enable/reset stats;
one fixed pending value is consumed into the first reset record. Disabled
RAM/semihost media has no physical boot-load sample. Instrumentation overhead
uses equal-event `off/on/on/off` arms, and every bounded run must return exact
success even when aggregation is off.

Physical-media selection is compile-time only:

```text
COLD_MEDIA=ram       logical RAM window, no physical flush
COLD_MEDIA=semihost  QEMU lab file transport
COLD_MEDIA=fake      deterministic bounded fault adapter
COLD_MEDIA=rpi4-sd   Pi 4B BCM2711 EMMC2 PIO target
```

The target-private adapter maps the two logical M2 superblocks to distinct
512-byte physical sectors behind one versioned raw-extent descriptor. It
checks descriptor, presence, read-only state, capacity, translated range,
deadline, and non-reentrancy. Physical append ordering adds barriers after the
object commit and inactive superblock. A submitted uncertain write is not
retried. Any controller/read or write fault latches reset-required until an
explicit session reset, which also resets the target-private controller/card
session. The barrier proves only controller/card ready completion, not
power-cut durability. RuntimeIdentity, checkpoint v2, logical cold v2, boot
selection, and fail-closed format policy are unchanged.

The fake-media full gate runs real `cold_snap_save`, remount, production
selection, and decode under every declared injected fault at every physical
transfer boundary. The fake-only build exports its bounded smoke and
exhaustive matrix test words only to the dedicated media target; they are not
part of the production header or normal Forth vocabulary. Fake evidence is not
physical-controller or power-cut evidence.

No Pi 4/card run or destructive power-cut campaign is part of the repository
tests. Therefore `target-timing`, `media-controller`, and
`physical-power-cut` remain unproven until separately retained hardware
evidence satisfies the M3 profile.

---

## 6. Jets (pure; no MMIO)

C `hot_state` labels (via `%wild` on op9):

- Arithmetic: `%dec %add %sub %mul %lth %gth %lte %gte %div %mod`
- Structural: `%eq %lsh %rsh %con %dis %mix %cap %mas %peg`
- Lists: `%lent %flop %weld`

**KERNEL / `nock_eval`:** C only.  
**SKA `nock_op9_continue`:** Forth dictionary first, then C (arithmetic names may be shadowed in REPL).

### Jet pack vs Hoon twin (Epic #5 WP2)

Existing pure jets are **sufficient** for the shipped closed pure-Nock IEC lowerer (Hoon twin path): demo cascade ≈ 1.8e3 mini_nock entries/slam vs **1e6** default budget (~550× headroom). See `docs/hoon/JET-BUDGET.md`. No MMIO jets. Soft/mold acceleration not added; prefer soft-free Hoon/Nock.

---

## 7. Versioning

| Knob | Where | Meaning |
|------|-------|---------|
| I1 pill | legacy 16-byte PILL v2 header | Frozen I1 compatibility path only |
| I2 pill | PILL2 256-byte header + RuntimeIdentity | Strict I2 admission/restart anchor |
| IEC `kver` | Nock `kstate` in app state (`docs/I1.md`) | **Profile / kernel schema** version — independent of pill header |

**I1 host ABI (WP1–5):** no new **app-facing** effect tags required. Budget reuses `%timeout`. Overflow is host metrics/UART only. **No pill-version bump required** for consumers of the pure-Nock demo pill.

If a future change adds `%budget` / `%overflow` as effects, bump:

1. This contract + `docs/I1.md` §6  
2. Pill `--version` for new default pills (optional but recommended)  
3. IEC `kver` only if Nock state/event ISA changes  

---

## 8. Verify

```bash
make -C trinitite test          # 544+ goldens
make -C trinitite test-media-fake
make -C trinitite test-media-rpi4-build
bash trinitite/tests/kernel-boot.sh   # includes idle-timer path
# from 1499kernel:
bash tests/demo-poke.sh         # demo pill; UART OK
bash tests/app-poke.sh fanout
bash tests/field-demo.sh        # pipeline; UART Q1 (EP8)
```

Key sources: `src/kernel.c`, `src/kernel.h`, `src/nock.c`, `src/uart.c`, `src/memory.h`.

---

*Host industrial base + EP8 payload/field-demo contract. Prefer 1499kernel OUT product changes over host C unless print path is insufficient.*

## M7 ABI boundary — bounded target implementation

The M7 host ABI is `(1,2)` and is selected by the exact M7 RuntimeIdentity.
Trinitite exposes a bounded target MANAGER seam in `m7_supervisor.c`:
`m7_manager_init` implements QI/QO initialization, and
`m7_manager_request_bytes` accepts only canonical jammed OBJECT bytes up to
512 bytes with the exact M7 cue/depth/cell ceilings. A one-entry mailbox is
accepted by receipt and evaluated by the pure-Nock manager formula at
`m7_scheduler_boundary`, after every complete terminal application
transaction, including abort/refusal cleanup. `M7REQB`
and the related `M7*` Forth words are trusted-lab diagnostics; application
events cannot forge these forms.

The framed application receiver is a separate origin. It is admitted only in
the exact M7 RuntimeIdentity's RUNNING mode and rejects application-origin
`i2-lifecycle`/`i2-control` nouns; M6 is not subjected to an uninitialised-M7
default-deny fence. One closed supervisor lifecycle slot, rather than the
drop-newest application FIFO, is the sole lifecycle provenance.

The Nock formula owns command shape, object validity, IEC status, and the
closed lifecycle intent. The host executes only that fixed intent vocabulary,
checks generation+incarnation on timer/service/cause dequeue and again before
activation, and performs bounded safe-low/deployment effects. A standard STOP
has one attempted `E_RESTART.STOP`; a failed or emergency path records
non-delivery and returns `SYSTEM_TERMINATION` if the backend clear did not
complete; it never reports safe-low success in that case.
`TRI_RESOURCE.FORCE_STOP/RESET` and
`TRI_DEPLOY` are vendor-namespaced, not IEC FB-level KILL/RESET or
CREATE/DELETE.

The M7 application FIFO is 256 entries; management is an independent
one-entry priority mailbox. STOP's exact lifecycle slot is selected ahead of
that FIFO, including at depth 256; its promotion retires the application
backlog rather than copying it before the STOP cleanup. The dedicated M7
source explicitly supplies COLD/WARM/STOP receiver edges; the lowerer does not
clone COLD. The slot drains the bounded E_RESTART receiver-cause chain (root
plus at most two causes) and refuses before selecting transaction four, so
`M7 LIFECYCLE COMMIT` is emitted only after both the lifecycle root and its
actual destination causes commit; `M7 LIFECYCLE FAIL` is the audited
non-delivery marker. `M7LROOT@`/`M7LDEST@` expose those counters only to the
trusted-lab evidence bridge. `M7CFAIL` and `M7QFILL` are trusted-lab QEMU
fault/priority witnesses, not services or application ingress. The target
RuntimeIdentity work admits M7
host/deployment `(1,2)` and M7 digital-output profile 2 using the fixed
`I2M7CAPv1` selector. PILL2, framed ingress, checkpoint, and cold-store
container layouts remain unchanged. Candidate PILL bytes occupy the fixed
volatile stage at `PILL_SCRATCH_BASE` until `SEAL`; activation stores the full
candidate as a cold blob and records its full digest plus identity in the M7
supervisor snapshot. It publishes RAM after confirmed cold selection; the
explicit unknown-durability exception publishes only the prepared safe/IDLE
candidate. With active fake or `rpi4-sd` media, before physically verified
`COLD_DEPLOY_COMMITTED`, the target reads the full selected object chain and
selecting superblock back from physical media, validates every object/digest
and the superblock, and compares the selected superblock with the planned
bytes; the RAM window is not the durability witness. Default RAM and
semihost/QEMU media are inactive, so their `COMMITTED` is volatile logical
acceptance rather than physical-media proof. The 8-byte-aligned append can
share a retained physical sector, so any active-media deployment write,
barrier, or readback error is `TRI_DEPLOY_DURABILITY_UNKNOWN`: the
assignment-only candidate is published safe/IDLE, but START, checkpoint, and
new deployment are rejected until reboot/remount. Remount may find the old
pair, new pair, or no valid pair; the target makes no old-or-new recovery
claim. The target prebuilds all
fallible RAM roots before selection and makes
the final gate/supervisor/identity/output-inhibition publication
assignment-only. It preflights the complete jammed supervisor snapshot against
65,536 bytes and every cold-store jam against the 131,072-byte writer before
calling it. See the
parent `docs/I2-M7-CONTRACT.md` and `docs/I2-M7-VERDICT.md` for the exact
profile and nonclaims.
