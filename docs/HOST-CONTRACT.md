# Trinitite host contract (IEC consumers)

**Status:** as built 2026-07-26 (industrial epic WP1–WP5)  
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
| `i2-timer-set` / `i2ts` | `[token delay-ns]` | I2 timer arm; cell token → fire `[%i2-timer token fired-at]`; bare atom owner → TICK path; ns→CNTVCT |
| `i2-timer-cancel` / `i2tc` | `token` | Cancel arm for token owner |
| `i2-service-request` / `i2sr` | service-req | UART TX of STRING payload (or bare atom) |
| `i2-service-cancel` / `i2sc` | token | D0 nop (one-shot UART) |

Long I2 names (`i2-timer-set`, …) are **indirect atoms** (BLAKE3-62 identity). Dispatch matches them by precomputed hash62 (not only `cord_to_cstr`), so recognition does not depend on atom-store residency after long slam sessions.
| `%irq` | noun | Enqueue as event |
| `%swapped` | version | Hot-swap applied |
| `%wdt` | — | Soft WDT fired |
| `%etx` / `%mtx` / `%ctx` | … | Net stubs (loopback optional) |

### 2.0a Slam product shapes (shrine)

| Shape | Product | Host action |
|-------|---------|-------------|
| I1 | `[effects [gate causes]]` | promote gate, enqueue causes, `DO-FX` effects |
| I2 hybrid | `[%commit [effects [gate causes]]]` | same after unwrap |
| I2 hybrid | `[%abort fault]` | **no** promote, **no** effects |

Device does **not** yet run Host ABI preflight (capacity/delay checks); offline `HostRunner` does. Known tags dispatch; unknown → `unkfx` once/session.

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
| Queue empty | **Idle poll:** `uart_rx_ready` else `tarm_poll` + soft WDT (no forever block on UART) |
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
| `nock_crash` (hard, default) | clear | **clear all** | last good `g_kernel` kept |
| `nock_crash` (soft, `SOFT!`) | clear | **keep** | last good kept |
| Budget / mid-eval wall | unchanged | **keep** | no product commit |
| Post-hoc `%tmrarm` after slam | — | — | product discarded |
| Heap / atom-store exhaustion | via `nock_crash` | per crash policy | last good kept |

Hard clear of tarms: after a structural crash, re-arm periods from Nock state on the next cold event rather than firing TICKs into a half-broken gate.

### 5.1 Noun heap / atom store ceilings

| Region | Range | On exhaust |
|--------|-------|------------|
| Cell heap (bump) | `HEAP_BASE` .. `HEAP_TOP` (≤ `ATOM_INDEX_BASE`) | `nock_crash("heap exhausted")` — **never** overruns into atom index |
| Atom data | `ATOM_DATA_BASE` .. `ATOM_DATA_TOP` | `nock_crash("atom store exhausted")` |
| Atom index | 64k open-address slots | `nock_crash("atom index full")` |

Heap is bump-only (refcounts free logical cells, not bump space). Long sessions that allocate unbounded products will eventually crash cleanly rather than corrupt the atom index (which previously manifested as I2 long-cord `unkfx` after `cord_to_cstr` store misses).

**Operational note:** a free-running E_CYCLE (re-arm every DT) keeps slamming; with DT=1ms a multi-second QEMU session can exhaust the 64MB heap after the useful cascade. Prefer longer DT for demos, or stop the cycle from the app, once Q1/effects are observed.

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
| Pill version | PILL v2 bytes 9–12 LE; `noun_pill_version` / `KVER@` | Host packaging / live version for hot-swap |
| Pill shape | byte 8; `KSHAPE` | 0 Arvo / 1 Shrine |
| IEC `kver` | Nock `kstate` in app state (`docs/I1.md`) | **Profile / kernel schema** version — independent of pill header |

**I1 host ABI (WP1–5):** no new **app-facing** effect tags required. Budget reuses `%timeout`. Overflow is host metrics/UART only. **No pill-version bump required** for consumers of the pure-Nock demo pill.

If a future change adds `%budget` / `%overflow` as effects, bump:

1. This contract + `docs/I1.md` §6  
2. Pill `--version` for new default pills (optional but recommended)  
3. IEC `kver` only if Nock state/event ISA changes  

---

## 8. Verify

```bash
make -C trinitite test          # 523+ goldens
bash trinitite/tests/kernel-boot.sh   # includes idle-timer path
# from 1499kernel:
bash tests/demo-poke.sh         # demo pill; UART OK
bash tests/app-poke.sh fanout
bash tests/field-demo.sh        # pipeline; UART Q1 (EP8)
```

Key sources: `src/kernel.c`, `src/kernel.h`, `src/nock.c`, `src/uart.c`, `src/memory.h`.

---

*Host industrial base + EP8 payload/field-demo contract. Prefer 1499kernel OUT product changes over host C unless print path is insufficient.*
