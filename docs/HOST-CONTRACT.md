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
| `%out` / `%blit` | atom | Print bytes to UART |
| `%timeout` | elapsed | Print `timeout`; used for **slam deadline and op-budget abort** |
| `%mmio` | `[addr val]` | 32-bit store |
| `%tmrarm` / `%tmrcan` | abs / — | Legacy **single** cooperative wall deadline (slam wall) |
| `%tset` / `%tcan` | `[id period]` / `id` | Multi-arm **IEC periods** (CNTVCT ticks; period 0 cancels) |
| `%irq` | noun | Enqueue as event |
| `%swapped` | version | Hot-swap applied |
| `%wdt` | — | Soft WDT fired |
| `%etx` / `%mtx` / `%ctx` | … | Net stubs (loopback optional) |

**Unknown tags:** not silent — `trace_rec(T_UFX)` + one-shot UART `unkfx` per session. Apps should not rely on unknown tags.

**Not an app effect today:** queue overflow is host-side (`overflow` UART + `T_OVF` + `QOVF@`). No `%overflow` tag in the effect list (avoids effect→queue re-entry storms). Documented for possible later ISA bump.

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

Hard clear of tarms: after a structural crash, re-arm periods from Nock state on the next cold event rather than firing TICKs into a half-broken gate.

---

## 6. Jets (pure; no MMIO)

C `hot_state` labels (via `%wild` on op9):

- Arithmetic: `%dec %add %sub %mul %lth %gth %lte %gte %div %mod`
- Structural: `%eq %lsh %rsh %con %dis %mix %cap %mas %peg`
- Lists: `%lent %flop %weld`

**KERNEL / `nock_eval`:** C only.  
**SKA `nock_op9_continue`:** Forth dictionary first, then C (arithmetic names may be shadowed in REPL).

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
bash tests/demo-poke.sh         # from 1499kernel; pure-Nock shrine pill
```

Key sources: `src/kernel.c`, `src/kernel.h`, `src/nock.c`, `src/uart.c`, `src/memory.h`.

---

*Host epic complete. Next product work: IEC data-driven stepper in Nock (1499kernel), not more host C unless a new gap appears.*
