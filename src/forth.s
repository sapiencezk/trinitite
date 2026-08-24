// src/forth.s
// Trinitite Forth Kernel — AArch64 bare metal
// Phase 1: Inner interpreter + primitives + QUIT loop
//
// ── Register assignments ─────────────────────────────────────────────────────
//   x27  IP  — Instruction Pointer: next cell to fetch from word list
//   x26  DSP — Data Stack Pointer: points TO top item, grows DOWN
//   x25  RSP — Return Stack Pointer: points TO top item, grows DOWN
//   x24  W   — Working register: current dictionary entry address
//
//   x0-x18   — scratch, any word may clobber
//   x19-x23  — reserved for noun heap pointers (Phase 2+)
//   x24-x27  — RESERVED, never clobber
//
// Stack convention: DSP/RSP point TO the top item.
//   Push: str x0, [DSP, #-8]!     (pre-decrement then store)
//   Pop:  ldr x0, [DSP], #8       (load then post-increment)
//
// ── Dictionary entry layout ──────────────────────────────────────────────────
//   offset  0 : link      [8 bytes] — address of previous entry (0 = end)
//   offset  8 : flags|len [8 bytes] — low byte = name length, high bits = flags
//   offset 16 : name      [8 bytes] — ASCII name, zero-padded to 8 bytes
//   offset 24 : codeword  [8 bytes] — pointer to machine code
//   offset 32 : body               — colon def: list of entry addrs
//                                    DOCON: the constant value
//                                    DOVAR: the variable storage cell
//
// ── Memory map (must match memory.h) ─────────────────────────────────────────

#if defined(TRINITITE_PLATFORM_QEMU_VIRT)
.set DICT_BASE,    0x40100000          /* must match FORTH_BASE in memory.h */
.set DSTACK_TOP,   0x40480000
.set RSTACK_TOP,   0x40490000
.set TIB_BASE,     0x400FF000          /* just below FORTH_BASE */
#else
.set DICT_BASE,    0x00100000          /* must match FORTH_BASE in memory.h */
.set DSTACK_TOP,   0x00480000
.set RSTACK_TOP,   0x00490000
.set TIB_BASE,     0x000FF000          /* just below FORTH_BASE */
#endif
.set TIB_SIZE,     256

// ── UART (PL011) ─────────────────────────────────────────────────────────────
// The named build-time platform selects the concrete PL011 console.
#if defined(TRINITITE_PLATFORM_QEMU_VIRT)
.set UART_DR,   0x09000000
.set UART_FR,   0x09000018
#else
.set UART_DR,   0xFE201000
.set UART_FR,   0xFE201018
#endif

// ── Register aliases ─────────────────────────────────────────────────────────

IP  .req x27
DSP .req x26
RSP .req x25
W   .req x24

// ── Flag bits ────────────────────────────────────────────────────────────────

.set F_IMMEDIATE, 0x80
.set F_HIDDEN,    0x40

// ═════════════════════════════════════════════════════════════════════════════
// MACROS
// ═════════════════════════════════════════════════════════════════════════════

// NEXT — fetch next word, advance IP, dispatch via codeword.
.macro NEXT
    ldr     W, [IP], #8         // W = *IP (entry addr),  IP += 8
    ldr     x0, [W, #24]        // x0 = codeword at entry+24
    br      x0                  // jump to codeword
.endm

// Link chain — updated by each defword.
.set link, 0

// defword — emit the dictionary header only.
.macro defword name, len, label, flags
    .section .rodata
    .balign 8
    .global word_\label
word_\label:
    .quad   link
    .set    link, word_\label
    .quad   ((\flags) << 8) | (\len)
    .ascii  "\name"
    .balign 8, 0
    // codeword at +24, body at +32
.endm

// defcode — primitive; codeword points to immediately following asm.
.macro defcode name, len, label, flags
    defword "\name", \len, \label, \flags
    .quad   code_\label
    .text
    .balign 4
code_\label:
.endm

// defvar — variable; codeword = DOVAR, body = one storage cell.
.macro defvar name, len, label, flags, initial=0
    defword "\name", \len, \label, \flags
    .quad   DOVAR
    .quad   \initial
.endm

// defconst — constant; codeword = DOCON, body = value.
.macro defconst name, len, label, flags, value
    defword "\name", \len, \label, \flags
    .quad   DOCON
    .quad   \value
.endm

// ═════════════════════════════════════════════════════════════════════════════
// INNER INTERPRETER
// ═════════════════════════════════════════════════════════════════════════════

    .text
    .balign 4

// DOCOL — enter a colon definition.
// W holds the entry address. Push IP, set IP = body (W+32), dispatch.
    .global DOCOL
DOCOL:
    str     IP, [RSP, #-8]!
    add     IP, W, #32
    NEXT

// DOCON — push constant value stored at W+32.
    .global DOCON
DOCON:
    ldr     x0, [W, #32]
    str     x0, [DSP, #-8]!
    NEXT

// DOVAR — push address of storage cell at W+32.
    .global DOVAR
DOVAR:
    add     x0, W, #32
    str     x0, [DSP, #-8]!
    NEXT

// EXIT — leave a colon definition. Pop saved IP, resume caller.
defcode "EXIT", 4, exit, 0
    ldr     IP, [RSP], #8
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// STACK PRIMITIVES
// ═════════════════════════════════════════════════════════════════════════════

// DROP ( a -- )
defcode "DROP", 4, drop, 0
    ldr     x0, [DSP], #8
    NEXT

// DUP ( a -- a a )
defcode "DUP", 3, dup, 0
    ldr     x0, [DSP]
    str     x0, [DSP, #-8]!
    NEXT

// SWAP ( a b -- b a )
defcode "SWAP", 4, swap, 0
    ldr     x0, [DSP]
    ldr     x1, [DSP, #8]
    str     x0, [DSP, #8]
    str     x1, [DSP]
    NEXT

// OVER ( a b -- a b a )
defcode "OVER", 4, over, 0
    ldr     x0, [DSP, #8]
    str     x0, [DSP, #-8]!
    NEXT

// ROT ( a b c -- b c a )
// Before: [DSP]=c [DSP+8]=b [DSP+16]=a   After: [DSP]=a [DSP+8]=c [DSP+16]=b
defcode "ROT", 3, rot, 0
    ldr     x0, [DSP]           // x0 = c (top)
    ldr     x1, [DSP, #8]       // x1 = b
    ldr     x2, [DSP, #16]      // x2 = a (deepest)
    str     x2, [DSP]           // a → new top
    str     x0, [DSP, #8]       // c → new middle
    str     x1, [DSP, #16]      // b → new deep
    NEXT

// -ROT ( a b c -- c a b )
// Before: [DSP]=c [DSP+8]=b [DSP+16]=a   After: [DSP]=b [DSP+8]=a [DSP+16]=c
defcode "-ROT", 4, nrot, 0
    ldr     x0, [DSP]           // x0 = c (top)
    ldr     x1, [DSP, #8]       // x1 = b
    ldr     x2, [DSP, #16]      // x2 = a (deepest)
    str     x1, [DSP]           // b → new top
    str     x2, [DSP, #8]       // a → new middle
    str     x0, [DSP, #16]      // c → new deep
    NEXT

// NIP ( a b -- b )
defcode "NIP", 3, nip, 0
    ldr     x0, [DSP], #8
    str     x0, [DSP]
    NEXT

// 2DUP ( a b -- a b a b )
defcode "2DUP", 4, twodup, 0
    ldr     x0, [DSP]
    ldr     x1, [DSP, #8]
    sub     DSP, DSP, #16
    str     x0, [DSP]
    str     x1, [DSP, #8]
    NEXT

// 2DROP ( a b -- )
defcode "2DRP", 4, twodrop, 0
    add     DSP, DSP, #16
    NEXT

// ?DUP ( a -- a a | 0 )
defcode "?DUP", 4, qdup, 0
    ldr     x0, [DSP]
    cbz     x0, 1f
    str     x0, [DSP, #-8]!
1:  NEXT

// DEPTH ( -- n )
defcode "DPTH", 4, depth, 0
    ldr     x0, =DSTACK_TOP
    sub     x0, x0, DSP
    lsr     x0, x0, #3
    str     x0, [DSP, #-8]!
    NEXT

// EXECUTE ( xt -- )  execute execution token (entry address) on top of stack
// The dispatched word sees IP pointing to the word after EXECUTE in the
// current definition, so its NEXT resumes the calling colon word normally.
defcode "EXECUTE", 7, execute_word, 0
    ldr     W, [DSP], #8            // W = execution token (dict entry address)
    ldr     x0, [W, #24]            // load codeword from entry+24
    br      x0                      // dispatch (no NEXT — dispatched word uses its own)

// TIMER@ ( -- u )  read AArch64 virtual counter (CNTVCT_EL0, ~54 MHz on RPi4)
defcode "TIMER@", 6, timer_fetch, 0
    mrs     x0, cntvct_el0
    str     x0, [DSP, #-8]!
    NEXT

// TFREQ@ ( -- u )  timer frequency in Hz (CNTFRQ_EL0)
defcode "TFREQ@", 6, timer_freq, 0
    mrs     x0, cntfrq_el0
    str     x0, [DSP, #-8]!
    NEXT

// DL! ( abs -- )  set absolute deadline in CNTVCT ticks; 0 = disarmed
defcode "DL!", 3, deadline_store, 0
    ldr     x0, [DSP], #8
    bl      deadline_set
    NEXT

// DL@ ( -- abs )  get absolute deadline; 0 if disarmed
defcode "DL@", 3, deadline_fetch, 0
    bl      deadline_get
    str     x0, [DSP, #-8]!
    NEXT

// TMOUT? ( -- f )  true (-1) if deadline armed and TIMER@ >= deadline
defcode "TMOUT?", 6, timeout_q, 0
    bl      deadline_expired
    cmp     x0, #0
    csetm   x0, ne                  // x0 = -1 if expired, else 0
    str     x0, [DSP, #-8]!
    NEXT

// ELAPS@ ( start -- u )  ticks since start: TIMER@ - start
defcode "ELAPS@", 6, elapsed_fetch, 0
    ldr     x1, [DSP]
    mrs     x0, cntvct_el0
    sub     x0, x0, x1
    str     x0, [DSP]
    NEXT

// ETOUT ( -- )  emit a %timeout effect (elapsed = 0) via DO-FX path
defcode "ETOUT", 5, emit_timeout_word, 0
    mov     x0, #0
    bl      emit_timeout
    NEXT

// BUDGET! ( n -- )  set Nock op budget for subsequent NOCK/SKNOCK; 0 = unlimited
defcode "BUDGET!", 7, budget_store, 0
    ldr     x0, [DSP], #8
    bl      nock_budget_set
    NEXT

// BUDGET@ ( -- n )  current max op budget (0 = unlimited)
defcode "BUDGET@", 7, budget_fetch, 0
    bl      nock_budget_get
    str     x0, [DSP, #-8]!
    NEXT

// OPS@ ( -- n )  ops consumed since last BUDGET!
defcode "OPS@", 4, ops_fetch, 0
    bl      nock_ops_used
    str     x0, [DSP, #-8]!
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// ARITHMETIC PRIMITIVES
// ═════════════════════════════════════════════════════════════════════════════

// + ( a b -- a+b )
defcode "+", 1, plus, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    add     x1, x1, x0
    str     x1, [DSP]
    NEXT

// - ( a b -- a-b )
defcode "-", 1, minus, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    sub     x1, x1, x0
    str     x1, [DSP]
    NEXT

// * ( a b -- a*b )
defcode "*", 1, mul, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    mul     x1, x1, x0
    str     x1, [DSP]
    NEXT

// /MOD ( a b -- rem quot )
defcode "/MOD", 4, divmod, 0
    ldr     x0, [DSP], #8       // x0 = b (divisor)
    ldr     x1, [DSP], #8       // x1 = a (dividend)
    sdiv    x2, x1, x0          // x2 = quotient
    msub    x3, x2, x0, x1      // x3 = remainder
    str     x2, [DSP, #-8]!    // push quot (top after swap below)
    str     x3, [DSP, #-8]!    // push rem  (top)
    // Stack is now ( rem quot ) as expected
    NEXT

// / ( a b -- a/b )   truncated quotient
defcode "/", 1, div, 0
    ldr     x0, [DSP], #8       // x0 = b (divisor)
    ldr     x1, [DSP]           // x1 = a (dividend)
    sdiv    x1, x1, x0
    str     x1, [DSP]
    NEXT

// MOD ( a b -- a mod b )   truncated remainder
defcode "MOD", 3, mod, 0
    ldr     x0, [DSP], #8       // x0 = b (divisor)
    ldr     x1, [DSP]           // x1 = a (dividend)
    sdiv    x2, x1, x0          // x2 = quotient
    msub    x1, x2, x0, x1      // x1 = a - (a/b)*b
    str     x1, [DSP]
    NEXT

// NEGATE ( a -- -a )
defcode "NEG", 3, negate, 0
    ldr     x0, [DSP]
    neg     x0, x0
    str     x0, [DSP]
    NEXT

// ABS ( a -- |a| )
defcode "ABS", 3, abs, 0
    ldr     x0, [DSP]
    cmp     x0, #0
    cneg    x0, x0, mi
    str     x0, [DSP]
    NEXT

// 1+ ( a -- a+1 )
defcode "1+", 2, oneplus, 0
    ldr     x0, [DSP]
    add     x0, x0, #1
    str     x0, [DSP]
    NEXT

// 1- ( a -- a-1 )
defcode "1-", 2, oneminus, 0
    ldr     x0, [DSP]
    sub     x0, x0, #1
    str     x0, [DSP]
    NEXT

// 2* ( a -- a<<1 )
defcode "2*", 2, twostar, 0
    ldr     x0, [DSP]
    lsl     x0, x0, #1
    str     x0, [DSP]
    NEXT

// 2/ ( a -- a>>1 ) arithmetic
defcode "2/", 2, twoslash, 0
    ldr     x0, [DSP]
    asr     x0, x0, #1
    str     x0, [DSP]
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// COMPARISON AND LOGIC
// ═════════════════════════════════════════════════════════════════════════════
// Forth boolean: 0 = false, -1 (all bits set) = true.
// CSETM sets all bits on match (gives -1), clears on no match (gives 0).

// = ( a b -- flag )
defcode "=", 1, eq, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    cmp     x0, x1
    csetm   x0, eq
    str     x0, [DSP]
    NEXT

// <> ( a b -- flag )
defcode "<>", 2, neq, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    cmp     x0, x1
    csetm   x0, ne
    str     x0, [DSP]
    NEXT

// < ( a b -- flag ) signed
defcode "<", 1, lt, 0
    ldr     x0, [DSP], #8       // b
    ldr     x1, [DSP]           // a
    cmp     x1, x0              // a < b?
    csetm   x0, lt
    str     x0, [DSP]
    NEXT

// > ( a b -- flag ) signed
defcode ">", 1, gt, 0
    ldr     x0, [DSP], #8       // b
    ldr     x1, [DSP]           // a
    cmp     x1, x0              // a > b?
    csetm   x0, gt
    str     x0, [DSP]
    NEXT

// <= ( a b -- flag )
defcode "<=", 2, le, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    cmp     x1, x0
    csetm   x0, le
    str     x0, [DSP]
    NEXT

// >= ( a b -- flag )
defcode ">=", 2, ge, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    cmp     x1, x0
    csetm   x0, ge
    str     x0, [DSP]
    NEXT

// U< ( a b -- flag ) unsigned
defcode "U<", 2, ult, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    cmp     x1, x0
    csetm   x0, lo
    str     x0, [DSP]
    NEXT

// 0= ( a -- flag )
defcode "0=", 2, zeq, 0
    ldr     x0, [DSP]
    cmp     x0, #0
    csetm   x0, eq
    str     x0, [DSP]
    NEXT

// 0< ( a -- flag )
defcode "0<", 2, zlt, 0
    ldr     x0, [DSP]
    cmp     x0, #0
    csetm   x0, lt
    str     x0, [DSP]
    NEXT

// 0> ( a -- flag )
defcode "0>", 2, zgt, 0
    ldr     x0, [DSP]
    cmp     x0, #0
    csetm   x0, gt
    str     x0, [DSP]
    NEXT

// AND ( a b -- a&b )
defcode "AND", 3, and, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    and     x1, x1, x0
    str     x1, [DSP]
    NEXT

// OR ( a b -- a|b )
defcode "OR", 2, or, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    orr     x1, x1, x0
    str     x1, [DSP]
    NEXT

// XOR ( a b -- a^b )
defcode "XOR", 3, xor, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    eor     x1, x1, x0
    str     x1, [DSP]
    NEXT

// INVERT ( a -- ~a )
defcode "INV", 3, invert, 0
    ldr     x0, [DSP]
    mvn     x0, x0
    str     x0, [DSP]
    NEXT

// LSHIFT ( a n -- a<<n )
defcode "LSH", 3, lshift, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    lsl     x1, x1, x0
    str     x1, [DSP]
    NEXT

// RSHIFT ( a n -- a>>n ) logical
defcode "RSH", 3, rshift, 0
    ldr     x0, [DSP], #8
    ldr     x1, [DSP]
    lsr     x1, x1, x0
    str     x1, [DSP]
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// MEMORY PRIMITIVES
// ═════════════════════════════════════════════════════════════════════════════

// @ ( addr -- val )
defcode "@", 1, fetch, 0
    ldr     x0, [DSP]
    ldr     x0, [x0]
    str     x0, [DSP]
    NEXT

// ! ( val addr -- )
defcode "!", 1, store, 0
    ldr     x0, [DSP], #8       // addr
    ldr     x1, [DSP], #8       // val
    str     x1, [x0]
    NEXT

// +! ( n addr -- )
defcode "+!", 2, plusstore, 0
    ldr     x0, [DSP], #8       // addr
    ldr     x1, [DSP], #8       // n
    ldr     x2, [x0]
    add     x2, x2, x1
    str     x2, [x0]
    NEXT

// C@ ( addr -- char )
defcode "C@", 2, cfetch, 0
    ldr     x0, [DSP]
    ldrb    w0, [x0]
    str     x0, [DSP]
    NEXT

// C! ( char addr -- )
defcode "C!", 2, cstore, 0
    ldr     x0, [DSP], #8       // addr
    ldr     x1, [DSP], #8       // char
    strb    w1, [x0]
    NEXT

// CELL+ ( addr -- addr+8 )
defcode "CEL+", 4, cellplus, 0
    ldr     x0, [DSP]
    add     x0, x0, #8
    str     x0, [DSP]
    NEXT

// CELLS ( n -- n*8 )
defcode "CELL", 4, cells, 0
    ldr     x0, [DSP]
    lsl     x0, x0, #3
    str     x0, [DSP]
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// RETURN STACK PRIMITIVES
// ═════════════════════════════════════════════════════════════════════════════

// >R ( a -- ) R( -- a )
defcode ">R", 2, tor, 0
    ldr     x0, [DSP], #8
    str     x0, [RSP, #-8]!
    NEXT

// R> ( -- a ) R( a -- )
defcode "R>", 2, fromr, 0
    ldr     x0, [RSP], #8
    str     x0, [DSP, #-8]!
    NEXT

// R@ ( -- a ) R( a -- a )
defcode "R@", 2, rfetch, 0
    ldr     x0, [RSP]
    str     x0, [DSP, #-8]!
    NEXT

// RDROP ( -- ) R( a -- )
defcode "RDP", 3, rdrop, 0
    add     RSP, RSP, #8
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// CONTROL FLOW PRIMITIVES
// ═════════════════════════════════════════════════════════════════════════════

// LIT — push the next cell in the word stream as a literal.
// At runtime: IP points past the opcode to the value cell.
defcode "LIT", 3, lit, 0
    ldr     x0, [IP], #8        // value; advance IP past it
    str     x0, [DSP, #-8]!
    NEXT

// BRANCH — unconditional relative branch.
// Cell after BRANCH is a signed byte offset added to IP.
// Offset is relative to the address of the offset cell itself plus 8
// (i.e. to the cell following the offset). So offset 0 means next word.
defcode "BRN", 3, branch, 0
    ldr     x0, [IP]            // load offset
    add     IP, IP, x0          // IP += offset  (IP already past BRN cell)
    NEXT

// 0BRANCH — branch if zero (false).
defcode "0BRN", 4, zbranch, 0
    ldr     x0, [DSP], #8       // pop condition
    cbnz    x0, 1f              // non-zero: don't branch
    ldr     x0, [IP]            // zero: load offset
    add     IP, IP, x0
    NEXT
1:  add     IP, IP, #8          // skip offset cell
    NEXT

// EXECUTE ( xt -- )
defcode "EXEC", 4, execute, 0
    ldr     W, [DSP], #8        // W = execution token (entry address)
    ldr     x0, [W, #24]        // load codeword
    br      x0

// ═════════════════════════════════════════════════════════════════════════════
// I/O PRIMITIVES
// ═════════════════════════════════════════════════════════════════════════════

// KEY ( -- char )
defcode "KEY", 3, key, 0
1:  ldr     x0, =UART_FR
    ldr     w1, [x0]
    tbnz    w1, #4, 1b          // RX FIFO empty: spin
    ldr     x0, =UART_DR
    ldr     w0, [x0]
    and     x0, x0, #0xFF
    str     x0, [DSP, #-8]!
    NEXT

// EMIT ( char -- )
defcode "EMIT", 4, emit, 0
    ldr     x1, [DSP], #8
1:  ldr     x0, =UART_FR
    ldr     w2, [x0]
    tbnz    w2, #5, 1b          // TX FIFO full: spin
    ldr     x0, =UART_DR
    str     w1, [x0]
    NEXT

// CR ( -- )
defcode "CR", 2, cr, 0
1:  ldr     x0, =UART_FR
    ldr     w1, [x0]
    tbnz    w1, #5, 1b
    ldr     x0, =UART_DR
    mov     w1, #13
    str     w1, [x0]
2:  ldr     x0, =UART_FR
    ldr     w1, [x0]
    tbnz    w1, #5, 2b
    ldr     x0, =UART_DR
    mov     w1, #10
    str     w1, [x0]
    NEXT

// SPACE ( -- )
defcode "SPC", 3, space, 0
1:  ldr     x0, =UART_FR
    ldr     w1, [x0]
    tbnz    w1, #5, 1b
    ldr     x0, =UART_DR
    mov     w1, #32
    str     w1, [x0]
    NEXT

// TYPE ( addr len -- )
defcode "TYPE", 4, type, 0
    ldr     x2, [DSP], #8       // len
    ldr     x1, [DSP], #8       // addr
    cbz     x2, 2f
1:  ldrb    w0, [x1], #1
.Ltype_wait:
    ldr     x3, =UART_FR
    ldr     w4, [x3]
    tbnz    w4, #5, .Ltype_wait
    ldr     x3, =UART_DR
    str     w0, [x3]
    subs    x2, x2, #1
    bne     1b
2:  NEXT

// ═════════════════════════════════════════════════════════════════════════════
// SYSTEM VARIABLES AND CONSTANTS
// ═════════════════════════════════════════════════════════════════════════════

defvar "HERE", 4, here,   0, DICT_BASE  // next free dictionary address
defvar "LTST", 4, latest, 0, 0          // most recent entry (set in forth_main)
defvar "STAT", 4, state,  0, 0          // 0=interpret 1=compile
defvar "BASE", 4, base,   0, 10         // number base
defvar ">IN",  3, toin,   0, 0          // offset into TIB
defvar "#TIB", 4, ntib,   0, 0          // valid chars in TIB

defconst "TIB",  3, tib,      0, TIB_BASE
defconst "CEL",  3, cellsize, 0, 8

// ═════════════════════════════════════════════════════════════════════════════
// DICTIONARY OPERATIONS
// ═════════════════════════════════════════════════════════════════════════════

// , ( val -- )   append cell to HERE, advance HERE
defcode ",", 1, comma, 0
    ldr     x0, [DSP], #8               // value to compile
    ldr     x1, =word_here + 32         // address of HERE's storage
    ldr     x1, [x1]                    // current HERE
    str     x0, [x1]                    // store value there
    add     x1, x1, #8
    ldr     x2, =word_here + 32
    str     x1, [x2]                    // update HERE
    NEXT

// C, ( char -- )   append byte to HERE, advance HERE by 1
defcode "C,", 2, ccomma, 0
    ldr     x0, [DSP], #8
    ldr     x1, =word_here + 32
    ldr     x1, [x1]
    strb    w0, [x1]
    add     x1, x1, #1
    ldr     x2, =word_here + 32
    str     x1, [x2]
    NEXT

// ALLOT ( n -- )   advance HERE by n bytes
defcode "ALT", 3, allot, 0
    ldr     x0, [DSP], #8
    ldr     x1, =word_here + 32
    ldr     x2, [x1]
    add     x2, x2, x0
    str     x2, [x1]
    NEXT

// ALIGN ( -- )   align HERE to next 8-byte boundary
defcode "ALN", 3, align, 0
    ldr     x0, =word_here + 32
    ldr     x1, [x0]
    add     x1, x1, #7
    and     x1, x1, #~7
    str     x1, [x0]
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// WORD PARSING
// ═════════════════════════════════════════════════════════════════════════════

// WORD ( delim -- addr len )
// Parse next delim-delimited token from TIB into a scratch buffer at HERE.
// Does NOT advance HERE permanently. Returns addr=HERE and byte count.
defcode "WORD", 4, word, 0
    ldr     x7, [DSP], #8               // x7 = delimiter

    ldr     x0, =word_toin + 32
    ldr     x1, [x0]                    // x1 = >IN
    ldr     x2, =word_ntib + 32
    ldr     x2, [x2]                    // x2 = #TIB
    ldr     x3, =TIB_BASE               // x3 = TIB base

    // Skip leading delimiters
.Lword_skip:
    cmp     x1, x2
    bge     .Lword_empty
    ldrb    w4, [x3, x1]
    cmp     w4, w7
    bne     .Lword_collect
    add     x1, x1, #1
    b       .Lword_skip

    // Collect non-delimiter chars
.Lword_collect:
    ldr     x5, =word_here + 32
    ldr     x5, [x5]                    // x5 = output buffer (HERE)
    mov     x6, #0                      // x6 = length

.Lword_loop:
    cmp     x1, x2
    bge     .Lword_done
    ldrb    w4, [x3, x1]
    cmp     w4, w7
    beq     .Lword_done
    strb    w4, [x5, x6]
    add     x1, x1, #1
    add     x6, x6, #1
    b       .Lword_loop

.Lword_done:
    ldr     x0, =word_toin + 32
    str     x1, [x0]                    // update >IN
    str     x5, [DSP, #-8]!            // push addr
    str     x6, [DSP, #-8]!            // push len (top)
    NEXT

.Lword_empty:
    ldr     x5, =word_here + 32
    ldr     x5, [x5]
    str     x5, [DSP, #-8]!
    str     xzr, [DSP, #-8]!
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// DICTIONARY SEARCH
// ═════════════════════════════════════════════════════════════════════════════

// FIND ( addr len -- entry | 0 )
// Walk the dictionary chain from LATEST. Returns entry address or 0.
// Skips hidden words. Caller checks F_IMMEDIATE bit in entry+8 if needed.
defcode "FIND", 4, find, 0
    ldr     x6, [DSP], #8               // x6 = len
    ldr     x5, [DSP], #8               // x5 = string addr

    ldr     x0, =word_latest + 32
    ldr     x0, [x0]                    // x0 = start of chain

.Lfind_loop:
    cbz     x0, .Lfind_notfound
    ldr     x1, [x0, #8]                // flags|len
    and     x2, x1, #(F_HIDDEN << 8)
    cbnz    x2, .Lfind_next             // hidden: skip
    and     x2, x1, #0xFF               // name length
    cmp     x2, x6
    bne     .Lfind_next                 // length mismatch

    // Compare characters
    add     x3, x0, #16                 // entry name field
    mov     x4, #0
.Lfind_cmp:
    cmp     x4, x6
    bge     .Lfind_found
    ldrb    w8, [x5, x4]
    ldrb    w9, [x3, x4]
    cmp     w8, w9
    bne     .Lfind_next
    add     x4, x4, #1
    b       .Lfind_cmp

.Lfind_found:
    str     x0, [DSP, #-8]!
    NEXT

.Lfind_next:
    ldr     x0, [x0]                    // follow link
    b       .Lfind_loop

.Lfind_notfound:
    str     xzr, [DSP, #-8]!
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// NUMBER PARSING
// ═════════════════════════════════════════════════════════════════════════════

// NUMBER ( addr len -- n true | false )
// Parse string as unsigned integer in current BASE.
defcode "NUM", 3, number, 0
    ldr     x6, [DSP], #8               // len
    ldr     x5, [DSP], #8               // addr
    cbz     x6, .Lnum_bad               // empty string

    ldr     x0, =word_base + 32
    ldr     x0, [x0]                    // x0 = BASE

    // Check for leading '-'
    ldrb    w1, [x5]
    mov     x9, #0                      // x9 = negative flag
    cmp     w1, #'-'
    bne     .Lnum_start
    mov     x9, #1
    add     x5, x5, #1
    sub     x6, x6, #1
    cbz     x6, .Lnum_bad

.Lnum_start:
    mov     x3, #0                      // accumulator
    mov     x4, #0                      // index

.Lnum_loop:
    cmp     x4, x6
    bge     .Lnum_ok
    ldrb    w1, [x5, x4]

    // Digit conversion
    cmp     w1, #'0'
    blt     .Lnum_bad
    cmp     w1, #'9'
    ble     .Lnum_dec
    cmp     w1, #'A'
    blt     .Lnum_bad
    cmp     w1, #'F'
    ble     .Lnum_upper
    cmp     w1, #'a'
    blt     .Lnum_bad
    cmp     w1, #'f'
    bgt     .Lnum_bad
    sub     w1, w1, #('a' - 10)
    b       .Lnum_digit
.Lnum_upper:
    sub     w1, w1, #('A' - 10)
    b       .Lnum_digit
.Lnum_dec:
    sub     w1, w1, #'0'
.Lnum_digit:
    cmp     x1, x0                      // digit >= base?
    bge     .Lnum_bad
    mul     x3, x3, x0
    add     x3, x3, x1
    add     x4, x4, #1
    b       .Lnum_loop

.Lnum_ok:
    cbnz    x9, 1f                      // apply sign
    b       2f
1:  neg     x3, x3
2:  str     x3, [DSP, #-8]!            // push number
    mov     x0, #-1
    str     x0, [DSP, #-8]!            // push true
    NEXT

.Lnum_bad:
    str     xzr, [DSP, #-8]!           // push false
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// REFILL — read a line from UART into TIB
// ═════════════════════════════════════════════════════════════════════════════

defcode "RFL", 3, refill, 0
    ldr     x5, =TIB_BASE
    mov     x6, #0                      // char count

.Lrfl_loop:
    // Blocking UART read
    ldr     x0, =UART_FR
.Lrfl_rx:
    ldr     w1, [x0]
    tbnz    w1, #4, .Lrfl_rx           // RX FIFO empty
    ldr     x0, =UART_DR
    ldr     w2, [x0]
    and     w2, w2, #0xFF

    // CR/LF → done (CRLF emitted below, no echo here)
    cmp     w2, #13
    beq     .Lrfl_done
    cmp     w2, #10
    beq     .Lrfl_done

    // BS/DEL → erase last char if buffer non-empty
    cmp     w2, #8
    beq     .Lrfl_bs
    cmp     w2, #127
    beq     .Lrfl_bs

    // Normal char: echo then store (if buffer not full)
    cmp     x6, #(TIB_SIZE - 1)
    bge     .Lrfl_loop
    ldr     x0, =UART_FR
.Lrfl_echo:
    ldr     w3, [x0]
    tbnz    w3, #5, .Lrfl_echo
    ldr     x0, =UART_DR
    str     w2, [x0]
    strb    w2, [x5, x6]
    add     x6, x6, #1
    b       .Lrfl_loop

.Lrfl_bs:
    cbz     x6, .Lrfl_loop             // nothing to erase
    sub     x6, x6, #1
    // Send \b \b  (move back, overwrite with space, move back)
    ldr     x0, =UART_FR
.Lrfl_bs1:
    ldr     w3, [x0]
    tbnz    w3, #5, .Lrfl_bs1
    ldr     x0, =UART_DR
    mov     w1, #8
    str     w1, [x0]
    ldr     x0, =UART_FR
.Lrfl_bs2:
    ldr     w3, [x0]
    tbnz    w3, #5, .Lrfl_bs2
    ldr     x0, =UART_DR
    mov     w1, #32
    str     w1, [x0]
    ldr     x0, =UART_FR
.Lrfl_bs3:
    ldr     w3, [x0]
    tbnz    w3, #5, .Lrfl_bs3
    ldr     x0, =UART_DR
    mov     w1, #8
    str     w1, [x0]
    b       .Lrfl_loop

.Lrfl_done:
    // Emit CRLF
    ldr     x0, =UART_FR
.Lrfl_cr1:
    ldr     w1, [x0]
    tbnz    w1, #5, .Lrfl_cr1
    ldr     x0, =UART_DR
    mov     w1, #13
    str     w1, [x0]
    ldr     x0, =UART_FR
.Lrfl_lf1:
    ldr     w1, [x0]
    tbnz    w1, #5, .Lrfl_lf1
    ldr     x0, =UART_DR
    mov     w1, #10
    str     w1, [x0]

    // Update TIB state
    ldr     x0, =word_ntib + 32
    str     x6, [x0]
    ldr     x0, =word_toin + 32
    str     xzr, [x0]
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// COMPILER PRIMITIVES
// ═════════════════════════════════════════════════════════════════════════════

// [ ( -- )   enter interpret mode (immediate)
defcode "[", 1, lbrac, F_IMMEDIATE
    ldr     x0, =word_state + 32
    str     xzr, [x0]
    NEXT

// ] ( -- )   enter compile mode
defcode "]", 1, rbrac, 0
    ldr     x0, =word_state + 32
    mov     x1, #1
    str     x1, [x0]
    NEXT

// ' ( <name> -- xt )   push execution token of next parsed word
defcode "'", 1, tick, 0
    // Parse next space-delimited word from TIB
    ldr     x7, =word_toin + 32
    ldr     x1, [x7]
    ldr     x8, =word_ntib + 32
    ldr     x2, [x8]
    ldr     x3, =TIB_BASE

    // Skip spaces
.Ltick_skip:
    cmp     x1, x2
    bge     .Ltick_none
    ldrb    w4, [x3, x1]
    cmp     w4, #' '
    bne     .Ltick_col
    add     x1, x1, #1
    b       .Ltick_skip

    // Collect word
.Ltick_col:
    ldr     x5, =word_here + 32
    ldr     x5, [x5]
    mov     x6, #0
.Ltick_coll:
    cmp     x1, x2
    bge     .Ltick_done
    ldrb    w4, [x3, x1]
    cmp     w4, #' '
    beq     .Ltick_done
    strb    w4, [x5, x6]
    add     x1, x1, #1
    add     x6, x6, #1
    b       .Ltick_coll
.Ltick_done:
    str     x1, [x7]

    // FIND it
    ldr     x0, =word_latest + 32
    ldr     x0, [x0]
.Ltick_find:
    cbz     x0, .Ltick_none
    ldr     x1, [x0, #8]
    and     x2, x1, #0xFF
    cmp     x2, x6
    bne     .Ltick_next
    add     x3, x0, #16
    mov     x4, #0
.Ltick_cmp:
    cmp     x4, x6
    bge     .Ltick_found
    ldrb    w8, [x5, x4]
    ldrb    w9, [x3, x4]
    cmp     w8, w9
    bne     .Ltick_next
    add     x4, x4, #1
    b       .Ltick_cmp
.Ltick_found:
    str     x0, [DSP, #-8]!
    NEXT
.Ltick_next:
    ldr     x0, [x0]
    ldr     x3, =TIB_BASE
    b       .Ltick_find
.Ltick_none:
    str     xzr, [DSP, #-8]!
    NEXT

// IMMEDIATE ( -- )   mark the most recent definition as immediate
defcode "IMM", 3, immediate, 0
    ldr     x0, =word_latest + 32
    ldr     x0, [x0]                    // current latest entry
    ldr     x1, [x0, #8]                // flags|len
    orr     x1, x1, #(F_IMMEDIATE << 8)
    str     x1, [x0, #8]
    NEXT

// HIDDEN ( entry -- )   toggle hidden flag on an entry
defcode "HID", 3, hidden, 0
    ldr     x0, [DSP], #8
    ldr     x1, [x0, #8]
    eor     x1, x1, #(F_HIDDEN << 8)
    str     x1, [x0, #8]
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// COLON DEFINITIONS
// ═════════════════════════════════════════════════════════════════════════════

// : ( -- )   begin a colon definition
// Parses next space-delimited token from TIB, builds a DOCOL header at HERE,
// updates LATEST and HERE, marks the entry hidden until ; completes, enters
// compile mode.
defcode ":", 1, colon, 0
    // Load current HERE — this will be the base of the new entry
    ldr     x10, =word_here + 32
    ldr     x10, [x10]                  // x10 = entry base

    // ── Parse next token from TIB ─────────────────────────────────────────
    ldr     x0, =word_toin + 32
    ldr     x1, [x0]                    // x1 = >IN
    ldr     x2, =word_ntib + 32
    ldr     x2, [x2]                    // x2 = #TIB
    ldr     x3, =TIB_BASE

    // Skip leading spaces
.Lcolon_skip:
    cmp     x1, x2
    bge     .Lcolon_noname
    ldrb    w4, [x3, x1]
    cmp     w4, #' '
    bne     .Lcolon_collect
    add     x1, x1, #1
    b       .Lcolon_skip

    // Collect name chars into entry+16; zero the field first
.Lcolon_collect:
    str     xzr, [x10, #16]             // zero name field
    add     x5, x10, #16               // x5 = name field address
    mov     x6, #0                      // x6 = length
.Lcolon_coll:
    cmp     x1, x2
    bge     .Lcolon_namedone
    ldrb    w4, [x3, x1]
    cmp     w4, #' '
    beq     .Lcolon_namedone
    cmp     x6, #7                      // max 7 chars (8th byte stays zero)
    bge     .Lcolon_namedone
    strb    w4, [x5, x6]
    add     x1, x1, #1
    add     x6, x6, #1
    b       .Lcolon_coll

.Lcolon_namedone:
    // Update >IN
    ldr     x0, =word_toin + 32
    str     x1, [x0]

    // ── Write dictionary header at x10 ───────────────────────────────────
    // [entry+0]  = link  = current LATEST
    ldr     x0, =word_latest + 32
    ldr     x0, [x0]
    str     x0, [x10]

    // [entry+8]  = flags|len  (hidden during compilation)
    orr     x0, x6, #(F_HIDDEN << 8)
    str     x0, [x10, #8]

    // [entry+16] = name  (already written above)

    // [entry+24] = codeword = DOCOL
    ldr     x0, =DOCOL
    str     x0, [x10, #24]

    // ── Update LATEST and HERE ────────────────────────────────────────────
    ldr     x0, =word_latest + 32
    str     x10, [x0]                   // LATEST = new entry

    add     x0, x10, #32               // HERE = entry + 32 (body starts here)
    ldr     x1, =word_here + 32
    str     x0, [x1]

    // ── Enter compile mode ────────────────────────────────────────────────
    ldr     x0, =word_state + 32
    mov     x1, #1
    str     x1, [x0]
    NEXT

.Lcolon_noname:
    NEXT                                // no name token — ignore silently

// ; ( -- )   end a colon definition  (IMMEDIATE)
// Compiles EXIT, unhides the new word, returns to interpret mode.
defcode ";", 1, semicolon, F_IMMEDIATE
    // Compile EXIT: append word_exit to HERE
    ldr     x0, =word_here + 32
    ldr     x1, [x0]                    // x1 = HERE
    ldr     x2, =word_exit
    str     x2, [x1]                    // write EXIT entry address
    add     x1, x1, #8
    str     x1, [x0]                    // update HERE

    // Unhide the word just defined (clear F_HIDDEN bit)
    ldr     x0, =word_latest + 32
    ldr     x0, [x0]                    // x0 = latest entry
    ldr     x1, [x0, #8]               // flags|len
    mov     x2, #(F_HIDDEN << 8)
    bic     x1, x1, x2                 // x1 &= ~(F_HIDDEN << 8)
    str     x1, [x0, #8]

    // Return to interpret mode
    ldr     x0, =word_state + 32
    str     xzr, [x0]
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// CONTROL FLOW COMPILER WORDS  (all F_IMMEDIATE — run at compile time)
// ═════════════════════════════════════════════════════════════════════════════
//
// Offset convention (BRN / 0BRN):
//   When code_branch / code_zbranch runs, IP points TO the offset cell.
//   The branch sets IP = &offset_cell + offset, then NEXT reads from there.
//   So:  offset = target_addr - &offset_cell
//   Forward jump (positive),  backward jump (negative).
//
// Data-stack protocol during compilation:
//   IF   ( -- fixup )            fixup = addr of the 0BRN offset cell
//   THEN ( fixup -- )            patches fixup so false branch exits block
//   ELSE ( fixup_if -- fixup_else )
//   BEGIN ( -- loop_addr )       loop_addr = first word of loop body
//   UNTIL ( loop_addr -- )       0BRN back to loop_addr when false (= 0)
//   AGAIN ( loop_addr -- )       unconditional BRN back to loop_addr
//   WHILE ( loop_addr -- loop_addr fixup_while )
//   REPEAT ( loop_addr fixup_while -- )

// IF  ( -- fixup )
defcode "IF", 2, if, F_IMMEDIATE
    ldr     x0, =word_here + 32
    ldr     x1, [x0]               // x1 = HERE
    ldr     x2, =word_zbranch
    str     x2, [x1]               // compile word_zbranch
    add     x1, x1, #8
    str     xzr, [x1]              // compile placeholder 0
    str     x1, [DSP, #-8]!        // push placeholder addr (fixup)
    add     x1, x1, #8
    str     x1, [x0]               // update HERE
    NEXT

// THEN  ( fixup -- )
// Back-patches the forward branch left by IF or ELSE.
defcode "THEN", 4, then, F_IMMEDIATE
    ldr     x1, [DSP], #8          // pop fixup (offset cell address)
    ldr     x0, =word_here + 32
    ldr     x2, [x0]               // x2 = HERE (branch target)
    sub     x3, x2, x1             // offset = HERE - fixup_addr
    str     x3, [x1]               // patch placeholder
    NEXT

// ELSE  ( fixup_if -- fixup_else )
// Compiles BRN over the else-body; back-patches IF's forward branch to here.
defcode "ELSE", 4, else, F_IMMEDIATE
    ldr     x0, =word_here + 32
    ldr     x1, [x0]               // x1 = HERE
    ldr     x2, =word_branch
    str     x2, [x1]               // compile word_branch
    add     x1, x1, #8
    str     xzr, [x1]              // compile placeholder 0
    mov     x4, x1                 // x4 = ELSE's placeholder addr (fixup_else)
    add     x1, x1, #8            // x1 = HERE = start of else-body
    str     x1, [x0]               // update HERE
    // Back-patch IF's placeholder: offset = HERE (start of else-body) - if_fixup
    ldr     x3, [DSP], #8          // pop IF's fixup addr
    sub     x5, x1, x3             // offset = start_of_else - if_fixup
    str     x5, [x3]               // patch IF's placeholder
    str     x4, [DSP, #-8]!        // push ELSE's fixup for THEN
    NEXT

// BEGIN  ( -- loop_addr )
// Records the current HERE as the loop-back target.
defcode "BEGIN", 5, begin, F_IMMEDIATE
    ldr     x0, =word_here + 32
    ldr     x1, [x0]               // x1 = HERE = loop-back target
    str     x1, [DSP, #-8]!        // push it
    NEXT

// UNTIL  ( loop_addr -- )
// Compile 0BRN back to loop_addr.  Loops while condition is false (= 0);
// exits when condition is true (non-zero).
defcode "UNTIL", 5, until, F_IMMEDIATE
    ldr     x3, [DSP], #8          // pop loop-back target T
    ldr     x0, =word_here + 32
    ldr     x1, [x0]               // x1 = HERE
    ldr     x2, =word_zbranch
    str     x2, [x1]               // compile word_zbranch
    add     x1, x1, #8             // x1 = offset cell addr
    sub     x4, x3, x1             // offset = T - &offset_cell  (negative)
    str     x4, [x1]               // compile offset
    add     x1, x1, #8
    str     x1, [x0]               // update HERE
    NEXT

// AGAIN  ( loop_addr -- )
// Compile unconditional BRN back to loop_addr (infinite loop).
defcode "AGAIN", 5, again, F_IMMEDIATE
    ldr     x3, [DSP], #8          // pop loop-back target T
    ldr     x0, =word_here + 32
    ldr     x1, [x0]               // x1 = HERE
    ldr     x2, =word_branch
    str     x2, [x1]               // compile word_branch
    add     x1, x1, #8             // x1 = offset cell addr
    sub     x4, x3, x1             // offset = T - &offset_cell  (negative)
    str     x4, [x1]               // compile offset
    add     x1, x1, #8
    str     x1, [x0]               // update HERE
    NEXT

// WHILE  ( loop_addr -- loop_addr fixup_while )
// Compile 0BRN + placeholder.  Exits loop when condition is false (= 0).
defcode "WHILE", 5, while, F_IMMEDIATE
    ldr     x0, =word_here + 32
    ldr     x1, [x0]               // x1 = HERE
    ldr     x2, =word_zbranch
    str     x2, [x1]               // compile word_zbranch
    add     x1, x1, #8
    str     xzr, [x1]              // compile placeholder 0
    mov     x4, x1                 // x4 = WHILE's fixup addr
    add     x1, x1, #8
    str     x1, [x0]               // update HERE
    str     x4, [DSP, #-8]!        // push fixup (loop_addr stays below it)
    NEXT

// RECURSE  ( -- )   compile a self-call to the word currently being defined.
// The word is hidden during compilation, so it can't be found by name;
// RECURSE compiles its entry address directly from LATEST.
defcode "RECURSE", 7, recurse, F_IMMEDIATE
    ldr     x0, =word_latest + 32
    ldr     x1, [x0]               // LATEST = entry of word being defined
    ldr     x0, =word_here + 32
    ldr     x2, [x0]               // HERE
    str     x1, [x2]               // compile self-reference
    add     x2, x2, #8
    str     x2, [x0]               // update HERE
    NEXT

// REPEAT  ( loop_addr fixup_while -- )
// Compile BRN back to loop_addr; back-patch WHILE's fixup to exit the loop.
defcode "REPEAT", 6, repeat, F_IMMEDIATE
    ldr     x5, [DSP], #8          // pop WHILE's fixup addr
    ldr     x3, [DSP], #8          // pop loop-back target T
    ldr     x0, =word_here + 32
    ldr     x1, [x0]               // x1 = HERE
    ldr     x2, =word_branch
    str     x2, [x1]               // compile word_branch
    add     x1, x1, #8             // x1 = offset cell addr
    sub     x4, x3, x1             // offset = T - &offset_cell  (negative)
    str     x4, [x1]               // compile backward offset
    add     x1, x1, #8             // x1 = HERE after REPEAT = loop exit addr
    str     x1, [x0]               // update HERE
    sub     x4, x1, x5             // offset = exit_addr - while_fixup
    str     x4, [x5]               // patch WHILE's placeholder
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// DEBUG / INTROSPECTION
// ═════════════════════════════════════════════════════════════════════════════

// .S ( -- )   print stack non-destructively as hex values
defcode ".S", 2, dots, 0
    mov     x10, DSP
    ldr     x11, =DSTACK_TOP
.Ldots_loop:
    cmp     x10, x11
    bge     .Ldots_done
    ldr     x0, [x10]
    bl      printhex64
    ldr     x1, =UART_FR
.Ldots_sp:
    ldr     w2, [x1]
    tbnz    w2, #5, .Ldots_sp
    ldr     x1, =UART_DR
    mov     w2, #' '
    str     w2, [x1]
    add     x10, x10, #8
    b       .Ldots_loop
.Ldots_done:
    NEXT

// . ( n -- )   print top of stack as hex + space
// Note: full decimal '.' requires bignum division (Phase 4).
// This hex version is correct and useful for all debug purposes now.
defcode ".", 1, dot, 0
    ldr     x0, [DSP], #8
    bl      printhex64
    ldr     x1, =UART_FR
.Ldot_sp:
    ldr     w2, [x1]
    tbnz    w2, #5, .Ldot_sp
    ldr     x1, =UART_DR
    mov     w2, #' '
    str     w2, [x1]
    NEXT

// WORDS ( -- )   list all non-hidden dictionary entries
defcode "WRDS", 4, words, 0
    ldr     x0, =word_latest + 32
    ldr     x0, [x0]
.Lwords_loop:
    cbz     x0, .Lwords_done
    ldr     x1, [x0, #8]               // flags|len
    and     x2, x1, #(F_HIDDEN << 8)
    cbnz    x2, .Lwords_next           // hidden: skip
    and     x2, x1, #0xFF              // name length
    add     x3, x0, #16                // name addr
    // TYPE the name
    mov     x4, #0
.Lwords_type:
    cmp     x4, x2
    bge     .Lwords_sp
    ldrb    w5, [x3, x4]
    ldr     x6, =UART_FR
.Lwords_tw:
    ldr     w7, [x6]
    tbnz    w7, #5, .Lwords_tw
    ldr     x6, =UART_DR
    str     w5, [x6]
    add     x4, x4, #1
    b       .Lwords_type
.Lwords_sp:
    ldr     x6, =UART_FR
.Lwords_spw:
    ldr     w7, [x6]
    tbnz    w7, #5, .Lwords_spw
    ldr     x6, =UART_DR
    mov     w7, #' '
    str     w7, [x6]
.Lwords_next:
    ldr     x0, [x0]
    b       .Lwords_loop
.Lwords_done:
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// NOUN PRIMITIVES  (Phase 2 — interfaces to noun.c)
// ═════════════════════════════════════════════════════════════════════════════
//
// Noun 64-bit word layout (bits 63:62 = tag):
//   00  cell        bits 31:0 = heap ptr to {refcount, pad, head, tail}
//   01  direct atom bits 61:0 = value
//   10  indirect    bits 61:32 = BLAKE3 prefix; bits 31:0 = heap ptr to atom_t
//   11  content     bits 61:0 = 62-bit BLAKE3 hash
//
// C functions called here use AAPCS; x24-x27 (W/RSP/DSP/IP) are callee-saved
// per AAPCS so they survive bl calls without explicit save/restore.

// CONS ( head tail -- cell )
defcode "CONS", 4, cons, 0
    ldr     x1, [DSP], #8       // x1 = tail (TOS)
    ldr     x0, [DSP], #8       // x0 = head
    bl      alloc_cell          // returns cell noun in x0
    str     x0, [DSP, #-8]!
    NEXT

// CAR ( cell -- head )   head of a cell noun
defcode "CAR", 3, car, 0
    ldr     x0, [DSP], #8       // x0 = cell noun
    and     x0, x0, #0xFFFFFFFF // extract 32-bit heap pointer
    ldr     x1, [x0, #8]        // cell_t.head at offset 8
    str     x1, [DSP, #-8]!
    NEXT

// CDR ( cell -- tail )   tail of a cell noun
defcode "CDR", 3, cdr, 0
    ldr     x0, [DSP], #8       // x0 = cell noun
    and     x0, x0, #0xFFFFFFFF // extract 32-bit heap pointer
    ldr     x1, [x0, #16]       // cell_t.tail at offset 16
    str     x1, [DSP, #-8]!
    NEXT

// >NOUN ( n -- noun )   wrap raw integer as a direct atom noun (bit63=0)
// In the new scheme direct(v) = v, so just clear bit 63.
defcode ">NOUN", 5, to_noun, 0
    ldr     x0, [DSP]
    lsl     x0, x0, #1          // clear bit 63
    lsr     x0, x0, #1
    str     x0, [DSP]
    NEXT

// NOUN> ( noun -- n )   extract raw integer from a direct atom noun
// direct_val(n) = n & 0x7FFF..., i.e. clear bit 63.
defcode "NOUN>", 5, from_noun, 0
    ldr     x0, [DSP]
    lsl     x0, x0, #1          // clear bit 63
    lsr     x0, x0, #1
    str     x0, [DSP]
    NEXT

// ATOM? ( noun -- flag )   true (-1) if atom (bits 63:62 ≠ 11), false (0) if cell
defcode "ATOM?", 5, isatom, 0
    ldr     x0, [DSP]
    lsr     x1, x0, #62         // top 2 bits → positions 1:0
    cmp     x1, #3
    csetm   x1, ne              // ne → -1 (atom), eq → 0 (cell)
    str     x1, [DSP]
    NEXT

// CELL? ( noun -- flag )   true (-1) if cell (bits 63:62 = 11), false (0) if atom
defcode "CELL?", 5, iscell, 0
    ldr     x0, [DSP]
    lsr     x1, x0, #62         // top 2 bits → positions 1:0
    cmp     x1, #3
    csetm   x1, eq              // eq → -1 (cell), ne → 0 (atom)
    str     x1, [DSP]
    NEXT

// =NOUN ( n1 n2 -- flag )   structural equality (calls noun_eq in noun.c)
defcode "=NOUN", 5, noueq, 0
    ldr     x1, [DSP], #8       // x1 = n2 (TOS)
    ldr     x0, [DSP], #8       // x0 = n1
    bl      noun_eq             // returns 1 (equal) or 0 (not equal)
    neg     x0, x0              // 1 → -1 (Forth true), 0 → 0 (Forth false)
    str     x0, [DSP, #-8]!
    NEXT

// HATOM ( noun -- noun' )   no-op in new scheme: atoms are always content-addressed.
defcode "HATOM", 5, hash_atom_word, 0
    NEXT

// PILL ( -- atom )   load jammed atom from PILL_BASE (QEMU -device loader).
//   Returns noun-zero (direct 0) if no pill was loaded.
//   Caller should CUE the result to decode the noun.
defcode "PILL", 4, pill, 0
    bl      pill_load           // noun.c: reads from PILL_BASE, returns atom
    str     x0, [DSP, #-8]!
    NEXT

// B3OK ( -- flag )   run official BLAKE3 test vectors; pushes 1=pass 0=fail
defcode "B3OK", 4, b3ok, 0
    bl      blake3_selftest     // blake3.c: returns 1 (pass) or 0 (fail)
    str     x0, [DSP, #-8]!
    NEXT

// N. ( noun -- )   print atom as decimal + space
// Calls bn_to_decimal_fill(noun) → fills bn_decimal_buf[], returns length.
defcode "N.", 2, ndot, 0
    ldr     x0, [DSP], #8
    bl      bn_to_decimal_fill  // x0 = length written into bn_decimal_buf[]
    cbz     x0, .Lndot_sp
    mov     x4, x0              // x4 = remaining chars
    ldr     x3, =bn_decimal_buf // x3 = buf pointer
.Lndot_loop:
    cbz     x4, .Lndot_sp
    ldrb    w5, [x3], #1
.Lndot_tx:
    ldr     x6, =UART_FR
    ldr     w7, [x6]
    tbnz    w7, #5, .Lndot_tx
    ldr     x6, =UART_DR
    str     w5, [x6]
    sub     x4, x4, #1
    b       .Lndot_loop
.Lndot_sp:
    ldr     x6, =UART_FR
.Lndot_spw:
    ldr     w7, [x6]
    tbnz    w7, #5, .Lndot_spw
    ldr     x6, =UART_DR
    mov     w7, #' '
    str     w7, [x6]
    NEXT

// BN+ ( noun1 noun2 -- noun )   bignum addition
defcode "BN+", 3, bnadd, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_add
    str     x0, [DSP, #-8]!
    NEXT

// BNDEC ( noun -- noun )   bignum decrement (crashes on zero)
defcode "BNDEC", 5, bndec, 0
    ldr     x0, [DSP], #8
    bl      bn_dec
    str     x0, [DSP, #-8]!
    NEXT

// BNMET ( noun -- n )   significant bit length; result is raw integer
defcode "BNMET", 5, bnmet, 0
    ldr     x0, [DSP], #8
    bl      bn_met              // returns uint64_t in x0
    str     x0, [DSP, #-8]!
    NEXT

// BNBEX ( n -- noun )   2^n as atom noun; n is raw integer
defcode "BNBEX", 5, bnbex, 0
    ldr     x0, [DSP], #8
    bl      bn_bex
    str     x0, [DSP, #-8]!
    NEXT

// BNLSH ( noun n -- noun )   left shift noun by n bits; n is raw integer
defcode "BNLSH", 5, bnlsh, 0
    ldr     x1, [DSP], #8      // k (raw integer)
    ldr     x0, [DSP], #8      // noun
    bl      bn_lsh
    str     x0, [DSP, #-8]!
    NEXT

// BNRSH ( noun n -- noun )   right shift noun by n bits; n is raw integer
defcode "BNRSH", 5, bnrsh, 0
    ldr     x1, [DSP], #8      // k (raw integer)
    ldr     x0, [DSP], #8      // noun
    bl      bn_rsh
    str     x0, [DSP, #-8]!
    NEXT

// BNOR ( n1 n2 -- n )   bitwise OR of two atom nouns
defcode "BNOR", 4, bnor, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_or
    str     x0, [DSP, #-8]!
    NEXT

// BNAND ( n1 n2 -- n )   bitwise AND of two atom nouns
defcode "BNAND", 5, bnand, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_and
    str     x0, [DSP, #-8]!
    NEXT

// BNXOR ( n1 n2 -- n )   bitwise XOR of two atom nouns
defcode "BNXOR", 5, bnxor, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_xor
    str     x0, [DSP, #-8]!
    NEXT

// BNMUL ( n1 n2 -- n )   bignum multiplication
defcode "BNMUL", 5, bnmul, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_mul
    str     x0, [DSP, #-8]!
    NEXT

// BNDIV ( n1 n2 -- n )   integer quotient: floor(n1 / n2)
defcode "BNDIV", 5, bndiv, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_div
    str     x0, [DSP, #-8]!
    NEXT

// BNMOD ( n1 n2 -- n )   remainder: n1 mod n2
defcode "BNMOD", 5, bnmod, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_mod
    str     x0, [DSP, #-8]!
    NEXT

// BNSUB ( n1 n2 -- n )   bignum subtraction: n1 - n2; crashes if n1 < n2
defcode "BNSUB", 5, bnsub, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_sub
    str     x0, [DSP, #-8]!
    NEXT

// Bignum comparisons — return Nock booleans: 0 = YES (true), 1 = NO (false).
// Stack: ( a b -- flag ) where b is on top.
// bn_cmp(a, b): x0=a (second pop), x1=b (first pop); returns sign(a-b).

// BNLTH ( a b -- flag )   a < b  → YES(0),  else NO(1)
defcode "BNLTH", 5, bnlth, 0
    ldr     x1, [DSP], #8          // x1 = b (top)
    ldr     x0, [DSP], #8          // x0 = a
    bl      bn_cmp
    cmp     w0, #0                  // 32-bit compare (bn_cmp returns int)
    cset    x0, ge                  // 1 (NO) if bn_cmp ≥ 0 (a ≥ b)
    str     x0, [DSP, #-8]!
    NEXT

// BNGTH ( a b -- flag )   a > b  → YES(0),  else NO(1)
defcode "BNGTH", 5, bngth, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_cmp
    cmp     w0, #0
    cset    x0, le                  // 1 (NO) if bn_cmp ≤ 0 (a ≤ b)
    str     x0, [DSP, #-8]!
    NEXT

// BNLTE ( a b -- flag )   a <= b → YES(0),  else NO(1)
defcode "BNLTE", 5, bnlte, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_cmp
    cmp     w0, #0
    cset    x0, gt                  // 1 (NO) if bn_cmp > 0 (a > b)
    str     x0, [DSP, #-8]!
    NEXT

// BNGTE ( a b -- flag )   a >= b → YES(0),  else NO(1)
defcode "BNGTE", 5, bngte, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      bn_cmp
    cmp     w0, #0
    cset    x0, lt                  // 1 (NO) if bn_cmp < 0 (a < b)
    str     x0, [DSP, #-8]!
    NEXT

// ─────────────────────────────────────────────────────────────────────────────
// JAM / CUE  (Phase 5a — noun serialization / deserialization)
// ─────────────────────────────────────────────────────────────────────────────

// JAM ( noun -- atom )   serialize noun to atom via jam encoding
defcode "JAM", 3, jam_word, 0
    ldr     x0, [DSP], #8
    bl      jam
    str     x0, [DSP, #-8]!
    NEXT

// JAMBYTES ( -- failures ) exact direct-view/legacy format parity probe.
defcode "JAMBYTES", 8, jam_bytes_test_word, 0
    bl      jam_encode_bytes_selftest
    str     x0, [DSP, #-8]!
    NEXT

// CUE ( atom -- noun )   deserialize atom back to noun via cue decoding
defcode "CUE", 3, cue_word, 0
    ldr     x0, [DSP], #8
    bl      cue
    str     x0, [DSP, #-8]!
    NEXT

// ─────────────────────────────────────────────────────────────────────────────
// NOCK EVAL PRIMITIVES  (Phase 3 — interfaces to nock.c)
// ─────────────────────────────────────────────────────────────────────────────

// SLOT ( axis noun -- result )   Nock / operator: tree address lookup
defcode "SLOT", 4, slot, 0
    ldr     x1, [DSP], #8       // x1 = noun (subject)
    ldr     x0, [DSP], #8       // x0 = axis (direct atom)
    bl      slot                // slot(axis, subject)
    str     x0, [DSP, #-8]!
    NEXT

// ─────────────────────────────────────────────────────────────────────────────
// NOCK GATE JETS — colon definitions registered by name in the Forth dictionary.
//
// Op 9 dispatch in nock.c calls find_by_cord(label) first; if found, the Forth
// word is called via forth_call_jet(entry, core).  These static definitions are
// the default implementations; %tame hints compiled later shadow them.
//
// ABI: ( core -- result )  where core is a gate [battery [sample context]].
//   Unary  gates: sample = slot(6, core)
//   Binary gates: a = slot(12, core),  b = slot(13, core)
//
// SLOT takes ( axis noun -- result ) with noun on top.  To extract axis N from
// a core sitting on the stack: push N, SWAP (core to top), then SLOT.
// ─────────────────────────────────────────────────────────────────────────────
defword "dec", 3, jet_dec_forth, 0
    .quad DOCOL
    .quad word_lit,  6,  word_swap, word_slot   // slot(6, core)
    .quad word_bndec
    .quad word_exit

defword "add", 3, jet_add_forth, 0
    .quad DOCOL
    .quad word_dup
    .quad word_lit, 12, word_swap, word_slot    // slot(12, core) = a
    .quad word_swap
    .quad word_lit, 13, word_swap, word_slot    // slot(13, core) = b
    .quad word_bnadd
    .quad word_exit

defword "sub", 3, jet_sub_forth, 0
    .quad DOCOL
    .quad word_dup
    .quad word_lit, 12, word_swap, word_slot
    .quad word_swap
    .quad word_lit, 13, word_swap, word_slot
    .quad word_bnsub
    .quad word_exit

defword "mul", 3, jet_mul_forth, 0
    .quad DOCOL
    .quad word_dup
    .quad word_lit, 12, word_swap, word_slot
    .quad word_swap
    .quad word_lit, 13, word_swap, word_slot
    .quad word_bnmul
    .quad word_exit

defword "div", 3, jet_div_forth, 0
    .quad DOCOL
    .quad word_dup
    .quad word_lit, 12, word_swap, word_slot
    .quad word_swap
    .quad word_lit, 13, word_swap, word_slot
    .quad word_bndiv
    .quad word_exit

defword "mod", 3, jet_mod_forth, 0
    .quad DOCOL
    .quad word_dup
    .quad word_lit, 12, word_swap, word_slot
    .quad word_swap
    .quad word_lit, 13, word_swap, word_slot
    .quad word_bnmod
    .quad word_exit

defword "lth", 3, jet_lth_forth, 0
    .quad DOCOL
    .quad word_dup
    .quad word_lit, 12, word_swap, word_slot
    .quad word_swap
    .quad word_lit, 13, word_swap, word_slot
    .quad word_bnlth
    .quad word_exit

defword "gth", 3, jet_gth_forth, 0
    .quad DOCOL
    .quad word_dup
    .quad word_lit, 12, word_swap, word_slot
    .quad word_swap
    .quad word_lit, 13, word_swap, word_slot
    .quad word_bngth
    .quad word_exit

defword "lte", 3, jet_lte_forth, 0
    .quad DOCOL
    .quad word_dup
    .quad word_lit, 12, word_swap, word_slot
    .quad word_swap
    .quad word_lit, 13, word_swap, word_slot
    .quad word_bnlte
    .quad word_exit

defword "gte", 3, jet_gte_forth, 0
    .quad DOCOL
    .quad word_dup
    .quad word_lit, 12, word_swap, word_slot
    .quad word_swap
    .quad word_lit, 13, word_swap, word_slot
    .quad word_bngte
    .quad word_exit

// SKA-EN ( -- addr )  when non-zero, NOCK routes through ska_nock
defvar "SKA-EN", 6, ska_enable, 0, 0

// SCORD ( -- addr )  scratch variable for saving a cord noun across operations
defvar "SCORD", 5, scord_var, 0, 0

// S>CRD ( addr len -- cord )  create a cord (atom) from a byte string in memory
defcode "S>CRD", 5, str_to_cord, 0
    ldr     x1, [DSP], #8               // x1 = len
    ldr     x0, [DSP], #8               // x0 = addr (src)
    bl      cord_from_bytes             // cord_from_bytes(addr, len) → x0
    str     x0, [DSP, #-8]!
    NEXT

// NOCK ( subject formula -- product )   Nock 4K evaluator
// When SKA-EN is non-zero, routes through ska_nock (SKA-annotated eval).
defcode "NOCK", 4, nock_word, 0
    ldr     x1, [DSP], #8       // x1 = formula
    ldr     x0, [DSP], #8       // x0 = subject
    adr     x4, word_ska_enable
    ldr     x4, [x4, #32]       // load SKA-EN storage cell
    cbz     x4, .Lnock_plain
    mov     x2, #0              // jets = NULL
    mov     x3, #0              // sky  = NULL
    bl      ska_nock
    b       .Lnock_done
.Lnock_plain:
    bl      nock
.Lnock_done:
    str     x0, [DSP, #-8]!
    NEXT

// SKNOCK ( subject formula -- product )  SKA-analyzed Nock evaluator
// Runs the SKA scan pass over the formula, then evaluates the nomm_t AST.
// Gives identical results to NOCK but with static jet dispatch at annotated
// call sites.  Falls back to nock_ex() for op 9 / indirect op 2 sites.
defcode "SKNOCK", 6, sknock, 0
    ldr     x1, [DSP], #8       // x1 = formula
    ldr     x0, [DSP], #8       // x0 = subject
    mov     x2, #0              // jets = NULL
    mov     x3, #0              // sky  = NULL
    bl      ska_nock            // ska_nock(subject, formula, NULL, NULL)
    str     x0, [DSP, #-8]!
    NEXT

// .SKA ( subject formula -- )   Print SKA analysis dashboard to UART
// Runs ska_analyze (scan + cook) and prints call site statistics:
//   "SKA: N call sites (D direct, J jetted)"
defcode ".SKA", 4, dotska, 0
    ldr     x1, [DSP], #8       // x1 = formula
    ldr     x0, [DSP], #8       // x0 = subject
    bl      ska_print_stats     // ska_print_stats(subject, formula)
    NEXT

// ═════════════════════════════════════════════════════════════════════════════
// QUIT — the top-level interpreter loop
// ═════════════════════════════════════════════════════════════════════════════
//
// QUIT never returns. On error we jump back to .Lquit_restart.
// Implements the standard Forth outer interpreter:
//   loop:
//     refill TIB
//     for each word in TIB:
//       find in dictionary
//         if found and interpreting: execute
//         if found and immediate: execute
//         if found and compiling:  compile (append xt to HERE)
//       not found: try as number
//         if number and interpreting: push
//         if number and compiling:    compile LIT + value
//       not found and not number: error
//
defcode "QUIT", 4, quit, 0

.Lquit_restart:
    // Reset stacks unconditionally — this is also the ABORT target
    ldr     DSP, =DSTACK_TOP
    ldr     RSP, =RSTACK_TOP

    // Interpret mode
    ldr     x0, =word_state + 32
    str     xzr, [x0]

    // Establish (or re-establish) nock crash recovery point.
    // setjmp saves all callee-saved regs (x19-x28 inc. Forth VM regs,
    // x29/x30, sp) with stacks already clean.
    // Returns 0 on normal entry; 1 after longjmp from nock_crash()
    // (crash message already printed).  Either way fall through to prompt.
    ldr     x0, =nock_abort
    bl      setjmp
    // x0 ignored — both paths print the prompt and enter the line loop

    // Print prompt
    ldr     x0, =str_prompt
    ldr     x1, =str_prompt_end
    sub     x1, x1, x0
    bl      puts_uart

.Lquit_line:
    // Read a line from UART into TIB
    // (Inline REFILL — can't call Forth words from a primitive easily)
    ldr     x5, =TIB_BASE
    mov     x6, #0
.Lq_rxloop:
    ldr     x0, =UART_FR
.Lq_rxwait:
    ldr     w1, [x0]
    tbnz    w1, #4, .Lq_rxwait
    ldr     x0, =UART_DR
    ldr     w2, [x0]
    and     w2, w2, #0xFF
    // CR/LF → end of line (no echo; CRLF emitted below)
    cmp     w2, #13
    beq     .Lq_eol
    cmp     w2, #10
    beq     .Lq_eol
    // BS/DEL → erase last char if buffer non-empty
    cmp     w2, #8
    beq     .Lq_bs
    cmp     w2, #127
    beq     .Lq_bs
    // Normal char: echo then store (if buffer not full)
    cmp     x6, #(TIB_SIZE - 1)
    bge     .Lq_rxloop
    ldr     x0, =UART_FR
.Lq_txwait:
    ldr     w3, [x0]
    tbnz    w3, #5, .Lq_txwait
    ldr     x0, =UART_DR
    str     w2, [x0]
    strb    w2, [x5, x6]
    add     x6, x6, #1
    b       .Lq_rxloop
.Lq_bs:
    cbz     x6, .Lq_rxloop             // nothing to erase
    sub     x6, x6, #1
    // Send \b \b  (move back, overwrite with space, move back)
    ldr     x0, =UART_FR
.Lq_bs1:
    ldr     w3, [x0]
    tbnz    w3, #5, .Lq_bs1
    ldr     x0, =UART_DR
    mov     w1, #8
    str     w1, [x0]
    ldr     x0, =UART_FR
.Lq_bs2:
    ldr     w3, [x0]
    tbnz    w3, #5, .Lq_bs2
    ldr     x0, =UART_DR
    mov     w1, #32
    str     w1, [x0]
    ldr     x0, =UART_FR
.Lq_bs3:
    ldr     w3, [x0]
    tbnz    w3, #5, .Lq_bs3
    ldr     x0, =UART_DR
    mov     w1, #8
    str     w1, [x0]
    b       .Lq_rxloop
.Lq_eol:
    // Emit CRLF
    ldr     x0, =UART_FR
.Lq_cr:
    ldr     w1, [x0]
    tbnz    w1, #5, .Lq_cr
    ldr     x0, =UART_DR
    mov     w1, #13
    str     w1, [x0]
    ldr     x0, =UART_FR
.Lq_lf:
    ldr     w1, [x0]
    tbnz    w1, #5, .Lq_lf
    ldr     x0, =UART_DR
    mov     w1, #10
    str     w1, [x0]
    // Store TIB length, reset >IN
    ldr     x0, =word_ntib + 32
    str     x6, [x0]
    ldr     x0, =word_toin + 32
    str     xzr, [x0]

    // ── Process each word in the TIB ─────────────────────────────────────
.Lquit_word:
    .global quit_word_loop
quit_word_loop:
    // Parse next space-delimited token from TIB
    ldr     x0, =word_toin + 32
    ldr     x1, [x0]                    // >IN
    ldr     x2, =word_ntib + 32
    ldr     x2, [x2]                    // #TIB
    ldr     x3, =TIB_BASE

    // Skip leading spaces
.Lq_skip:
    cmp     x1, x2
    bge     .Lq_newline                 // exhausted — print ok, new prompt
    ldrb    w4, [x3, x1]
    cmp     w4, #' '
    bne     .Lq_collect
    add     x1, x1, #1
    b       .Lq_skip

    // Collect non-space chars into scratch buffer at HERE
.Lq_collect:
    ldr     x5, =word_here + 32
    ldr     x5, [x5]                    // token buffer = current HERE
    mov     x6, #0
.Lq_coll:
    cmp     x1, x2
    bge     .Lq_colldone
    ldrb    w4, [x3, x1]
    cmp     w4, #' '
    beq     .Lq_colldone
    strb    w4, [x5, x6]
    add     x1, x1, #1
    add     x6, x6, #1
    b       .Lq_coll
.Lq_colldone:
    // Update >IN
    ldr     x0, =word_toin + 32
    str     x1, [x0]
    // x5 = token addr, x6 = token len

    // ── Dictionary lookup ─────────────────────────────────────────────────
    ldr     x0, =word_latest + 32
    ldr     x0, [x0]
.Lq_find:
    cbz     x0, .Lq_number             // not found: try as number
    ldr     x1, [x0, #8]               // flags|len of this entry
    and     x2, x1, #(F_HIDDEN << 8)
    cbnz    x2, .Lq_fnext              // hidden: skip
    and     x2, x1, #0xFF              // name length
    cmp     x2, x6
    bne     .Lq_fnext
    add     x3, x0, #16                // name field
    mov     x4, #0
.Lq_fcmp:
    cmp     x4, x6
    bge     .Lq_found
    ldrb    w7, [x5, x4]
    ldrb    w8, [x3, x4]
    cmp     w7, w8
    bne     .Lq_fnext
    add     x4, x4, #1
    b       .Lq_fcmp
.Lq_fnext:
    ldr     x0, [x0]
    ldr     x3, =TIB_BASE
    b       .Lq_find

    // ── Word found in dictionary ──────────────────────────────────────────
.Lq_found:
    // x0 = entry address
    ldr     x1, [x0, #8]               // flags|len
    // Check immediate flag — immediate words always execute
    and     x2, x1, #(F_IMMEDIATE << 8)
    cbnz    x2, .Lq_execute

    // Check STATE
    ldr     x1, =word_state + 32
    ldr     x1, [x1]
    cbnz    x1, .Lq_compile            // compiling: append to HERE

    // Interpreting: execute it
.Lq_execute:
    // Set W = entry, load codeword, branch
    // We do this with a mini NEXT — but we need IP to be valid.
    // Solution: build a one-cell trampoline on the return stack.
    // After execution, the word's EXIT will pop our saved IP and
    // return to .Lquit_word via the trampoline cell we leave.
    //
    // Actually simpler: just call the codeword directly.
    // Non-colon words end with NEXT which needs a valid IP.
    // We point IP at a 'resume' cell that holds word_quit's entry.
    // This keeps NEXT safe for primitives that fall into it.
    mov     W, x0
    ldr     x0, =trampoline_quit
    mov     IP, x0
    ldr     x0, [W, #24]               // codeword
    br      x0

.Lq_compile:
    // Append the entry address (xt) to HERE
    ldr     x1, =word_here + 32
    ldr     x2, [x1]                   // current HERE
    str     x0, [x2]                   // write xt
    add     x2, x2, #8
    str     x2, [x1]                   // update HERE
    b       .Lquit_word

    // ── Try as number ─────────────────────────────────────────────────────
.Lq_number:
    // x5 = token addr, x6 = token len
    ldr     x0, =word_base + 32
    ldr     x0, [x0]                   // BASE

    // Check for leading '-'
    ldrb    w1, [x5]
    mov     x9, #0
    cmp     w1, #'-'
    bne     .Lq_numparse
    mov     x9, #1
    add     x5, x5, #1
    sub     x6, x6, #1
    cbz     x6, .Lq_error

.Lq_numparse:
    mov     x3, #0                     // accumulator
    mov     x4, #0                     // index
.Lq_numloop:
    cmp     x4, x6
    bge     .Lq_numok
    ldrb    w1, [x5, x4]
    cmp     w1, #'0'
    blt     .Lq_error
    cmp     w1, #'9'
    ble     .Lq_numdec
    cmp     w1, #'A'
    blt     .Lq_error
    cmp     w1, #'F'
    ble     .Lq_numupp
    cmp     w1, #'a'
    blt     .Lq_error
    cmp     w1, #'f'
    bgt     .Lq_error
    sub     w1, w1, #('a' - 10)
    b       .Lq_numdig
.Lq_numupp:
    sub     w1, w1, #('A' - 10)
    b       .Lq_numdig
.Lq_numdec:
    sub     w1, w1, #'0'
.Lq_numdig:
    cmp     x1, x0
    bge     .Lq_error
    mul     x3, x3, x0
    add     x3, x3, x1
    add     x4, x4, #1
    b       .Lq_numloop
.Lq_numok:
    cbnz    x9, 1f
    b       2f
1:  neg     x3, x3
2:
    // Number parsed successfully: x3 = value
    ldr     x1, =word_state + 32
    ldr     x1, [x1]
    cbz     x1, .Lq_push               // interpret: push

    // Compile: LIT + value
    ldr     x1, =word_here + 32
    ldr     x2, [x1]
    ldr     x4, =word_lit
    str     x4, [x2]                   // compile LIT
    add     x2, x2, #8
    str     x3, [x2]                   // compile value
    add     x2, x2, #8
    str     x2, [x1]                   // update HERE
    b       .Lquit_word

.Lq_push:
    str     x3, [DSP, #-8]!           // push number onto data stack
    b       .Lquit_word

    // ── Error — unknown word ──────────────────────────────────────────────
.Lq_error:
    // Print the offending token and "?" then reset
    ldr     x0, =str_err
    ldr     x1, =str_err_end
    sub     x1, x1, x0
    bl      puts_uart
    b       .Lquit_restart             // reset stacks, start over

    // ── End of line — print " ok" and prompt ─────────────────────────────
.Lq_newline:
    // Only print "ok" if in interpret mode (standard Forth convention)
    ldr     x0, =word_state + 32
    ldr     x0, [x0]
    cbnz    x0, .Lq_prompt_only

    ldr     x0, =str_ok
    ldr     x1, =str_ok_end
    sub     x1, x1, x0
    bl      puts_uart

.Lq_prompt_only:
    ldr     x0, =str_prompt
    ldr     x1, =str_prompt_end
    sub     x1, x1, x0
    bl      puts_uart
    b       .Lquit_line

// ── Trampoline — NEXT target after executing a word from QUIT ────────────────
// When QUIT dispatches a word, IP is set to trampoline_quit.
// For primitives: NEXT reads *IP = word_quit_resume, dispatches code_quit_resume
//   which branches to quit_word_loop (next token), leaving data stack intact.
// For colon defs: DOCOL pushes IP (=trampoline_quit) onto RSP; EXIT pops it
//   and does NEXT, which dispatches word_quit_resume → quit_word_loop.
// This preserves the data stack between words on a single input line.

// Internal word (hidden): jump to QUIT's token loop without resetting stacks.
defcode "_QR", 3, quit_resume, F_HIDDEN
    b       quit_word_loop

// ── EVAL ( c-addr u -- ) ─────────────────────────────────────────────────────
// Evaluate a string of Forth source in the current dictionary context.
// Saves TIB/#TIB/>IN, installs the source, runs the token loop, restores.
// Uses RSP (Forth return stack) to save/restore the caller's IP — same pattern
// as DOCOL/EXIT.  Nesting: not safe for re-entrant use (single BSS save area).
//
// Error handling: unknown word → nock_crash() → longjmp back to QUIT.
// ─────────────────────────────────────────────────────────────────────────────
defcode "EVAL", 4, eval_word, 0
    ldr     x1, [DSP], #8               // u  (len)
    ldr     x0, [DSP], #8               // c-addr

    // Save caller's IP on return stack (mirrors DOCOL).
    str     IP, [RSP, #-8]!

    // Save TIB (256 bytes) to BSS buffer
    ldr     x3, =eval_tib_save
    ldr     x4, =TIB_BASE
    mov     x5, #(TIB_SIZE / 16)        // 16 iterations × 16 bytes
.Lev_tib_save:
    ldp     x6, x7, [x4], #16
    stp     x6, x7, [x3], #16
    subs    x5, x5, #1
    bne     .Lev_tib_save

    // Save #TIB and >IN
    ldr     x3, =word_ntib + 32
    ldr     x5, [x3]
    ldr     x4, =eval_ntib_save
    str     x5, [x4]
    ldr     x3, =word_toin + 32
    ldr     x5, [x3]
    ldr     x4, =eval_toin_save
    str     x5, [x4]

    // Copy source into TIB (x0=src, x1=len; clamp to TIB_SIZE-1)
    ldr     x3, =TIB_BASE
    cmp     x1, #(TIB_SIZE - 1)
    blt     1f
    mov     x1, #(TIB_SIZE - 1)
1:  mov     x5, #0
.Lev_copy:
    cmp     x5, x1
    bge     .Lev_copy_done
    ldrb    w6, [x0, x5]
    strb    w6, [x3, x5]
    add     x5, x5, #1
    b       .Lev_copy
.Lev_copy_done:
    strb    wzr, [x3, x5]               // null-terminate (defensive)

    // Set #TIB = len, >IN = 0
    ldr     x3, =word_ntib + 32
    str     x1, [x3]
    ldr     x3, =word_toin + 32
    str     xzr, [x3]

    // Fall into eval token loop
eval_word_loop:
    // Parse next space-delimited token from TIB
    ldr     x0, =word_toin + 32
    ldr     x1, [x0]
    ldr     x2, =word_ntib + 32
    ldr     x2, [x2]
    ldr     x3, =TIB_BASE

    // Skip leading spaces
.Lev_skip:
    cmp     x1, x2
    bge     .Lev_exhausted              // all tokens consumed
    ldrb    w4, [x3, x1]
    cmp     w4, #' '
    bne     .Lev_collect
    add     x1, x1, #1
    b       .Lev_skip

    // Collect non-space chars into token buffer at HERE
.Lev_collect:
    ldr     x5, =word_here + 32
    ldr     x5, [x5]
    mov     x6, #0
.Lev_coll:
    cmp     x1, x2
    bge     .Lev_colldone
    ldrb    w4, [x3, x1]
    cmp     w4, #' '
    beq     .Lev_colldone
    strb    w4, [x5, x6]
    add     x1, x1, #1
    add     x6, x6, #1
    b       .Lev_coll
.Lev_colldone:
    ldr     x0, =word_toin + 32
    str     x1, [x0]
    // x5 = token addr, x6 = token len

    // Dictionary lookup
    ldr     x0, =word_latest + 32
    ldr     x0, [x0]
.Lev_find:
    cbz     x0, .Lev_number
    ldr     x1, [x0, #8]               // flags|len
    and     x2, x1, #(F_HIDDEN << 8)
    cbnz    x2, .Lev_fnext
    and     x2, x1, #0xFF              // name length
    cmp     x2, x6
    bne     .Lev_fnext
    add     x3, x0, #16                // name field
    mov     x4, #0
.Lev_fcmp:
    cmp     x4, x6
    bge     .Lev_found
    ldrb    w7, [x5, x4]
    ldrb    w8, [x3, x4]
    cmp     w7, w8
    bne     .Lev_fnext
    add     x4, x4, #1
    b       .Lev_fcmp
.Lev_fnext:
    ldr     x0, [x0]
    ldr     x3, =TIB_BASE
    b       .Lev_find

    // Word found
.Lev_found:
    ldr     x1, [x0, #8]
    and     x2, x1, #(F_IMMEDIATE << 8)
    cbnz    x2, .Lev_execute
    ldr     x1, =word_state + 32
    ldr     x1, [x1]
    cbnz    x1, .Lev_compile

.Lev_execute:
    mov     W, x0
    ldr     x0, =trampoline_eval        // our trampoline, not trampoline_quit
    mov     IP, x0
    ldr     x0, [W, #24]
    br      x0

.Lev_compile:
    ldr     x1, =word_here + 32
    ldr     x2, [x1]
    str     x0, [x2]
    add     x2, x2, #8
    str     x2, [x1]
    b       eval_word_loop

    // Try as number (mirrors QUIT's .Lq_number)
.Lev_number:
    ldr     x0, =word_base + 32
    ldr     x0, [x0]
    ldrb    w1, [x5]
    mov     x9, #0
    cmp     w1, #'-'
    bne     .Lev_numparse
    mov     x9, #1
    add     x5, x5, #1
    sub     x6, x6, #1
    cbz     x6, .Lev_error
.Lev_numparse:
    mov     x3, #0
    mov     x4, #0
.Lev_numloop:
    cmp     x4, x6
    bge     .Lev_numok
    ldrb    w1, [x5, x4]
    cmp     w1, #'0'
    blt     .Lev_error
    cmp     w1, #'9'
    ble     .Lev_numdec
    cmp     w1, #'A'
    blt     .Lev_error
    cmp     w1, #'F'
    ble     .Lev_numupp
    cmp     w1, #'a'
    blt     .Lev_error
    cmp     w1, #'f'
    bgt     .Lev_error
    sub     w1, w1, #('a' - 10)
    b       .Lev_numdig
.Lev_numupp:
    sub     w1, w1, #('A' - 10)
    b       .Lev_numdig
.Lev_numdec:
    sub     w1, w1, #'0'
.Lev_numdig:
    cmp     x1, x0
    bge     .Lev_error
    mul     x3, x3, x0
    add     x3, x3, x1
    add     x4, x4, #1
    b       .Lev_numloop
.Lev_numok:
    cbnz    x9, 1f
    b       2f
1:  neg     x3, x3
2:
    ldr     x1, =word_state + 32
    ldr     x1, [x1]
    cbz     x1, .Lev_push
    ldr     x1, =word_here + 32
    ldr     x2, [x1]
    ldr     x4, =word_lit
    str     x4, [x2]
    add     x2, x2, #8
    str     x3, [x2]
    add     x2, x2, #8
    str     x2, [x1]
    b       eval_word_loop
.Lev_push:
    str     x3, [DSP, #-8]!
    b       eval_word_loop

    // Error: restore TIB then crash (longjmps to QUIT restart)
.Lev_error:
    b       .Lev_restore                // restore, then fall into crash path

    // Source exhausted: restore TIB and return to caller
.Lev_exhausted:
    // clear error flag in x9 (reuse path joins here from .Lev_error)
    mov     x9, #0
    b       .Lev_do_restore
.Lev_restore:
    mov     x9, #1                      // error = true
.Lev_do_restore:
    // Restore TIB from BSS buffer
    ldr     x3, =eval_tib_save
    ldr     x4, =TIB_BASE
    mov     x5, #(TIB_SIZE / 16)
.Lev_tib_restore:
    ldp     x6, x7, [x3], #16
    stp     x6, x7, [x4], #16
    subs    x5, x5, #1
    bne     .Lev_tib_restore

    // Restore #TIB and >IN
    ldr     x3, =eval_ntib_save
    ldr     x5, [x3]
    ldr     x3, =word_ntib + 32
    str     x5, [x3]
    ldr     x3, =eval_toin_save
    ldr     x5, [x3]
    ldr     x3, =word_toin + 32
    str     x5, [x3]

    // Restore caller's IP from return stack (mirrors EXIT)
    ldr     IP, [RSP], #8

    cbz     x9, 1f
    // Error path: crash (triggers longjmp to QUIT)
    ldr     x0, =str_eval_err
    bl      uart_puts
    ldr     x0, =nock_abort
    mov     x1, #1
    bl      longjmp
1:  NEXT

// Hidden word: resume eval token loop after a word executes
defcode "_ER", 3, eval_resume, F_HIDDEN
    b       eval_word_loop

// ── Phase 6 — Kernel Loop ─────────────────────────────────────────────────

// KSHAPE  ( -- addr )   kernel shape: 0=Arvo 1=Shrine
//   Loaded from PILL header by KERNEL. Inspect with KSHAPE @
defvar "KSHAPE", 6, kshape, 0, 0

// NOUN-RX ( -- noun )   read length-framed cue-decoded noun from UART
defcode "NOUN-RX", 7, recv_noun, 0
    bl      uart_recv_noun          // kernel.c
    str     x0, [DSP, #-8]!
    NEXT

// NOUN-TX ( noun -- )   jam noun, write length-framed to UART
defcode "NOUN-TX", 7, send_noun, 0
    ldr     x0, [DSP], #8
    bl      uart_send_noun          // kernel.c
    NEXT

// DO-FX ( effects -- )   walk effect list, dispatch known tags
defcode "DO-FX", 5, dispatch_fx, 0
    ldr     x0, [DSP], #8
    bl      dispatch_effects        // kernel.c
    NEXT

// ── Phase 3 — MMIO + IRQ ring ─────────────────────────────────────────────

// MMIO@ ( addr -- u )  32-bit physical load, zero-extended
defcode "MMIO@", 5, mmio_fetch, 0
    ldr     x0, [DSP]
    bl      mmio_read32
    str     x0, [DSP]
    NEXT

// MMIO! ( u addr -- )  32-bit physical store (low 32 bits of u)
defcode "MMIO!", 5, mmio_store, 0
    ldr     x1, [DSP], #8           // addr
    ldr     x0, [DSP], #8           // val
    mov     x2, x0                  // save val
    mov     x0, x1                  // addr in x0 for mmio_write32(addr,val)
    mov     x1, x2
    bl      mmio_write32
    NEXT

// MSCR ( -- addr )  address of RAM scratch word for MMIO tests
defcode "MSCR", 4, mscr, 0
    bl      mmio_scratch_addr
    str     x0, [DSP, #-8]!
    NEXT

// IRQP ( code -- f )  push code into IRQ ring; true if accepted
defcode "IRQP", 4, irqp, 0
    ldr     x0, [DSP]
    bl      irq_ring_push
    cmp     x0, #0
    csetm   x0, ne
    str     x0, [DSP]
    NEXT

// IRQDRN ( -- )  drain IRQ ring into event queue (same as kernel loop)
defcode "IRQDRN", 6, irqdrn, 0
    bl      irq_ring_drain
    NEXT

// IRQC ( -- )  clear IRQ ring (drop pending codes)
defcode "IRQC", 4, irqc, 0
    bl      irq_ring_clear
    NEXT

// ── Phase 4 — multi-core (core 0 Forth only) ──────────────────────────────

// CID@ ( -- n )  this core's id (0 on the REPL)
defcode "CID@", 4, core_id_fetch, 0
    bl      core_id
    str     x0, [DSP, #-8]!
    NEXT

// CSTART ( n -- )  cooperative start of core n (1..3)
defcode "CSTART", 6, core_start_word, 0
    ldr     x0, [DSP], #8
    bl      core_start
    NEXT

// CSTOP ( n -- )  cooperative stop of core n
defcode "CSTOP", 5, core_stop_word, 0
    ldr     x0, [DSP], #8
    bl      core_stop
    NEXT

// CSEND ( code n -- f )  send code to core n; true if queued
defcode "CSEND", 5, core_send_word, 0
    ldr     x0, [DSP], #8           // n (id)
    ldr     x1, [DSP]               // code
    // core_send(id, code): x0=id, x1=code — already correct order
    bl      core_send
    cmp     x0, #0
    csetm   x0, ne
    str     x0, [DSP]
    NEXT

// CHB@ ( n -- u )  heartbeat counter for core n
defcode "CHB@", 4, core_hb_fetch, 0
    ldr     x0, [DSP]
    bl      core_heartbeat_get
    str     x0, [DSP]
    NEXT

// ── Phase 5 — RAM cold store (content-addressed jam blobs) ────────────────

// CFMT ( -- )  wipe and reformat cold region
defcode "CFMT", 4, cold_fmt, 0
    bl      cold_format
    NEXT

// CSTOR ( noun -- hash62 )  jam+store; 0 on error
defcode "CSTOR", 5, cold_stor, 0
    ldr     x0, [DSP]
    bl      cold_store
    str     x0, [DSP]
    NEXT

// CLOAD ( hash62 -- noun )  load+cue; 0 if missing
defcode "CLOAD", 5, cold_load_word, 0
    ldr     x0, [DSP]
    bl      cold_load
    str     x0, [DSP]
    NEXT

// LOGEV ( noun -- )  append jammed event to log
defcode "LOGEV", 5, cold_logev, 0
    ldr     x0, [DSP], #8
    bl      cold_log
    NEXT

// LOGLEN ( -- n )
defcode "LOGLEN", 6, cold_loglen, 0
    bl      cold_log_len
    str     x0, [DSP, #-8]!
    NEXT

// LOG@ ( i -- noun )  log entry i; 0 if OOB
defcode "LOG@", 4, cold_logat, 0
    ldr     x0, [DSP]
    bl      cold_log_at
    str     x0, [DSP]
    NEXT

// SNAP! ( noun -- )  save snapshot root
defcode "SNAP!", 5, cold_snap_store, 0
    ldr     x0, [DSP], #8
    bl      cold_snap_save
    NEXT

// SNAP@ ( -- noun )  load snapshot; 0 if none
defcode "SNAP@", 5, cold_snap_fetch, 0
    bl      cold_snap_load
    str     x0, [DSP, #-8]!
    NEXT

// ── Durable host checkpoint (I2 live roots → cold store) ──────────────────
// CKPT!  ( -- st )     capture gate+queue+tarms → cold snap; 0=ok else -1
// CKLOAD ( -- st )     cold snap → install live roots; 0=ok else -1
// CKAUTO! ( n -- )     auto-save every n successful I2 commits (0=off)
// CKAUTO@ ( -- n )
// KGATE! ( noun -- )   set live shrine gate (persist copy; no loop)
// KGATE@ ( -- noun )   get live gate

defcode "CKPT!", 5, ckpt_save_word, 0
    bl      checkpoint_save
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "CKLOAD", 6, ckpt_load_word, 0
    bl      checkpoint_load
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "CKAUTO!", 7, ckpt_auto_store, 0
    ldr     x0, [DSP], #8
    bl      checkpoint_auto_every
    NEXT

defcode "CKAUTO@", 7, ckpt_auto_fetch, 0
    bl      checkpoint_auto_get
    str     x0, [DSP, #-8]!
    NEXT

// Narrow M2 diagnostics: stable rejection reason/counter and generation.
defcode "RXWHY", 5, rx_reason_fetch, 0
    bl      i2_rx_last_reason
    str     x0, [DSP, #-8]!
    NEXT

defcode "RXCNT", 5, rx_count_fetch, 0
    ldr     x0, [DSP]
    bl      i2_rx_reject_count
    str     x0, [DSP]
    NEXT

defcode "CKRES", 5, ckpt_result_fetch, 0
    bl      checkpoint_last_result
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "CKGEN", 5, ckpt_generation_fetch, 0
    bl      checkpoint_selected_generation
    str     x0, [DSP, #-8]!
    NEXT

defcode "CRES", 4, cold_result_fetch, 0
    bl      cold_last_result
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "CGEN", 4, cold_generation_fetch, 0
    bl      cold_selected_generation
    str     x0, [DSP, #-8]!
    NEXT

// Focused Milestone 2 boundary probes ( -- failures )
defcode "RXM2", 4, i2_rx_m2_test, 0
    bl      i2_rx_selftest
    str     x0, [DSP, #-8]!
    NEXT

defcode "CUEM2", 5, cue_m2_test, 0
    bl      cue_bounded_selftest
    str     x0, [DSP, #-8]!
    NEXT

defcode "TXM2", 4, tx_m2_test, 0
    bl      kernel_tx_stuck_selftest
    str     x0, [DSP, #-8]!
    NEXT

#ifndef I2_OPERATOR
defcode "I2OP", 4, i2_operator_test, 0
    bl      i2_operator_selftest
    str     x0, [DSP, #-8]!
    NEXT

defcode "I2OPQ", 5, i2_operator_query_test, 0
    ldr     x0, [DSP]
    bl      i2_operator_query_storm
    str     x0, [DSP]
    NEXT
#endif

defcode "COLDM2", 6, cold_m2_test, 0
    bl      cold_m2_selftest
    str     x0, [DSP, #-8]!
    NEXT

// M2PREP ( -- st ) admit/install PILL2 roots without entering scheduler.
defcode "M2PREP", 6, m2_prepare_pill, 0
    bl      kernel_prepare_pill
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

// M21 fixed two-slot authority probes.  The only external ingress accepts
// two BOOL samples for the admitted source REQ; no Forth word accepts raw
// EI, route, egress, or inter-resource carrier nouns.
// M21IN ( a b -- status ) / M21STEP ( -- status ) / M21AIN@ ( -- bool|-1 )
// M21BIN@ ( -- bool|-1 ) / M21Q ( slot -- count|-1 ) / M21ERR@ ( -- code )
// M21RAW?/M21ST?/M21FL?/M21RF? ( -- status ) are focused hostile controls.
// M21CKS?/M21CKR? capture/restore the fixed two-slot checkpoint noun;
// M21BD? proves tamper refusal retains the current root.
defcode "M21IN", 5, m21_input_word, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP], #8
    bl      m21_device_enqueue_source_bool
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21STEP", 7, m21_step_word, 0
    bl      m21_device_step
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21AIN@", 7, m21_a_input_word, 0
    mov     x0, #1
    bl      m21_device_sink_input
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21BIN@", 7, m21_b_input_word, 0
    mov     x0, #2
    bl      m21_device_sink_input
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21Q", 4, m21_queue_word, 0
    ldr     x0, [DSP]
    bl      m21_device_queue_len
    str     x0, [DSP]
    NEXT

defcode "M21ERR@", 7, m21_error_word, 0
    bl      m21_device_last_error
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21RAW?", 7, m21_raw_word, 0
    bl      m21_device_raw_ingress_refuses
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21ST?", 6, m21_stale_word, 0
    bl      m21_device_stale_carrier_refuses
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21FL?", 6, m21_full_word, 0
    bl      m21_device_destination_full_refuses
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21RF?", 6, m21_reservation_fault_word, 0
    bl      m21_device_publish_reservation_fault_refuses
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21CKS?", 7, m21_checkpoint_save_word, 0
    bl      m21_device_checkpoint_capture
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21CKR?", 7, m21_checkpoint_restore_word, 0
    bl      m21_device_checkpoint_restore
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M21BD?", 6, m21_checkpoint_bad_word, 0
    bl      m21_device_checkpoint_tamper_refuses
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

// M22 framed provider-core seam.  The frame carries only the post-transport
// product; the C path supplies the image-owned adapter attestation.
defcode "M22INIT", 7, m22_init_word, 0
    bl      m22_provider_core_init
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22RX?", 6, m22_receive_word, 0
    bl      m22_provider_core_receive_framed
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22STEP", 7, m22_step_word, 0
    bl      m22_provider_core_step
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22IND@", 7, m22_indication_word, 0
    bl      m22_provider_core_indication
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22SEQ@", 7, m22_indication_sequence_word, 0
    bl      m22_provider_core_indication_sequence
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22Q", 4, m22_queue_word, 0
    bl      m22_provider_core_queue_len
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22HWM@", 7, m22_high_water_word, 0
    bl      m22_provider_core_high_water
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22ERR@", 7, m22_error_word, 0
    bl      m22_provider_core_last_error
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22CUE@", 7, m22_cue_calls_word, 0
    bl      m22_provider_core_cue_calls
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22CK?", 6, m22_checkpoint_word, 0
    bl      m22_provider_core_checkpoint
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22RF?", 6, m22_reservation_fault_word, 0
    bl      m22_provider_core_reservation_fault_once
    mov     x0, #0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M22UA?", 6, m22_unattested_word, 0
    bl      m22_provider_core_unattested_probe
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

#ifdef M23_TEST_CONTROLS
// M23 restart-safe session authority.  These words are test-build-only
// image-owned operations; framed nouns can only attempt post-transport
// admission.  The provider core remains present without this surface.
defcode "M23INIT", 7, m23_init_word, 0
    bl      m23_provider_core_init
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23ARM", 6, m23_arm_word, 0
    bl      m23_provider_core_arm
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23COLD", 7, m23_cold_word, 0
    bl      m23_provider_core_cold
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23RST", 6, m23_clean_restart_word, 0
    bl      m23_provider_core_restart_clean
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23CLS", 6, m23_close_word, 0
    bl      m23_provider_core_close
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23RX?", 6, m23_receive_word, 0
    bl      m23_provider_core_receive_framed
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23STEP", 7, m23_step_word, 0
    bl      m23_provider_core_step
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23ROT", 6, m23_rotate_word, 0
    bl      m23_provider_core_rotate
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23CKS?", 7, m23_checkpoint_save_word, 0
    bl      m23_provider_core_checkpoint_save
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23CKR?", 7, m23_checkpoint_restore_word, 0
    bl      m23_provider_core_checkpoint_restore
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23BD?", 6, m23_checkpoint_bad_word, 0
    bl      m23_provider_core_checkpoint_tamper
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23PUB?", 7, m23_publish_word, 0
    bl      m23_provider_core_complete_egress
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23B64?", 7, m23_outbound_burst_word, 0
    bl      m23_provider_core_test_outbound_burst
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23MAX?", 7, m23_max_word, 0
    bl      m23_provider_core_set_next_max_minus_one
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT
defcode "M23Q", 4, m23_queue_word, 0
    bl      m23_provider_core_queue_len
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23HWM@", 7, m23_high_water_word, 0
    bl      m23_provider_core_high_water
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23NEXT@", 8, m23_next_word, 0
    bl      m23_provider_core_next_sequence
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23E@", 5, m23_epoch_word, 0
    bl      m23_provider_core_epoch
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23S@", 5, m23_state_word, 0
    bl      m23_provider_core_state
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23ERR@", 7, m23_error_word, 0
    bl      m23_provider_core_last_error
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23RC@", 6, m23_rate_count_word, 0
    bl      m23_provider_core_outbound_rate_count
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23CUE@", 7, m23_cue_calls_word, 0
    bl      m23_provider_core_cue_calls
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23IND@", 7, m23_indication_word, 0
    bl      m23_provider_core_indication
    str     x0, [DSP, #-8]!
    NEXT

defcode "M23SEQ@", 7, m23_indication_sequence_word, 0
    bl      m23_provider_core_indication_sequence
    str     x0, [DSP, #-8]!
    NEXT

#ifdef M24_NATIVE
// M24 native target controls are image-owned test operations.  M23PUB? is
// deliberately retained as the historical synthetic egress witness;
// M24PUB? commits only after virtio-net reports a used-ring completion.
defcode "M24INIT", 7, m24_init_word, 0
    bl      m23_provider_core_native_init
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24RX?", 6, m24_receive_word, 0
    bl      m23_provider_core_receive_native
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24PUB?", 7, m24_publish_word, 0
    bl      m23_provider_core_publish_native
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24ERR@", 7, m24_error_word, 0
    bl      m24_native_last_error
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24VERR@", 8, m24_virtio_error_word, 0
    bl      virtio_net_last_error
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24MAG@", 7, m24_virtio_magic_word, 0
    mov     x0, #0
    bl      virtio_net_debug_reg
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24VER@", 7, m24_virtio_version_word, 0
    mov     x0, #4
    bl      virtio_net_debug_reg
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24DID@", 7, m24_virtio_device_word, 0
    mov     x0, #8
    bl      virtio_net_debug_reg
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24STA@", 7, m24_virtio_status_word, 0
    bl      virtio_net_debug_status
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24Q0R@", 7, m24_virtio_rx_ready_word, 0
    mov     x0, #0
    bl      virtio_net_debug_queue_ready
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24Q1R@", 7, m24_virtio_tx_ready_word, 0
    mov     x0, #1
    bl      virtio_net_debug_queue_ready
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24TUA@", 7, m24_virtio_tx_avail_word, 0
    bl      virtio_net_debug_tx_avail
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24TUU@", 7, m24_virtio_tx_used_word, 0
    bl      virtio_net_debug_tx_used
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24TXP@", 7, m24_virtio_tx_packets_word, 0
    bl      virtio_net_debug_tx_packets
    str     x0, [DSP, #-8]!
    NEXT

#ifdef M23_TEST_CONTROLS
defcode "M24HOLD", 7, m24_virtio_test_hold_tx_plain_word, 0
    bl      virtio_net_test_hold_tx
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24REL", 6, m24_virtio_test_release_tx_word, 0
    bl      virtio_net_test_release_tx
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24RXBAD", 8, m24_virtio_test_corrupt_rx_used_word, 0
    bl      virtio_net_test_corrupt_rx_used
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24RXOVR", 8, m24_virtio_test_overadvance_rx_used_word, 0
    bl      virtio_net_test_overadvance_rx_used
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24RXLEN", 8, m24_virtio_test_overlong_rx_used_word, 0
    bl      virtio_net_test_overlong_rx_used
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24TXBAD", 8, m24_virtio_test_corrupt_tx_used_word, 0
    bl      virtio_net_test_corrupt_tx_used
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24TXLEN", 8, m24_virtio_test_overlong_tx_used_word, 0
    bl      virtio_net_test_overlong_tx_used
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M24B64?", 7, m24_native_rate_burst_word, 0
    bl      m23_provider_core_test_native_rate_burst
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT
#endif

#endif

#endif

// ── M7 pure resource supervisor / trusted lab bridge ─────────────────────
// M7INIT ( -- st )        validate the live M7 identity/gate and install the
//                         persistent pure-Nock MANAGER formula.
// M7OBJ  ( id kind -- noun )  make one static manager object noun.
// M7REQ  ( object cmd -- st ) receipt only; M7STEP is the REQ+ boundary.
defcode "M7INIT", 6, m7_init_word, 0
    bl      shrine_gate_get
    bl      m7_init
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

// M7MI ( qi -- status )  Annex-F QI/INITO bridge (0 disables service).
defcode "M7MI", 4, m7_manager_init_word, 0
    ldr     x0, [DSP]
    bl      m7_manager_init
    sxtw    x0, w0
    str     x0, [DSP]
    NEXT

defcode "M7OBJ", 5, m7_object_word, 0
    ldr     x0, [DSP], #8       // kind
    ldr     x1, [DSP], #8       // object id
    bl      m7_object
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7REQ", 5, m7_request_word, 0
    ldr     x0, [DSP], #8       // command
    ldr     x1, [DSP], #8       // object
    bl      m7_manager_request
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

// M7REQB ( address length command -- status )
// The address is a trusted-lab pointer to the canonical <=512-byte OBJECT.
defcode "M7REQB", 6, m7_request_bytes_word, 0
    ldr     x2, [DSP], #8       // command
    ldr     x1, [DSP], #8       // length
    ldr     x0, [DSP], #8       // address
    // C ABI: command, bytes, length.
    mov     x3, x1
    mov     x1, x0
    mov     x0, x2
    mov     x2, x3
    bl      m7_manager_request_bytes
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7STEP", 6, m7_step_word, 0
    bl      m7_scheduler_boundary
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7MODE", 6, m7_mode_word, 0
    bl      m7_mode
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7INC@", 6, m7_inc_word, 0
    bl      m7_incarnation
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7REQ@", 6, m7_req_fetch_word, 0
    bl      m7_req_plus
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7CNF@", 6, m7_cnf_fetch_word, 0
    bl      m7_confirmations
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7QO?", 5, m7_qo_word, 0
    bl      m7_qo
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7STAT", 6, m7_status_word, 0
    bl      m7_last_status
    str     x0, [DSP, #-8]!
    NEXT

// M7RES ( -- noun )  last successful QUERY RESULT noun. It is cleared at
// every receipt/REQ+ boundary, so an error cannot expose a prior result.
defcode "M7RES", 5, m7_result_word, 0
    bl      m7_last_result_noun
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7RST@", 6, m7_restart_word, 0
    bl      m7_last_restart
    str     x0, [DSP, #-8]!
    NEXT

// Trusted-lab M7 memory/lifecycle witnesses; neither is a MANAGER object.
defcode "M7MEM@", 6, m7_memory_word, 0
    bl      m7_persist_cells
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7ATOM@", 7, m7_atom_memory_word, 0
    bl      m7_atom_bytes
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7DUR?", 6, m7_durability_word, 0
    bl      m7_durability_unknown
    str     x0, [DSP, #-8]!
    NEXT

// M7DFAULT ( after-bytes -- ) injects only the final TRI_DEPLOY superblock
// write. It is a trusted-lab durability witness, not an M7 service form.
defcode "M7DFAULT", 8, m7_deploy_fault_word, 0
    ldr     x1, [DSP], #8
    mov     x0, #4              // COLD_WRITE_SUPERBLOCK
    bl      cold_fault_set
    NEXT

defcode "M7DCLR", 6, m7_deploy_fault_clear_word, 0
    bl      cold_fault_clear
    NEXT

defcode "M7LROOT@", 8, m7_lifecycle_root_word, 0
    bl      kernel_m7_lifecycle_root_commits
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7LDEST@", 8, m7_lifecycle_destination_word, 0
    bl      kernel_m7_lifecycle_destination_commits
    str     x0, [DSP, #-8]!
    NEXT

// M7QSTORM ( count -- status ) runs bounded serial QUERY/CNF pairs and
// returns 0 only when PERSIST cells and atom-store bytes stayed exactly
// constant while cycling every published static QUERY result shape.
defcode "M7QSTORM", 8, m7_query_storm_word, 0
    ldr     x0, [DSP], #8
    bl      m7_test_query_storm
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7FORCE", 7, m7_force_word, 0
    bl      m7_force_stop
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

// M7CFAIL ( cells -- status ) is a trusted-lab fault injector for the closed
// lifecycle promotion witness.  -1 disables it.  It is not an M7 service or
// application ingress form.
defcode "M7CFAIL", 7, m7_copy_fail_word, 0
    ldr     x0, [DSP], #8
    bl      m7_test_copy_fail_after
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

// M7QFILL ( -- ) fills the bounded application FIFO with 256 inert test
// events.  It is retained solely for the M7 scheduler-priority QEMU witness.
defcode "M7QFILL", 7, m7_queue_fill_word, 0
    sub     sp, sp, #16
    mov     x1, #256
    str     x1, [sp]
1:  mov     x0, #0
    bl      evq_enq
    ldr     x1, [sp]
    subs    x1, x1, #1
    str     x1, [sp]
    cbnz    x1, 1b
    add     sp, sp, #16
    NEXT

defcode "M7RESET", 7, m7_reset_word, 0
    bl      m7_reset
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

// TRI_DEPLOY bridge: ( stage-id total digest -- st )
defcode "M7DBEG", 6, m7_deploy_begin_word, 0
    ldr     x2, [DSP], #8       // digest noun
    ldr     x1, [DSP], #8       // total
    ldr     x0, [DSP], #8       // stage id
    bl      m7_deploy_begin
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

// M7DCH ( stage-id offset address len -- st )
defcode "M7DCH", 5, m7_deploy_chunk_word, 0
    ldr     x3, [DSP], #8       // len
    ldr     x2, [DSP], #8       // source address
    ldr     x1, [DSP], #8       // offset
    ldr     x0, [DSP], #8       // stage id
    bl      m7_deploy_chunk
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7DSEAL", 7, m7_deploy_seal_word, 0
    bl      m7_deploy_seal
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7DACT", 6, m7_deploy_activate_word, 0
    bl      m7_deploy_activate
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7DQ", 4, m7_deploy_query_word, 0
    bl      m7_deploy_query
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7DABT", 6, m7_deploy_abort_word, 0
    bl      m7_deploy_abort
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7DIG", 5, m7_pill_digest_word, 0
    bl      m7_current_pill_digest
    str     x0, [DSP, #-8]!
    NEXT

defcode "M7DEMO", 6, m7_deploy_demo_word, 0
    bl      m7_deploy_demo
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

// Shared fixed-bank read-only observations, not process ingress. DOUT@ is the
// backend shadow; GPIOLEV@ is the independently read BCM2838 GPLEV0 value
// masked to 17/27/22.
defcode "DOUT@", 5, digital_out_shadow_word, 0
    bl      digital_out_shadow
    str     x0, [DSP, #-8]!
    NEXT

defcode "GPIOLEV@", 8, digital_out_level_word, 0
    bl      digital_out_gpio_level
    str     x0, [DSP, #-8]!
    NEXT

defcode "DOUTOPS", 7, digital_out_operations_word, 0
    bl      digital_out_operation_count
    str     x0, [DSP, #-8]!
    NEXT

defcode "DOUTSTATE", 9, digital_out_state_word, 0
    bl      digital_out_state
    str     x0, [DSP, #-8]!
    NEXT

#ifdef DIGITAL_OUT_FAKE
defcode "M6DO", 4, digital_out_fake_test_word, 0
    bl      digital_out_fake_selftest
    str     x0, [DSP, #-8]!
    NEXT
#endif

#ifdef DIGITAL_IN_FAKE
defcode "M8DIN!", 6, digital_in_fake_set_word, 0
    ldr     x0, [DSP]
    bl      digital_in_test_set_logical_bank
    sxtw    x0, w0
    str     x0, [DSP]
    NEXT

// Test-only failure ordinal for the exact fake bank reader.  It exposes no
// GPIO number, mask, register, or arbitrary MMIO surface.
defcode "M8DIF!", 6, digital_in_fake_fail_word, 0
    ldr     x0, [DSP], #8
    bl      digital_in_test_fail_read_at
    NEXT

#ifdef M8_EVIDENCE
defcode "M8IFSAFE", 8, m8_input_failure_safe_word, 0
    bl      kernel_m8_input_failure_safe_selftest
    str     x0, [DSP, #-8]!
    NEXT
#endif

defcode "M8DI", 4, digital_in_fake_test_word, 0
    bl      digital_in_fake_selftest
    str     x0, [DSP, #-8]!
    NEXT
#endif

defcode "M8DIC@", 6, digital_in_count_word, 0
    bl      digital_in_read_count
    str     x0, [DSP, #-8]!
    NEXT

#ifdef M8_EVIDENCE
// M8EXTT ( -- failures ) proves selector-3 denies a shaped external event.
defcode "M8EXTT", 6, m8_external_ingress_test_word, 0
    bl      kernel_m8_external_ingress_selftest
    str     x0, [DSP, #-8]!
    NEXT

// Closed-profile read-only diagnostic: bits 0/1 input/output initialized,
// 2 input pending, 3 freshness, 4 output pending, 5 desired, 6 host mirror.
defcode "M8SVC@", 6, m8_service_state_word, 0
    bl      kernel_m8_service_state
    str     x0, [DSP, #-8]!
    NEXT

defcode "M8ADMIT", 7, m8_profile_admission_test_word, 0
    bl      kernel_m8_profile_admission_selftest
    str     x0, [DSP, #-8]!
    NEXT

// M8CKT ( -- failures ) requires a running quiescent selector-3 gate.
// It rejects queue, full-token, and service-lifecycle corruption without
// changing the live checkpoint authority.
defcode "M8CKT", 5, m8_checkpoint_restore_test_word, 0
    bl      kernel_m8_checkpoint_restore_selftest
    str     x0, [DSP, #-8]!
    NEXT

// M8MAT ( -- failures ) executes the live Nock path for 8 controller states
// and all 32 target fake-input banks. It is an evidence-build probe only.
defcode "M8MAT", 5, m8_state_matrix_test_word, 0
    bl      kernel_m8_state_matrix_selftest
    str     x0, [DSP, #-8]!
    NEXT
#endif

// CKM2 ( -- failures ) requires M2PREP; transactional restore matrix.
defcode "CKM2", 4, ckpt_m2_test, 0
    bl      checkpoint_m2_selftest
    str     x0, [DSP, #-8]!
    NEXT

// M17CKT ( -- failures ) forges UINT=65536 in a scratch copy of the live
// ABI-1.4 gate and proves restore admission rejects it without live mutation.
defcode "M17CKT", 6, m17_typed_checkpoint_test_word, 0
    bl      kernel_m17_typed_checkpoint_selftest
    str     x0, [DSP, #-8]!
    NEXT

// ── I2 Milestone 3 bounded measurement surface ───────────────────────────
// RSTON/RSTOFF toggle the allocation-free fixed stats block.
// RSTCLR resets one run, preserving the enable state.
// M3RUN executes exactly n admitted I2 commits after M2PREP, then returns.
// M3STAT emits the single versioned post-run UART summary.

defcode "RSTON", 5, runtime_stats_on, 0
    mov     x0, #1
    bl      runtime_stats_enable
    NEXT

defcode "RSTOFF", 6, runtime_stats_off, 0
    mov     x0, #0
    bl      runtime_stats_enable
    NEXT

defcode "RSTCLR", 6, runtime_stats_clear, 0
    bl      runtime_stats_reset
    NEXT

defcode "M3STAT", 6, runtime_stats_output, 0
    bl      runtime_stats_emit
    NEXT

defcode "RSTM3", 5, runtime_stats_test, 0
    bl      runtime_stats_selftest
    str     x0, [DSP, #-8]!
    NEXT

#if defined(COLD_MEDIA_FAKE)
defcode "MEDB3", 5, cold_media_smoke, 0
    bl      cold_media_fake_smoketest
    str     x0, [DSP, #-8]!
    NEXT

defcode "MEDM3", 5, cold_media_test, 0
    bl      cold_media_fake_selftest
    str     x0, [DSP, #-8]!
    NEXT
#endif

defcode "QPM3", 4, queue_pressure_test, 0
    ldr     x0, [DSP]
    bl      kernel_queue_pressure_selftest
    str     x0, [DSP]
    NEXT

// QRETRY ( -- failures ) checks that a queued I2 event remains FIFO-visible
// through a failed preflight and is consumed only on an explicit dequeue.
defcode "QRETRY", 6, queue_retry_test, 0
    bl      kernel_queue_retry_selftest
    str     x0, [DSP, #-8]!
    NEXT

// I2LIMT ( -- failures ) validates the complete ten-field execution-limit noun.
defcode "I2LIMT", 6, i2_limit_shape_test, 0
    bl      kernel_i2_limit_shape_selftest
    str     x0, [DSP, #-8]!
    NEXT

#ifdef M8_EVIDENCE
// Exact target cell-limit witness: parser-selected live ceiling and an
// evaluator edge/overflow selftest using the production allocation wrapper.
defcode "I2CELL@", 7, i2_cell_limit_fetch, 0
    bl      slam_cell_budget_get
    str     x0, [DSP, #-8]!
    NEXT

defcode "I2CELLT", 7, i2_cell_limit_test, 0
    bl      nock_cell_budget_selftest
    str     x0, [DSP, #-8]!
    NEXT
#endif

defcode "NOVM3", 5, novel_atom_test, 0
    ldr     x0, [DSP]
    bl      runtime_stats_characterize_novel
    sxtw    x0, w0
    str     x0, [DSP]
    NEXT

defcode "M3RUN", 5, runtime_stats_run, 0
    ldr     x0, [DSP]
    bl      kernel_run_bounded
    sxtw    x0, w0
    str     x0, [DSP]
    NEXT

// Generic read-only I2 lab probes.  UINT64_MAX means missing/malformed.
// I2STATE ( instance-id -- state-id|-1 )
// I2OUT   ( instance-id variable-id -- direct-payload|-1 )
defcode "I2STATE", 7, i2_state_fetch, 0
    ldr     x0, [DSP]
    bl      kernel_i2_active_state
    str     x0, [DSP]
    NEXT

defcode "I2OUT", 5, i2_output_fetch, 0
    ldr     x1, [DSP], #8
    ldr     x0, [DSP]
    bl      kernel_i2_output_atom
    str     x0, [DSP]
    NEXT

defcode "KGATE!", 6, kgate_store, 0
    ldr     x0, [DSP], #8
    bl      shrine_gate_set
    NEXT

defcode "KGATE@", 6, kgate_fetch, 0
    bl      shrine_gate_get
    str     x0, [DSP, #-8]!
    NEXT

// ── Phase 6 — cooperative kernel hot-swap ─────────────────────────────────

// KVER@ ( -- u )  live kernel version
defcode "KVER@", 5, kver_fetch, 0
    bl      swap_live_version
    str     x0, [DSP, #-8]!
    NEXT

// PVER@ ( -- u )  version from last pill_load header (bytes 9-12)
defcode "PVER@", 5, pver_fetch, 0
    ldr     x0, =noun_pill_version
    ldr     w0, [x0]
    str     x0, [DSP, #-8]!
    NEXT

// STAGE ( noun shape ver -- )  stage a kernel swap (does not apply)
defcode "STAGE", 5, swap_stage_word, 0
    ldr     x2, [DSP], #8           // ver
    ldr     x1, [DSP], #8           // shape
    ldr     x0, [DSP], #8           // noun
    // swap_stage(kernel, shape, version): x0, x1, x2 — already correct
    bl      swap_stage
    NEXT

// HSWAP ( -- f )  request apply at safe point; true if applied now
defcode "HSWAP", 5, hswap_word, 0
    bl      swap_request
    cmp     x0, #0
    csetm   x0, ne
    str     x0, [DSP, #-8]!
    NEXT

// HSTAT ( -- n )  0=idle 1=staged 2=pending
defcode "HSTAT", 5, hstat_word, 0
    bl      swap_status
    str     x0, [DSP, #-8]!
    NEXT

// HCAN ( -- )  cancel staged/pending swap
defcode "HCAN", 4, hcan_word, 0
    bl      swap_cancel
    NEXT

// SAPPLY ( -- f )  try apply once (tests / manual safe-point)
defcode "SAPPLY", 6, sapply_word, 0
    bl      swap_apply_if_ready
    cmp     x0, #0
    csetm   x0, ne
    str     x0, [DSP, #-8]!
    NEXT

// ── Phase 7 — observability (trace / WDT / canary) ────────────────────────

// TON ( -- )  enable tracing
defcode "TON", 3, ton, 0
    mov     x0, #1
    bl      trace_enable
    NEXT

// TOFF ( -- )  disable tracing
defcode "TOFF", 4, toff, 0
    mov     x0, #0
    bl      trace_enable
    NEXT

// TCLR ( -- )  clear trace ring
defcode "TCLR", 4, tclr, 0
    bl      trace_clear
    NEXT

// TREC ( tag data -- )  manual record if enabled
defcode "TREC", 4, trec, 0
    ldr     x1, [DSP], #8           // data
    ldr     x0, [DSP], #8           // tag
    bl      trace_rec
    NEXT

// TLEN ( -- n )
defcode "TLEN", 4, tlen, 0
    bl      trace_len
    str     x0, [DSP, #-8]!
    NEXT

// TLAST@ ( -- tag data )  last record; 0 0 if empty
defcode "TLAST@", 6, tlast, 0
    sub     sp, sp, #16
    add     x0, sp, #0              // &tag
    add     x1, sp, #8              // &data
    bl      trace_last
    cbz     x0, 1f
    ldr     w2, [sp]                // tag
    ldr     w3, [sp, #8]            // data
    str     x2, [DSP, #-8]!
    str     x3, [DSP, #-8]!
    add     sp, sp, #16
    NEXT
1:  str     xzr, [DSP, #-8]!
    str     xzr, [DSP, #-8]!
    add     sp, sp, #16
    NEXT

// WDT! ( period -- )  set software WDT period in ticks; 0 = off
defcode "WDT!", 4, wdt_store, 0
    ldr     x0, [DSP], #8
    bl      wdt_set
    NEXT

// WDTK ( -- )  kick WDT
defcode "WDTK", 4, wdt_kick_word, 0
    bl      wdt_kick
    NEXT

// WDT? ( -- f )  true if expired (records T_WDT and re-kicks)
defcode "WDT?", 4, wdt_q, 0
    bl      wdt_check
    cmp     x0, #0
    csetm   x0, ne
    str     x0, [DSP, #-8]!
    NEXT

// CANARY? ( -- f )  stack canary intact?
defcode "CANARY?", 7, canary_q, 0
    bl      canary_ok
    cmp     x0, #0
    csetm   x0, ne
    str     x0, [DSP, #-8]!
    NEXT

// ── Phase 8 — networking stubs ────────────────────────────────────────────

// NLOOP ( f -- )  loopback on (-1) / off (0)
defcode "NLOOP", 5, nloop, 0
    ldr     x0, [DSP], #8
    cmp     x0, #0
    cset    x0, ne
    bl      net_set_loopback
    NEXT

// NSTAT ( fam -- n )  TX count; fam 0=eth 1=mb 2=can
defcode "NSTAT", 5, nstat, 0
    ldr     x0, [DSP]
    bl      net_stat_tx
    str     x0, [DSP]
    NEXT

// NRX@ ( fam -- n )  RX (loopback inject) count
defcode "NRX@", 4, nrx_fetch, 0
    ldr     x0, [DSP]
    bl      net_stat_rx
    str     x0, [DSP]
    NEXT

// NCLR ( -- )  clear net stats
defcode "NCLR", 4, nclr, 0
    bl      net_stats_clear
    NEXT

// ETX ( frame -- )  emit %etx effect via DO-FX path
defcode "ETX", 3, etx_word, 0
    ldr     x0, [DSP], #8
    bl      net_handle_etx
    NEXT

// MTX ( pdu -- )  emit %mtx
defcode "MTX", 3, mtx_word, 0
    ldr     x0, [DSP], #8
    bl      net_handle_mtx
    NEXT

// CTX ( id data -- )  emit %ctx with [id data]
defcode "CTX", 3, ctx_word, 0
    ldr     x1, [DSP], #8           // data
    ldr     x0, [DSP], #8           // id
    // alloc_cell(id, data) then net_handle_ctx
    bl      alloc_cell              // x0=head id, x1=tail data — AAPCS
    bl      net_handle_ctx
    NEXT

// ── Phase 2 — cooperative FIFO event queue ────────────────────────────────
// Queue lives in kernel.c (g_evq).  Head = next event.  ENQ appends.

// ENQ ( event -- )  append event noun to FIFO
defcode "ENQ", 3, enq, 0
    ldr     x0, [DSP], #8
    bl      evq_enq
    NEXT

// ENQL ( list -- )  append each element of a Nock list [e0 e1 ... 0]
defcode "ENQL", 4, enql, 0
    ldr     x0, [DSP], #8
    bl      evq_enq_list
    NEXT

// DEQ ( -- event true | false )
//   Pop head.  true = -1.  Empty → single 0.
defcode "DEQ", 3, deq, 0
    sub     sp, sp, #16
    mov     x0, sp
    bl      evq_deq                 // x0 = 1 if ok
    cbz     x0, 1f
    ldr     x1, [sp]                // event
    str     x1, [DSP, #-8]!
    mov     x0, #-1                 // true
    str     x0, [DSP, #-8]!
    add     sp, sp, #16
    NEXT
1:  str     xzr, [DSP, #-8]!        // false
    add     sp, sp, #16
    NEXT

// QPEEK ( -- event true | false )  look at head without removing
defcode "QPEEK", 5, qpeek, 0
    sub     sp, sp, #16
    mov     x0, sp
    bl      evq_peek
    cbz     x0, 1f
    ldr     x1, [sp]
    str     x1, [DSP, #-8]!
    mov     x0, #-1
    str     x0, [DSP, #-8]!
    add     sp, sp, #16
    NEXT
1:  str     xzr, [DSP, #-8]!
    add     sp, sp, #16
    NEXT

// QCLR ( -- )  empty the queue
defcode "QCLR", 4, qclr, 0
    bl      evq_clear
    NEXT

// QLEN ( -- n )  number of queued events
defcode "QLEN", 4, qlen, 0
    bl      evq_len
    str     x0, [DSP, #-8]!
    NEXT

// QCAP@ ( -- n )  event queue capacity (EVQ_CAP)
defcode "QCAP@", 5, qcap_fetch, 0
    bl      evq_cap
    str     x0, [DSP, #-8]!
    NEXT

// QHWM@ ( -- n )  high-water mark depth this session
defcode "QHWM@", 5, qhwm_fetch, 0
    bl      evq_hwm
    str     x0, [DSP, #-8]!
    NEXT

// QOVF@ ( -- n )  drop-newest overflow count
defcode "QOVF@", 5, qovf_fetch, 0
    bl      evq_overflows
    str     x0, [DSP, #-8]!
    NEXT

// QMETR ( -- )  reset overflow + hwm metrics
defcode "QMETR", 5, qmetr, 0
    bl      evq_metrics_reset
    NEXT

// SOFT! ( f -- )  crash policy: nonzero = soft (keep tarms on nock_crash)
defcode "SOFT!", 5, soft_store, 0
    ldr     x0, [DSP], #8
    bl      crash_soft_set
    NEXT

// SOFT? ( -- f )  true if soft crash policy
defcode "SOFT?", 5, soft_q, 0
    bl      crash_soft_get
    cmp     x0, #0
    csetm   x0, ne
    str     x0, [DSP, #-8]!
    NEXT

// CREC ( -- )  apply host crash recovery (same as kernel_loop nock_crash path)
defcode "CREC", 4, crec, 0
    bl      crash_recover_host
    NEXT

// ALOOP ( kernel -- )   Arvo-shaped kernel event loop, never returns
defcode "ALOOP", 5, arvo_loop_word, 0
    ldr     x0, [DSP], #8
    bl      arvo_loop               // kernel.c; never returns

// SLOOP ( kernel -- )   Shrine-shaped kernel event loop, never returns
defcode "SLOOP", 5, shrine_loop_word, 0
    ldr     x0, [DSP], #8
    bl      shrine_loop             // kernel.c; never returns

// ── Multi-arm timers (%tset / %tcan) — IEC host ────────────────────────────
// Effects %tset [id period] / %tcan id via DO-FX; TPOLL fires due arms into EVQ.

// TPOLL ( -- )  fire due multi-arm timers → enq [%ei id %TICK 0]
defcode "TPOLL", 5, tpoll, 0
    bl      tarm_poll
    NEXT

// TACLR ( -- )  disarm all multi-arm timers
defcode "TACLR", 5, taclr, 0
    bl      tarm_clear
    NEXT

// TACT? ( id -- f )  true (-1) if arm id is active
defcode "TACT?", 5, tact_q, 0
    ldr     x0, [DSP]
    bl      tarm_active
    cmp     x0, #0
    csetm   x0, ne
    str     x0, [DSP]
    NEXT

// TNXT@ ( id -- abs )  next fire deadline for arm id; 0 if inactive
defcode "TNXT@", 5, tnxt_fetch, 0
    ldr     x0, [DSP]
    bl      tarm_next
    str     x0, [DSP]
    NEXT

// TDUE ( id -- )  force arm due (next=now-1) for deterministic tests
defcode "TDUE", 4, tdue, 0
    ldr     x0, [DSP], #8
    bl      tarm_force_due
    NEXT

// BOOTPOL! ( n -- )  boot policy: 0=pill 1=snap|pill 2=snap-only
defcode "BOOTPOL!", 8, bootpol_store, 0
    ldr     x0, [DSP], #8
    bl      boot_policy_set
    NEXT

// BOOTPOL@ ( -- n )
defcode "BOOTPOL@", 8, bootpol_fetch, 0
    bl      boot_policy_get
    str     x0, [DSP, #-8]!
    NEXT

// NVON ( -- )         arm semihost checkpoint flushing without an eager flush
// NVFLUSH ( -- st )   arm + flush COLD_BASE → build/cold.img (needs semihosting)
defcode "NVON", 4, nvon_word, 0
    bl      cold_nv_arm
    NEXT

defcode "NVFLUSH", 7, nvflush_word, 0
    bl      cold_nv_arm
    bl      cold_nv_flush
    sxtw    x0, w0
    str     x0, [DSP, #-8]!
    NEXT

// KERNEL ( -- )
//   Load PILL, apply BOOTPOL (pill / snap-else-pill / snap-only), enter loop.
//   Falls back to QUIT if policy cannot boot.
defcode "KERNEL", 6, kernel, 0
    bl      kernel_pill_load        // x0 = decoded gate; strict PILL2 or I1
    // propagate C global noun_pill_shape → KSHAPE variable
    ldr     x1, =noun_pill_shape
    ldr     w1, [x1]                // 32-bit C int
    ldr     x2, =word_kshape + 32   // KSHAPE storage cell
    str     x1, [x2]
    cbz     x0, .Lkernel_nopill
    bl      kernel_boot             // never returns if boot ok; -1 → REPL
    b       code_quit
.Lkernel_nopill:
    mov     x0, #0                  // no pill gate
    bl      kernel_boot             // may still boot from snap
    b       code_quit

    .section .rodata
    .balign 8
trampoline_quit:
    .quad   word_quit_resume

// Trampoline for EVAL: after each word executes, NEXT dispatches here
// which jumps back to eval_word_loop.
trampoline_eval:
    .quad   word_eval_resume

// Fake dict entry + trampoline for forth_eval_string C return path.
    .balign 8
eval_return_entry:
    .quad   0                          // link = NULL (not in dict chain)
    .quad   0                          // flags|len = 0
    .quad   0                          // name = empty
    .quad   eval_return_code           // codeword → eval_return_code in .text
eval_return_trampoline:
    .quad   eval_return_entry

// Fake dictionary entry for the jet call return stub.
// Layout matches the standard header: link(8)+flags|len(8)+name(8)+codeword(8).
// Not in the dictionary chain (link=0); codeword points to jet_return_code.
    .balign 8
forth_jet_return:
    .quad   0                          // link = NULL
    .quad   0                          // flags|len = 0 (internal stub)
    .quad   0                          // name = empty
    .quad   jet_return_code            // codeword → jet_return_code in .text

// One-cell trampoline for forth_call_jet.
// NEXT loads forth_jet_return as W and dispatches to jet_return_code.
trampoline_jet:
    .quad   forth_jet_return

// ═════════════════════════════════════════════════════════════════════════════
// HELPER SUBROUTINES (called via BL, not NEXT — these are C-ABI helpers)
// ═════════════════════════════════════════════════════════════════════════════

// ─── BSS: mutable globals for forth_call_jet ─────────────────────────────────
    .bss
    .balign 8
jet_ctx_sp:     .skip 8                 // saved C stack pointer during forth_call_jet

// ─── BSS: mutable state for EVAL / forth_eval_string ─────────────────────────
    .balign 8
eval_tib_save:  .skip 256               // saved TIB contents
eval_ntib_save: .skip 8                 // saved #TIB
eval_toin_save: .skip 8                 // saved >IN
eval_ctx_sp:    .skip 8                 // saved C stack pointer during forth_eval_string

    .text
    .balign 4

// ─────────────────────────────────────────────────────────────────────────────
// dict_get_latest: return the current head of the dictionary chain.
// extern dict_entry_t *dict_get_latest(void);
// C ABI: no args, return in x0. Clobbers x1.
// ─────────────────────────────────────────────────────────────────────────────
    .global dict_get_latest
dict_get_latest:
    ldr     x1, =word_latest + 32
    ldr     x0, [x1]
    ret

// ─────────────────────────────────────────────────────────────────────────────
// find_by_cord: search Forth dictionary by label cord.
// extern dict_entry_t *find_by_cord(uint64_t cord);
//
// A cord is a LE-packed ASCII string. The dictionary name field (offset 16,
// 8 bytes, zero-padded) stores the same encoding, so a direct 64-bit compare
// matches both content and length in one instruction.
// Returns entry pointer on match, NULL if not found. Skips F_HIDDEN words.
// C ABI: arg in x0, return in x0. Clobbers x1-x3.
// ─────────────────────────────────────────────────────────────────────────────
    .global find_by_cord
find_by_cord:
    ldr     x1, =word_latest + 32
    ldr     x1, [x1]                    // x1 = head of dictionary chain
.Lfbc_loop:
    cbz     x1, .Lfbc_not_found
    ldr     x2, [x1, #8]               // flags|len
    tst     x2, #(F_HIDDEN << 8)
    b.ne    .Lfbc_next                  // skip hidden words
    ldr     x2, [x1, #16]              // name field (8 bytes LE == cord value)
    cmp     x2, x0
    b.eq    .Lfbc_found
.Lfbc_next:
    ldr     x1, [x1]                   // follow link pointer
    b       .Lfbc_loop
.Lfbc_not_found:
    mov     x0, #0
    ret
.Lfbc_found:
    mov     x0, x1
    ret

// ─────────────────────────────────────────────────────────────────────────────
// forth_call_jet: call a Forth dictionary word as a Nock jet.
// extern noun forth_call_jet(dict_entry_t *entry, noun core);
//
// Saves all C callee-saved registers and Forth machine registers (x19-x30)
// onto the C stack. Pushes core onto DSP. Sets W = entry, IP = trampoline_jet,
// then dispatches to the word's codeword via br (no return here).
//
// When the Forth word finishes, NEXT fires through trampoline_jet and lands in
// jet_return_code, which restores the C context from jet_ctx_sp and returns
// the top-of-stack result in x0 to the original C caller.
// ─────────────────────────────────────────────────────────────────────────────
    .global forth_call_jet
forth_call_jet:
    sub     sp, sp, #96
    stp     x19, x20, [sp, #0]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]        // x24 = W  (Forth)
    stp     x25, x26, [sp, #48]        // x25 = RSP, x26 = DSP  (Forth)
    stp     x27, x28, [sp, #64]        // x27 = IP  (Forth)
    stp     x29, x30, [sp, #80]        // frame pointer + link register

    ldr     x4, =jet_ctx_sp
    mov     x5, sp
    str     x5, [x4]                   // save C sp for jet_return_code

    str     x1, [DSP, #-8]!            // push core onto Forth data stack

    mov     W, x0                      // W = entry pointer
    ldr     x0, =trampoline_jet
    mov     IP, x0                     // IP points at trampoline_jet
    ldr     x0, [W, #24]               // load codeword
    br      x0                         // dispatch (does not return here)

// Codeword for forth_jet_return (the fake return-stub entry).
// Entered via NEXT when trampoline_jet dispatches forth_jet_return.
// Restores the full C context saved by forth_call_jet and returns result in x0.
jet_return_code:
    ldr     x1, =jet_ctx_sp
    ldr     x2, [x1]                   // restore saved C stack pointer
    mov     sp, x2
    ldr     x0, [DSP], #8             // pop result from Forth data stack
    ldp     x19, x20, [sp, #0]
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    ldp     x29, x30, [sp, #80]
    add     sp, sp, #96
    ret

// ─── forth_eval_string ────────────────────────────────────────────────────────
// extern int forth_eval_string(const char *src, size_t len);
//   Returns 0 on success; the error path longjmps to nock_abort (QUIT restart).
//
// This bridges from C into the Forth EVAL defcode.  We push (src, len) onto the
// Forth data stack, save all C callee-saved + Forth machine regs, set IP to
// eval_return_trampoline, and dispatch EVAL's codeword via `br` (not `blr`).
// EVAL's NEXT ultimately dispatches eval_return_code which restores everything.
// ─────────────────────────────────────────────────────────────────────────────
    .global forth_eval_string
    .type   forth_eval_string, @function
forth_eval_string:                      // x0 = src, x1 = len
    sub     sp, sp, #96
    stp     x19, x20, [sp, #0]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    ldr     x4, =eval_ctx_sp
    mov     x5, sp
    str     x5, [x4]                   // save C sp for eval_return_code

    // Push src (c-addr) then len (u) onto Forth data stack
    str     x0, [DSP, #-8]!            // c-addr
    str     x1, [DSP, #-8]!            // u  (TOS)

    // Set IP to point to eval_return_trampoline so that NEXT after EVAL returns
    // to eval_return_code.
    ldr     IP, =eval_return_trampoline

    // Dispatch EVAL's codeword (W = word_eval_word)
    ldr     W, =word_eval_word
    ldr     x0, [W, #24]
    br      x0

// Called by EVAL's NEXT at exhaustion when entered from forth_eval_string.
// Restores C context and returns 0.
eval_return_code:
    ldr     x1, =eval_ctx_sp
    ldr     x2, [x1]
    mov     sp, x2
    mov     x0, #0                     // success
    ldp     x19, x20, [sp, #0]
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    ldp     x29, x30, [sp, #80]
    add     sp, sp, #96
    ret

// printhex64 ( x0 = value ) — print 16 hex digits to UART
// Clobbers x0-x4. Uses standard C ABI (bl/ret).
printhex64:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    mov     x4, x0                     // value
    mov     x3, #60                    // bit shift start
1:  lsr     x0, x4, x3
    and     x0, x0, #0xF
    cmp     x0, #10
    blt     2f
    add     x0, x0, #('A' - 10)
    b       3f
2:  add     x0, x0, #'0'
3:  // emit char in w0
    ldr     x1, =UART_FR
4:  ldr     w2, [x1]
    tbnz    w2, #5, 4b
    ldr     x1, =UART_DR
    str     w0, [x1]
    subs    x3, x3, #4
    bge     1b
    ldp     x29, x30, [sp], #16
    ret

// puts_uart ( x0 = addr, x1 = len ) — write a string to UART
// Clobbers x0-x4.
puts_uart:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    cbz     x1, .Lputs_done
    mov     x4, x0                     // addr
    mov     x3, x1                     // len
.Lputs_loop:
    ldrb    w0, [x4], #1
    ldr     x1, =UART_FR
.Lputs_wait:
    ldr     w2, [x1]
    tbnz    w2, #5, .Lputs_wait
    ldr     x1, =UART_DR
    str     w0, [x1]
    subs    x3, x3, #1
    bne     .Lputs_loop
.Lputs_done:
    ldp     x29, x30, [sp], #16
    ret

// ═════════════════════════════════════════════════════════════════════════════
// STRING LITERALS
// ═════════════════════════════════════════════════════════════════════════════

    .section .rodata
    .balign 4

str_banner:
    .ascii  "\r\nTrinitite v0.1  AArch64 Forth\r\n"
str_banner_end:

str_ok:
    .ascii  " ok\r\n"
str_ok_end:

str_prompt:
    .ascii  "> "
str_prompt_end:

str_err:
    .ascii  " ?\r\n"
str_err_end:

str_eval_err:
    .asciz  "EVAL error\r\n"

// BENCH word source — compiled via forth_eval_string at boot.
// ( xt n -- cycles ): run xt n times, return elapsed CNTVCT_EL0 ticks.
str_bench_def:
    .ascii  ": BENCH TIMER@ ROT ROT BEGIN OVER EXECUTE 1 - DUP 0 = UNTIL DROP DROP TIMER@ SWAP - ;"
str_bench_def_end:

// W/DL ( xt rel -- )  WITH-DEADLINE: arm absolute = now+rel, run xt,
// emit %timeout on expiry, always disarm.
str_wdl_def:
    .ascii  ": W/DL TIMER@ + DL! EXECUTE TMOUT? IF ETOUT THEN 0 DL! ;"
str_wdl_def_end:

// IFILL ( -- )  push 63 codes into IRQ ring (fills to capacity).
str_ifill_def:
    .ascii  ": IFILL 0 BEGIN DUP 63 < WHILE DUP IRQP DROP 1+ REPEAT DROP ;"
str_ifill_def_end:

// BUSY ( -- )  short spin for multi-core tests (let secondaries run).
str_busy_def:
    .ascii  ": BUSY 0 BEGIN 1+ DUP 200000 = UNTIL DROP ;"
str_busy_def_end:

// MFILL ( -- )  fill core-1 mailbox to capacity (15 messages).
str_mfill_def:
    .ascii  ": MFILL 0 BEGIN DUP 15 < WHILE DUP 1 CSEND DROP 1+ REPEAT DROP ;"
str_mfill_def_end:

// ═════════════════════════════════════════════════════════════════════════════
// COLD START
// ═════════════════════════════════════════════════════════════════════════════
// The initial "program" — a list of word addresses that Forth executes.
// IP is set to cold_start before the first NEXT. NEXT loads word_quit,
// loads DOCOL (its codeword), and DOCOL sets IP to quit's body.
// But QUIT is a defcode (primitive), not a colon def, so we handle it
// specially: cold_start just holds quit's entry; NEXT loads its codeword
// (code_quit) and branches there directly.

    .balign 8
    .global cold_start
cold_start:
    .quad   word_quit

// ═════════════════════════════════════════════════════════════════════════════
// ENTRY POINT
// Called from main.c after UART init.
// Sets up VM registers, patches LATEST, prints banner, enters QUIT.
// ═════════════════════════════════════════════════════════════════════════════

    .text
    .balign 4
    .global forth_main
forth_main:
    // Callee-saved registers (we never return, but keep ABI clean)
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    // Initialize Forth VM registers
    ldr     DSP, =DSTACK_TOP            // data stack pointer
    ldr     RSP, =RSTACK_TOP            // return stack pointer

    // Patch LATEST to point at the last defword in the chain.
    // 'link' is the assembler symbol holding the last defined entry address.
    // We store it into LATEST's body at runtime.
    ldr     x0, =word_latest + 32       // address of LATEST's storage cell
    ldr     x1, =word_kernel        // last defined entry (see defcode order)
    str     x1, [x0]

    // Compile bootstrap words via forth_eval_string before entering QUIT.
    // BENCH: ( xt n -- cycles ) — execute xt n times, return elapsed CNTVCT ticks.
    ldr     x0, =str_bench_def
    ldr     x1, =str_bench_def_end
    sub     x1, x1, x0
    bl      forth_eval_string

    // W/DL: ( xt rel -- ) — run xt under a relative deadline
    ldr     x0, =str_wdl_def
    ldr     x1, =str_wdl_def_end
    sub     x1, x1, x0
    bl      forth_eval_string

    // IFILL: fill IRQ ring to capacity (63)
    ldr     x0, =str_ifill_def
    ldr     x1, =str_ifill_def_end
    sub     x1, x1, x0
    bl      forth_eval_string

    // BUSY / MFILL: multi-core test helpers
    ldr     x0, =str_busy_def
    ldr     x1, =str_busy_def_end
    sub     x1, x1, x0
    bl      forth_eval_string
    ldr     x0, =str_mfill_def
    ldr     x1, =str_mfill_def_end
    sub     x1, x1, x0
    bl      forth_eval_string

    // Print banner
    ldr     x0, =str_banner
    ldr     x1, =str_banner_end
    sub     x1, x1, x0
    bl      puts_uart

    // Set IP to cold_start and fire NEXT — enters QUIT
    ldr     IP, =cold_start
    NEXT

    // Never reached
    ldp     x29, x30, [sp], #16
    ret
