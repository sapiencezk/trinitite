#include <stddef.h>
#include "i2_operator.h"

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);

static int bytes_eq(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i])
            return 0;
    return 1;
}

static size_t cstr_len(const char *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}
#include "blake3.h"
#include "digital_out.h"
#include "i2_ingress.h"
#include "jam.h"
#include "kernel.h"
#include "m7_supervisor.h"
#include "runtime_identity.h"
#include "uart.h"
#include "cold.h"

#define OP_STATUS 1
#define OP_START 2
#define OP_STOP 3
#define OP_SNAPSHOT 4
#define OP_IBEGIN 5
#define OP_ICHUNK 6
#define OP_ISEAL 7
#define OP_IACT 8
#define OP_ISTATUS 9
#define OP_ICANCEL 10

#define RES_DONE 1
#define RES_REJECTED 2
#define RES_FAILED 3

#define INST_IDLE 0
#define INST_STAGING 1
#define INST_SEALED 2
#define INST_COMMITTED 3
#define INST_FAILED 4
#define INST_CANCELLED 5
#define INST_LEASE 6
#define INST_DURABILITY 7

#define FRAME_MAX (I2_FRAME_HEADER_SIZE + I2_OPERATOR_MAX_PAYLOAD)

static struct {
    int ready;
    int active;
    unsigned recovery;
    unsigned install_condition;
    uint64_t last_id;
    uint8_t last_content[32];
    uint8_t last_frame[FRAME_MAX];
    uint64_t last_frame_len;
    uint8_t tx[FRAME_MAX];
    uint64_t tx_len;
    uint64_t tx_off;
    uint64_t lease_deadline;
    uint64_t busy_drops;
    uint64_t now_override;
    uint64_t scheduler_ticks;
    uint8_t pending[FRAME_MAX];
    uint64_t pending_len;
    int mute_tx;
} g_op;

static uint64_t counter_now(void)
{
    if (g_op.now_override)
        return g_op.now_override;
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static uint64_t counter_freq(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v ? v : 54000000ULL;
}

static int take(noun n, noun *h, noun *t)
{
    if (!noun_is_cell(n) || !h || !t)
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *h = c->head;
    *t = c->tail;
    return 1;
}

static noun pair(noun a, noun b)
{
    noun out = NOUN_ZERO;
    return alloc_cell_checked(a, b, &out) ? out : NOUN_ZERO;
}

static int cord_is(noun n, const char *s)
{
    char buf[32];
    size_t want = 0;
    while (s[want]) want++;
    if (want >= sizeof buf)
        return 0;
    size_t got = cord_to_cstr(n, buf, sizeof buf);
    return got == want && bytes_eq(buf, s, want);
}

static int op_code(noun n)
{
    if (cord_is(n, "status")) return OP_STATUS;
    if (cord_is(n, "start")) return OP_START;
    if (cord_is(n, "stop")) return OP_STOP;
    if (cord_is(n, "snapshot")) return OP_SNAPSHOT;
    if (cord_is(n, "install-begin")) return OP_IBEGIN;
    if (cord_is(n, "install-chunk")) return OP_ICHUNK;
    if (cord_is(n, "install-seal")) return OP_ISEAL;
    if (cord_is(n, "install-activate")) return OP_IACT;
    if (cord_is(n, "install-status")) return OP_ISTATUS;
    if (cord_is(n, "install-cancel")) return OP_ICANCEL;
    return 0;
}

static noun digest_atom(const uint8_t bytes[32])
{
    uint64_t limbs[4];
    memcpy(limbs, bytes, 32);
    noun out = NOUN_ZERO;
    return make_atom_checked(limbs, 4, &out) ? out : NOUN_ZERO;
}

static int atom_bytes(noun n, uint8_t *out, size_t max, size_t *len)
{
    if (!out || !len || noun_is_cell(n))
        return 0;
    if (noun_is_direct(n)) {
        uint64_t v = direct_val(n);
        size_t nout = 0;
        do {
            if (nout >= max)
                return 0;
            out[nout++] = (uint8_t)(v & 0xff);
            v >>= 8;
        } while (v);
        *len = nout;
        return 1;
    }
    atom_t *a = atom_store_get(indirect_hash(n));
    if (!a)
        return 0;
    size_t bytes = (size_t)a->size * 8;
    while (bytes > 1 && ((const uint8_t *)a->limbs)[bytes - 1] == 0)
        bytes--;
    if (bytes > max)
        return 0;
    memcpy(out, a->limbs, bytes);
    *len = bytes;
    return 1;
}

static int direct_u64(noun n, uint64_t *out)
{
    if (!noun_is_direct(n) || !out)
        return 0;
    *out = direct_val(n);
    return 1;
}

void i2_operator_init(void)
{
    memset(&g_op, 0, sizeof g_op);
    g_op.ready = 1;
    g_op.recovery = 2;
}

void i2_operator_set_recovery(unsigned selected)
{
    g_op.recovery = selected;
}

unsigned i2_operator_recovery(void)
{
    return g_op.recovery;
}

int i2_operator_busy(void)
{
    return g_op.active || g_op.tx_len != 0;
}

int i2_operator_is_noun(noun n)
{
    noun tag, rest;
    return take(n, &tag, &rest) && cord_is(tag, "i2-operator");
}

static void expire_lease(void)
{
    if (!m7_stage_open() || !g_op.lease_deadline)
        return;
    if (counter_now() < g_op.lease_deadline)
        return;
    (void)m7_deploy_abort();
    g_op.install_condition = INST_LEASE;
    g_op.lease_deadline = 0;
}

static void touch_lease(void)
{
    uint64_t freq = counter_freq();
    g_op.lease_deadline = counter_now() + freq * I2_OPERATOR_LEASE_TICKS_SEC;
}

static int queue_frame(const uint8_t *frame, uint64_t len)
{
    if (!frame || len == 0 || len > FRAME_MAX)
        return 0;
    memcpy(g_op.tx, frame, (size_t)len);
    g_op.tx_len = len;
    g_op.tx_off = 0;
    g_op.active = 1;
    return 1;
}

static int tx_in_progress(void)
{
    return g_op.tx_len != 0 && g_op.tx_off < g_op.tx_len;
}

static int enqueue_or_send(const uint8_t *frame, uint64_t len)
{
    if (!frame || len == 0 || len > FRAME_MAX)
        return 0;
    if (tx_in_progress()) {
        if (g_op.pending_len)
            return 1;
        memcpy(g_op.pending, frame, (size_t)len);
        g_op.pending_len = len;
        return 1;
    }
    return queue_frame(frame, len);
}

static int encode_result_frame(uint64_t request_id, noun result, noun body,
                               uint8_t *out, uint64_t *out_len)
{
    noun cmd = pair(result, body);
    noun rest = pair(direct(request_id), cmd);
    noun ver = pair(direct(1), rest);
    noun noun_out = pair(cord_from_bytes("i2-operator", 11), ver);
    const uint8_t *jammed = 0;
    uint64_t jam_len = 0;
    uint8_t payload[I2_OPERATOR_MAX_PAYLOAD];
    if (!out || !out_len || !noun_is_cell(noun_out)
        || jam_encode_bytes_checked(noun_out, &jammed, &jam_len) != 0
        || jam_len == 0 || jam_len > I2_OPERATOR_MAX_PAYLOAD)
        return 0;
    memcpy(payload, jammed, (size_t)jam_len);
    return i2_frame_encode(payload, jam_len, out, FRAME_MAX, out_len);
}

static int finish(uint64_t request_id, const uint8_t content[32],
                  noun result, noun body)
{
    uint64_t frame_len = 0;
    if (!encode_result_frame(request_id, result, body, g_op.last_frame, &frame_len))
        return 0;
    g_op.last_frame_len = frame_len;
    g_op.last_id = request_id;
    memcpy(g_op.last_content, content, 32);
    return enqueue_or_send(g_op.last_frame, frame_len);
}

static int send_uncached(uint64_t request_id, noun result, noun body)
{
    uint8_t frame[FRAME_MAX];
    uint64_t frame_len = 0;
    if (!encode_result_frame(request_id, result, body, frame, &frame_len))
        return 0;
    return enqueue_or_send(frame, frame_len);
}

static noun reject_body(const char *reason)
{
    return pair(cord_from_bytes(reason, cstr_len(reason)), NOUN_ZERO);
}

static noun fail_body(const char *domain, uint64_t reason)
{
    return pair(cord_from_bytes(domain, cstr_len(domain)),
                pair(direct(reason), NOUN_ZERO));
}

static int outputs_inhibited(void)
{
    return (digital_out_state() & 2u) != 0 || m7_outputs_safe();
}

static noun status_body(void)
{
    uint8_t pkg[32] = {0};
    uint8_t stage[32] = {0};
    uint8_t anchor[32] = {0};
    const runtime_identity_t *id = runtime_identity_get();
    if (id)
        memcpy(anchor, id->package_hash, 32);
    (void)m7_copy_active_digest(pkg);
    (void)m7_copy_stage_digest(stage);
    unsigned inst = g_op.install_condition;
    if (m7_durability_unknown())
        inst = INST_DURABILITY;
    noun n = pair(direct(m7_persist_cells()), direct(m7_atom_bytes()));
    n = pair(direct(runtime_identity_capability_profile()), n);
    n = pair(direct(outputs_inhibited() ? 1 : 0), n);
    n = pair(direct(g_op.recovery), n);
    n = pair(digest_atom(stage), n);
    n = pair(direct(m7_stage_total()), n);
    n = pair(direct(m7_stage_received()), n);
    n = pair(direct(m7_stage_id()), n);
    n = pair(direct(inst), n);
    n = pair(direct(outputs_inhibited() ? 1 : 0), n);
    n = pair(direct(m7_last_status()), n);
    n = pair(digest_atom(anchor), n);
    n = pair(digest_atom(pkg), n);
    n = pair(direct(m7_incarnation()), n);
    n = pair(direct(m7_mode()), n);
    return n;
}

static int dispatch(int op, noun payload, noun *result, noun *body)
{
    if (!result || !body)
        return 0;
    *result = cord_from_bytes("done", 4);
    *body = NOUN_ZERO;
    if (op == OP_STATUS) {
        *body = status_body();
        return noun_is_cell(*body);
    }
    if (op == OP_START || op == OP_STOP) {
        g_op.active = 1;
        uint64_t cmd = op == OP_START ? 2 : 3;
        noun object = m7_object(M7_OBJECT_APPLICATION, 1);
        int receipt = m7_manager_request(cmd, object);
        if (receipt != M7_STATUS_RDY) {
            *result = cord_from_bytes("failed", 6);
            *body = fail_body("management", (uint64_t)(receipt < 0 ? 4 : receipt));
            return 1;
        }
        int cnf = m7_scheduler_boundary();
        if (cnf != M7_STATUS_RDY) {
            *result = cord_from_bytes("failed", 6);
            *body = fail_body("management", (uint64_t)(cnf < 0 ? 10 : cnf));
            return 1;
        }
        return 1;
    }
    if (op == OP_SNAPSHOT) {
        if (m7_checkpoint_save() != 0) {
            *result = cord_from_bytes("failed", 6);
            *body = fail_body("snapshot", 1);
            return 1;
        }
        if (cold_nv_enabled() && cold_nv_flush() != 0) {
            *result = cord_from_bytes("failed", 6);
            *body = fail_body("snapshot", 2);
            return 1;
        }
        return 1;
    }
    if (op == OP_IBEGIN) {
        noun stage_n, rest, total_n, digest_n;
        uint64_t stage_id, total;
        uint8_t digest[32];
        uint64_t mode = m7_mode();
        if ((mode != M7_MODE_IDLE && mode != M7_MODE_STOPPED)
            || !outputs_inhibited()) {
            *result = cord_from_bytes("rejected", 8);
            *body = reject_body("state");
            return 1;
        }
        if (!take(payload, &stage_n, &rest) || !take(rest, &total_n, &digest_n)
            || !direct_u64(stage_n, &stage_id) || !direct_u64(total_n, &total)
            || !noun_atom_read_fixed(digest_n, digest, 32) || stage_id == 0
            || total == 0 || total > 131066) {
            *result = cord_from_bytes("rejected", 8);
            *body = reject_body("bounds");
            return 1;
        }
        noun digest_atom_n = digest_n;
        int st = m7_deploy_begin(stage_id, total, digest_atom_n);
        if (st != 0) {
            *result = cord_from_bytes("failed", 6);
            *body = fail_body("installation", (uint64_t)(uint32_t)(-st));
            g_op.install_condition = INST_FAILED;
            return 1;
        }
        g_op.install_condition = INST_STAGING;
        touch_lease();
        return 1;
    }
    if (op == OP_ICHUNK) {
        noun stage_n, rest, offset_n, data_n;
        uint64_t stage_id, offset;
        uint8_t data[4096];
        size_t len = 0;
        if (!take(payload, &stage_n, &rest) || !take(rest, &offset_n, &data_n)
            || !direct_u64(stage_n, &stage_id) || !direct_u64(offset_n, &offset)
            || !atom_bytes(data_n, data, sizeof data, &len) || len == 0) {
            *result = cord_from_bytes("rejected", 8);
            *body = reject_body("bounds");
            return 1;
        }
        int st = m7_deploy_chunk(stage_id, offset, data, len);
        if (st != 0) {
            *result = cord_from_bytes("failed", 6);
            *body = fail_body("installation", (uint64_t)(uint32_t)(-st));
            g_op.install_condition = INST_FAILED;
            return 1;
        }
        g_op.install_condition = INST_STAGING;
        touch_lease();
        return 1;
    }
    if (op == OP_ISEAL) {
        int st = m7_deploy_seal();
        if (st != 0) {
            *result = cord_from_bytes("failed", 6);
            *body = fail_body("installation", (uint64_t)(uint32_t)(-st));
            g_op.install_condition = INST_FAILED;
            return 1;
        }
        g_op.install_condition = INST_SEALED;
        touch_lease();
        return 1;
    }
    if (op == OP_IACT) {
        int st = m7_deploy_activate();
        if (st != 0) {
            *result = cord_from_bytes("failed", 6);
            *body = fail_body("installation", (uint64_t)(uint32_t)(-st));
            if (st == -28)
                g_op.install_condition = INST_DURABILITY;
            else
                g_op.install_condition = INST_FAILED;
            return 1;
        }
        g_op.install_condition = INST_COMMITTED;
        g_op.lease_deadline = 0;
        return 1;
    }
    if (op == OP_ISTATUS) {
        uint8_t stage[32] = {0};
        (void)m7_copy_stage_digest(stage);
        *body = pair(direct(g_op.install_condition),
                     pair(direct(m7_stage_id()),
                          pair(direct(m7_stage_received()),
                               pair(direct(m7_stage_total()),
                                    digest_atom(stage)))));
        return 1;
    }
    if (op == OP_ICANCEL) {
        if (g_op.install_condition != INST_STAGING
            && g_op.install_condition != INST_SEALED) {
            *result = cord_from_bytes("rejected", 8);
            *body = reject_body("state");
            return 1;
        }
        (void)m7_deploy_abort();
        g_op.install_condition = INST_CANCELLED;
        g_op.lease_deadline = 0;
        return 1;
    }
    *result = cord_from_bytes("rejected", 8);
    *body = reject_body("protocol");
    return 1;
}

int i2_operator_handle(noun request)
{
    noun tag, rest, ver, rest2, rid_n, command, op_n, payload;
    uint64_t request_id;
    uint8_t content[32];
    expire_lease();
    if (!take(request, &tag, &rest) || !cord_is(tag, "i2-operator")
        || !take(rest, &ver, &rest2) || !noun_is_direct(ver)
        || direct_val(ver) != 1
        || !take(rest2, &rid_n, &command) || !direct_u64(rid_n, &request_id)
        || request_id == 0 || !take(command, &op_n, &payload)) {
        return 0;
    }
    {
        const uint8_t *jammed = 0;
        uint64_t jam_len = 0;
        if (jam_encode_bytes_checked(request, &jammed, &jam_len) != 0
            || jam_len == 0)
            return 0;
        blake3_hash(jammed, (size_t)jam_len, content);
    }
    if (noun_tx_active())
        noun_tx_commit();
    if (g_op.last_id == request_id
        && bytes_eq(g_op.last_content, content, 32)
        && g_op.last_frame_len) {
        if (tx_in_progress())
            return 1;
        return enqueue_or_send(g_op.last_frame, g_op.last_frame_len);
    }
    if (g_op.last_id == request_id
        && !bytes_eq(g_op.last_content, content, 32)) {
        return send_uncached(request_id,
                             cord_from_bytes("rejected", 8),
                             reject_body("conflict"));
    }
    if (g_op.active || tx_in_progress()) {
        g_op.busy_drops++;
        return send_uncached(request_id,
                             cord_from_bytes("rejected", 8),
                             reject_body("busy"));
    }
    int op = op_code(op_n);
    if (!op)
        return finish(request_id, content,
                      cord_from_bytes("rejected", 8), reject_body("protocol"));
    noun result = NOUN_ZERO, body = NOUN_ZERO;
    if (!dispatch(op, payload, &result, &body))
        return 0;
    return finish(request_id, content, result, body);
}

void i2_operator_poll(void)
{
    expire_lease();
    g_op.scheduler_ticks++;
    while (g_op.tx_off < g_op.tx_len) {
        if (g_op.mute_tx) {
            if (uart_test_tx_is_stuck())
                break;
            g_op.tx_off = g_op.tx_len;
            break;
        }
        if (!uart_putc_nb(g_op.tx[g_op.tx_off]))
            break;
        g_op.tx_off++;
    }
    if (g_op.tx_len && g_op.tx_off >= g_op.tx_len) {
        g_op.tx_len = 0;
        g_op.tx_off = 0;
        g_op.active = 0;
        if (g_op.pending_len) {
            (void)queue_frame(g_op.pending, g_op.pending_len);
            g_op.pending_len = 0;
        }
    }
}

uint64_t i2_operator_scheduler_ticks(void)
{
    return g_op.scheduler_ticks;
}

static noun test_request(uint64_t id, const char *op)
{
    noun cmd = pair(cord_from_bytes(op, cstr_len(op)), NOUN_ZERO);
    noun rest = pair(direct(id), cmd);
    noun ver = pair(direct(1), rest);
    return pair(cord_from_bytes("i2-operator", 11), ver);
}

uint64_t i2_operator_selftest(void)
{
    uint64_t failures = 0;
    i2_operator_init();
    g_op.mute_tx = 1;
    noun req = test_request(1, "status");
    if (!i2_operator_is_noun(req))
        failures++;
    if (!noun_is_cell(req) || !i2_operator_handle(req))
        failures++;
    uint64_t first_len = g_op.last_frame_len;
    if (first_len == 0)
        failures++;
    if (!i2_operator_handle(req) || g_op.last_frame_len != first_len)
        failures++;
    noun conflict = test_request(1, "start");
    if (!i2_operator_handle(conflict) || g_op.last_id != 1)
        failures++;
    if (g_op.last_frame_len != first_len)
        failures++;
    if (!i2_operator_handle(req) || g_op.last_frame_len != first_len)
        failures++;
    uart_test_tx_stuck(1);
    i2_operator_init();
    g_op.mute_tx = 1;
    req = test_request(3, "status");
    if (!i2_operator_handle(req))
        failures++;
    uint64_t ticks0 = g_op.scheduler_ticks;
    i2_operator_poll();
    if (g_op.tx_off != 0)
        failures++;
    noun busy_req = test_request(4, "status");
    if (!i2_operator_handle(busy_req) || g_op.pending_len == 0)
        failures++;
    if (g_op.tx_off != 0 || g_op.last_id != 3)
        failures++;
    uint64_t pending0 = g_op.pending_len;
    noun busy2 = test_request(5, "status");
    if (!i2_operator_handle(busy2) || g_op.pending_len != pending0)
        failures++;
    if (g_op.tx_off != 0 || g_op.last_id != 3)
        failures++;
    i2_operator_poll();
    i2_operator_poll();
    if (g_op.scheduler_ticks <= ticks0 || g_op.tx_off != 0)
        failures++;
    uart_test_tx_stuck(0);
    for (int i = 0; i < 16; i++)
        i2_operator_poll();
    if (g_op.tx_len != 0 || g_op.pending_len != 0)
        failures++;
    if (m7_ready()) {
        uint8_t zeros[32] = {0};
        if (m7_deploy_begin(1, 16, digest_atom(zeros)) == 0) {
            uart_test_tx_stuck(1);
            noun held = test_request(8, "status");
            if (!i2_operator_handle(held))
                failures++;
            g_op.lease_deadline = 1;
            g_op.now_override = 2;
            i2_operator_poll();
            if (g_op.install_condition != INST_LEASE || m7_stage_open())
                failures++;
            uart_test_tx_stuck(0);
            for (int i = 0; i < 16; i++)
                i2_operator_poll();
        }
        (void)m7_deploy_abort();
        if (m7_stage_id() || m7_stage_total())
            failures++;
    }
    uart_test_tx_stuck(0);
    g_op.tx_len = 0;
    g_op.tx_off = 0;
    g_op.pending_len = 0;
    g_op.active = 0;
    return failures;
}

uint64_t i2_operator_query_storm(uint64_t count)
{
    if (count == 0 || count > 10000 || !m7_ready())
        return 1;
    i2_operator_init();
    uint64_t cells = m7_persist_cells();
    uint64_t atoms = m7_atom_bytes();
    for (uint64_t i = 0; i < count; i++) {
        noun req = test_request(i + 1, "status");
        if (!noun_is_cell(req) || !i2_operator_handle(req))
            return 1;
        g_op.tx_len = 0;
        g_op.tx_off = 0;
        g_op.active = 0;
    }
    return (m7_persist_cells() == cells && m7_atom_bytes() == atoms) ? 0 : 1;
}

void i2_operator_boot(void)
{
    i2_operator_init();
    cold_nv_arm();
    boot_policy_set(BOOT_SNAP_ELSE_PILL);
    (void)kernel_boot(kernel_pill_load());
}
