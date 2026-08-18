#include "i2_closed_process.h"
#include "noun.h"

static i2_closed_process_roles_t g_roles;
static int g_roles_valid;

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail)
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head;
    *tail = c->tail;
    return 1;
}

static int name_is(noun tag, const char *name)
{
    char buf[32];
    size_t n = cord_to_cstr(tag, buf, sizeof buf);
    size_t m = 0;
    while (name[m])
        m++;
    if (n != m)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (buf[i] != name[i])
            return 0;
    return 1;
}

static int lib_for_type(noun fb_types, uint64_t wanted, noun *lib_out)
{
    for (unsigned n = 0; n < 32 && noun_is_cell(fb_types); n++) {
        noun entry, rest, ftid, body, kind, rest2, symbol, rest3, iface, libbody;
        if (!take(fb_types, &entry, &rest)
            || !take(entry, &ftid, &body)
            || !noun_is_direct(ftid))
            return 0;
        fb_types = rest;
        if (direct_val(ftid) != wanted)
            continue;
        if (!take(body, &kind, &rest2)
            || !take(rest2, &symbol, &rest3)
            || !take(rest3, &iface, &libbody))
            return 0;
        if (!name_is(kind, "sifb") && !name_is(kind, "efb"))
            return 0;
        noun lib;
        if (!take(libbody, &lib, &rest2))
            return 0;
        *lib_out = lib;
        return 1;
    }
    return 0;
}

int i2_closed_process_roles_from_program(
    noun program, i2_closed_process_roles_t *out)
{
    noun tag, rest, schema, rest2, types, rest3, fb_types, rest4;
    noun instances, rest5, conn, rest6, ext;
    if (!out || !take(program, &tag, &rest) || !name_is(tag, "i2-program")
        || !take(rest, &schema, &rest2)
        || !take(rest2, &types, &rest3)
        || !take(rest3, &fb_types, &rest4)
        || !take(rest4, &instances, &rest5)
        || !take(rest5, &conn, &rest6)
        || !take(rest6, &ext, &rest))
        return 0;
    if (ext != NOUN_ZERO && noun_is_cell(ext))
        return 0;
    uint64_t timer = 0, input = 0, output = 0;
    uint64_t seen[32];
    unsigned seen_n = 0;
    for (unsigned n = 0; n < 32 && noun_is_cell(instances); n++) {
        noun entry, more, iid_n, body, symbol, restb, ftid_n;
        if (!take(instances, &entry, &more)
            || !take(entry, &iid_n, &body)
            || !noun_is_direct(iid_n)
            || direct_val(iid_n) == 0
            || !take(body, &symbol, &restb)
            || !take(restb, &ftid_n, &restb)
            || !noun_is_direct(ftid_n))
            return 0;
        instances = more;
        uint64_t iid = direct_val(iid_n);
        for (unsigned s = 0; s < seen_n; s++)
            if (seen[s] == iid)
                return 0;
        if (seen_n >= 32)
            return 0;
        seen[seen_n++] = iid;
        noun lib;
        if (!lib_for_type(fb_types, direct_val(ftid_n), &lib))
            continue;
        if (name_is(lib, "E_DELAY")) {
            if (timer) return 0;
            timer = iid;
        } else if (name_is(lib, "TRI_DIGITAL_IN")) {
            if (input) return 0;
            input = iid;
        } else if (name_is(lib, "TRI_DIGITAL_OUT")) {
            if (output) return 0;
            output = iid;
        } else if (name_is(lib, "TRI_UART_OUT")) {
            return 0;
        } else if (name_is(lib, "E_RESTART") || name_is(lib, "SCAN_COORDINATOR")) {
            continue;
        } else {
            return 0;
        }
    }
    if (!timer || !input || !output || timer == input
        || timer == output || input == output)
        return 0;
    out->timer_owner = timer;
    out->input_bank_owner = input;
    out->output_bank_owner = output;
    return 1;
}

int i2_closed_process_roles_from_gate(
    noun gate, i2_closed_process_roles_t *out)
{
    noun battery, sample, axis, state, tag, rest, header, program, dynamic;
    if (!take(gate, &battery, &sample)
        || !take(sample, &axis, &state)
        || !noun_is_direct(axis) || direct_val(axis) != 0
        || !take(state, &tag, &rest)
        || !name_is(tag, "i2-state")
        || !take(rest, &header, &rest)
        || !take(rest, &program, &dynamic))
        return 0;
    return i2_closed_process_roles_from_program(program, out);
}

void i2_closed_process_roles_clear(void)
{
    g_roles = (i2_closed_process_roles_t){0};
    g_roles_valid = 0;
}

int i2_closed_process_roles_publish(const i2_closed_process_roles_t *roles)
{
    if (!roles || !roles->timer_owner || !roles->input_bank_owner
        || !roles->output_bank_owner
        || roles->timer_owner == roles->input_bank_owner
        || roles->timer_owner == roles->output_bank_owner
        || roles->input_bank_owner == roles->output_bank_owner)
        return 0;
    g_roles = *roles;
    g_roles_valid = 1;
    return 1;
}

int i2_closed_process_roles_live(i2_closed_process_roles_t *out)
{
    if (!g_roles_valid || !out)
        return 0;
    *out = g_roles;
    return 1;
}

int i2_closed_process_roles_refresh(noun gate)
{
    i2_closed_process_roles_t roles;
    if (!i2_closed_process_roles_from_gate(gate, &roles))
        return 0;
    return i2_closed_process_roles_publish(&roles);
}

int i2_closed_process_is_owner(uint64_t owner)
{
    return g_roles_valid
        && (owner == g_roles.timer_owner
            || owner == g_roles.input_bank_owner
            || owner == g_roles.output_bank_owner);
}

uint64_t i2_closed_process_selftest(void)
{
    uint64_t failures = 0;
    i2_closed_process_roles_t live;
    i2_closed_process_roles_t cell = {
        .timer_owner = 12, .input_bank_owner = 20, .output_bank_owner = 30
    };
    i2_closed_process_roles_t missing = {
        .timer_owner = 12, .input_bank_owner = 20, .output_bank_owner = 0
    };
    i2_closed_process_roles_t duplicate = {
        .timer_owner = 12, .input_bank_owner = 12, .output_bank_owner = 30
    };
    i2_closed_process_roles_t legacy = {
        .timer_owner = 3, .input_bank_owner = 4, .output_bank_owner = 7
    };

    i2_closed_process_roles_clear();
    if (i2_closed_process_roles_live(&live))
        failures++;
    if (!i2_closed_process_roles_publish(&cell)
        || !i2_closed_process_roles_live(&live)
        || live.timer_owner != 12
        || live.input_bank_owner != 20
        || live.output_bank_owner != 30)
        failures++;
    /* Refusals must not mutate the published owners or fall back to 3/4/7. */
    if (i2_closed_process_roles_publish(&missing)
        || i2_closed_process_roles_publish(&duplicate)
        || i2_closed_process_roles_publish(0)
        || !i2_closed_process_roles_live(&live)
        || live.timer_owner != 12
        || live.input_bank_owner != 20
        || live.output_bank_owner != 30
        || i2_closed_process_is_owner(3)
        || i2_closed_process_is_owner(4)
        || i2_closed_process_is_owner(7)
        || !i2_closed_process_is_owner(12)
        || !i2_closed_process_is_owner(20)
        || !i2_closed_process_is_owner(30))
        failures++;
    if (!i2_closed_process_roles_publish(&legacy)
        || !i2_closed_process_roles_live(&live)
        || live.timer_owner != 3)
        failures++;
    i2_closed_process_roles_clear();
    if (i2_closed_process_roles_live(&live) || i2_closed_process_is_owner(3))
        failures++;
    return failures;
}
