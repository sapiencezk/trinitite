/* M37-A target-side publication boundary.  M29 remains the owner of
 * commissioning and lifecycle sequencing; this file only validates the
 * candidate's compact binding projection and hands it to the isolated core. */
#include <stdint.h>

#include "m37_a_target_core.h"

#ifdef M37_A

#include "candidate_execution_core.h"
#include "i2_application_surface.h"
#include "m34_local_allocation.h"
#include "runtime_identity.h"

#define M37_A_PROFILE 3ULL
#define M37_A_WIRE_MAJOR 0ULL
#define M37_A_WIRE_MINOR 2ULL
#define M37_A_KEY_ID 3ULL
#define M37_A_EPOCH 1ULL
#define M37_A_MAX_OPS 2000000ULL
#define M37_A_MAX_CELLS 128000ULL

static const uint8_t M37_A_SCHEMA[32] = {
    0x1c,0x23,0xe8,0x41,0x4c,0x1b,0x98,0x53,
    0x0d,0x58,0x45,0x3c,0x1a,0x90,0xc3,0x39,
    0x28,0xa4,0x5b,0xec,0x9b,0xd7,0xff,0xd1,
    0x05,0x54,0xd3,0x3b,0x22,0x3e,0x30,0x98,
};
static const uint8_t M37_A_DOMAIN[32] = {
    0x20,0x69,0x15,0x23,0xfb,0x3b,0xa7,0xaa,
    0x03,0x30,0x79,0xb7,0xff,0x21,0x78,0x6a,
    0xf4,0xc1,0xae,0xe9,0x2d,0x0f,0xde,0x1a,
    0x6e,0x56,0x0f,0xb9,0xd3,0x52,0x91,0xb6,
};

static candidate_execution_prepared_t g_prepared;
static uint8_t g_prepared_valid;

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail) return 0;
    cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = cell->head; *tail = cell->tail; return 1;
}

static int direct_is(noun n, uint64_t value)
{
    return noun_is_direct(n) && direct_val(n) == value;
}

static int fixed_atom(noun n, uint8_t *out, unsigned length)
{
    return out && noun_atom_read_fixed(n, out, length);
}

static int nonzero_bytes(const uint8_t *bytes, unsigned length)
{
    uint8_t value = 0;
    for (unsigned i = 0; i < length; i++) value |= bytes[i];
    return value != 0;
}

static int resource_id(noun gate, uint64_t *out)
{
    noun battery, sample, zero, state, tag, rest, header, dynamic;
    noun versions, rid;
    return take(gate, &battery, &sample) && take(sample, &zero, &state)
        && direct_is(zero, 0) && take(state, &tag, &rest)
        && take(rest, &header, &dynamic) && take(header, &versions, &rest)
        && take(rest, &rid, &rest) && noun_is_direct(rid)
        && out && (*out = direct_val(rid), 1);
}

static int parse_binding(noun binding_noun, m37_a_transport_binding_t *binding)
{
    noun tag, rest, item;
    uint64_t *direct_fields;
    uint8_t *byte_fields[4];
    if (!binding || !take(binding_noun, &tag, &rest)
        || !i2_application_surface_tag_matches(
            tag, "m37-a-transport-binding-v1",
            (uint32_t)(sizeof "m37-a-transport-binding-v1" - 1u))) return 0;
    direct_fields = &binding->local_device;
    for (unsigned i = 0; i < 12; i++) {
        if (!take(rest, &item, &rest) || !noun_is_direct(item)) return 0;
        direct_fields[i] = direct_val(item);
    }
    byte_fields[0] = binding->outbound_binding;
    byte_fields[1] = binding->inbound_binding;
    byte_fields[2] = binding->schema_digest;
    byte_fields[3] = binding->domain_digest;
    for (unsigned i = 0; i < 4; i++)
        if (!take(rest, &item, &rest) || !fixed_atom(item, byte_fields[i], i < 2 ? 16u : 32u)) return 0;
    for (unsigned i = 0; i < CANDIDATE_EXECUTION_DESCRIPTOR_FIELDS; i++) {
        if (!take(rest, &item, &rest) || !noun_is_direct(item)) return 0;
        binding->peer_descriptor[i] = direct_val(item);
    }
    return direct_is(rest, 0);
}

static int binding_valid(const m37_a_transport_binding_t *binding)
{
    if (!binding) return 0;
    if (binding->local_device != (uint64_t)M24_NODE_ID
        || binding->peer_device == binding->local_device
        || (binding->local_device != 11 && binding->local_device != 22)
        || binding->peer_device != (binding->local_device == 11 ? 22 : 11)
        || binding->profile != M37_A_PROFILE
        || binding->wire_major != M37_A_WIRE_MAJOR
        || binding->wire_minor != M37_A_WIRE_MINOR
        || binding->key_id != M37_A_KEY_ID || binding->epoch != M37_A_EPOCH
        || binding->max_payload != M37_A_MAX_PAYLOAD
        || binding->max_ops != M37_A_MAX_OPS || binding->max_cells != M37_A_MAX_CELLS
        || binding->local_port != (binding->local_device == 11 ? 25911 : 25922)
        || binding->peer_port != (binding->peer_device == 11 ? 25911 : 25922)
        || !nonzero_bytes(binding->outbound_binding, 16)
        || !nonzero_bytes(binding->inbound_binding, 16)) {
        return 0;
    }
    for (unsigned i = 0; i < 32; i++)
        if (binding->schema_digest[i] != M37_A_SCHEMA[i]) {
            return 0;
        }
    for (unsigned i = 0; i < 32; i++)
        if (binding->domain_digest[i] != M37_A_DOMAIN[i]) {
            return 0;
        }
    for (unsigned i = 0; i < CANDIDATE_EXECUTION_DESCRIPTOR_FIELDS; i++)
        if (binding->peer_descriptor[i] == 0) {
            return 0;
        }
    return 1;
}

static int surface_from_gate(noun gate, NativeExecutionSurface *out)
{
    i2_application_service_surface_t application;
    noun ignored, state, tag, rest, program, dynamic, tables, exports, services;
    noun source_hash, binding_noun;
    if (!out || !i2_application_surface_from_gate(gate, &application)
        || application.publication_count != 1 || application.ingress.sample_count != 1
        || application.ingress.sample_type[0] != 1
        || !take(gate, &ignored, &rest) || !take(rest, &ignored, &state)
        || !take(state, &tag, &rest) || !take(rest, &ignored, &rest)
        || !take(rest, &program, &dynamic) || !take(program, &tag, &rest)
        || !take(rest, &ignored, &tables) || !take(tables, &ignored, &tables)
        || !take(tables, &ignored, &tables) || !take(tables, &ignored, &tables)
        || !take(tables, &exports, &services) || !take(exports, &source_hash, &binding_noun)) return 0;
    (void)source_hash; (void)services;
    m37_a_transport_binding_t binding;
    if (!parse_binding(binding_noun, &binding)) {
        return 0;
    }
    if (!binding_valid(&binding)) {
        return 0;
    }
    for (unsigned i = 0; i < sizeof *out; i++) ((uint8_t *)out)[i] = 0;
    out->binding = binding;
    const i2_publication_attachment_t *publication = &application.publications[0];
    const uint64_t fields[11] = {
        publication->source_instance, publication->source_event, publication->source_ordinal,
        publication->source_data, publication->source_type, publication->source_service,
        publication->target_service, publication->target_instance, publication->target_event,
        publication->target_data, publication->target_type,
    };
    for (unsigned i = 0; i < 11; i++) out->publication[i] = fields[i];
    out->ingress_instance = application.ingress.instance;
    out->ingress_event = application.ingress.event;
    out->ingress_sample = application.ingress.sample_id[0];
    out->ingress_type = application.ingress.sample_type[0];
    out->route_count = application.event_edge_count;
    if (out->route_count == 0 || out->route_count > CANDIDATE_EXECUTION_ROUTE_CAPACITY) return 0;
    for (uint32_t i = 0; i < application.event_edge_count; i++) {
        out->routes[i][0] = application.event_edges[i].ordinal;
        out->routes[i][1] = application.event_edges[i].source_instance;
        out->routes[i][2] = application.event_edges[i].source_event;
        out->routes[i][3] = application.event_edges[i].target_instance;
        out->routes[i][4] = application.event_edges[i].target_event;
    }
    return 1;
}

int m37_target_boot(noun gate, const runtime_identity_t *identity,
                    uint8_t capability_profile)
{
    uint64_t rid;
    if (!identity || capability_profile != RUNTIME_CAPABILITY_PROFILE_M25
        || identity->runtime_abi[0] != 1 || identity->runtime_abi[1] != 9
        || identity->host_abi[0] != 1 || identity->host_abi[1] != 3
        || !runtime_identity_validate_gate(gate, identity, 0)
        || !resource_id(gate, &rid)
        || !m34_local_allocation_matches((uint64_t)M24_NODE_ID, rid,
                                         M24_NODE_ID == 11 ? 1 : 2)
        || !m34_local_allocation_predecessor_matches(identity)) return -1;
    return 0;
}

int m37_target_prepare_gate(noun gate, const runtime_identity_t *identity,
                            uint8_t capability_profile, noun *out)
{
    NativeExecutionSurface surface;
    if (!out || capability_profile != RUNTIME_CAPABILITY_PROFILE_M25
        || !surface_from_gate(gate, &surface)) {
        g_prepared_valid = 0; return -1;
    }
    if (candidate_execution_core_prepare(&surface, gate, identity, &g_prepared) != 0) {
        g_prepared_valid = 0; return -1;
    }
    g_prepared_valid = 1; *out = gate; return 0;
}

void m37_target_publish_gate(noun gate, const runtime_identity_t *identity,
                             uint8_t capability_profile)
{
    (void)identity; (void)capability_profile;
    if (!g_prepared_valid || gate != g_prepared.gate) return;
    if (candidate_execution_core_activate(&g_prepared) == 0) g_prepared_valid = 0;
}

int m37_target_init(void) { return candidate_execution_core_init(); }
int m37_target_set_running(int running) { return candidate_execution_core_set_running(running); }
int m37_target_input(uint64_t value)
{
    candidate_execution_ingress_t ingress = { 1, value };
    return candidate_execution_core_submit(&ingress);
}
int m37_target_service_tick(void) { return candidate_execution_core_pump(); }
uint64_t m37_target_queue_len(void) { return candidate_execution_core_queue_len(); }
uint64_t m37_target_output(void) { return candidate_execution_core_output(); }
uint64_t m37_target_sequence(void) { return candidate_execution_core_sequence(); }
uint64_t m37_target_high_water(void) { return candidate_execution_core_high_water(); }
uint64_t m37_target_error(void) { return candidate_execution_core_error(); }
uint64_t m37_target_root_commits(void) { return candidate_execution_core_root_commits(); }
uint64_t m37_target_publications(void) { return candidate_execution_core_publications(); }
int m37_target_test_hold_processing(int enabled)
{ return candidate_execution_core_test_hold_processing(enabled); }
int m37_target_test_clear_error(void)
{ return candidate_execution_core_test_clear_error(); }
int m37_target_test_rate_exhaust(void)
{ return candidate_execution_core_test_rate_exhaust(); }
int m37_target_test_rate_reset(void)
{ return candidate_execution_core_test_rate_reset(); }
int m37_target_test_allocation_pressure(void)
{ return candidate_execution_core_test_allocation_pressure(); }
int m37_target_test_allocation_release(void)
{ return candidate_execution_core_test_allocation_release(); }

#else

int m37_target_boot(noun gate, const runtime_identity_t *identity, uint8_t capability_profile)
{ (void)gate; (void)identity; (void)capability_profile; return -1; }
int m37_target_init(void) { return -1; }
int m37_target_set_running(int running) { (void)running; return -1; }
int m37_target_input(uint64_t value) { (void)value; return -1; }
int m37_target_service_tick(void) { return 0; }
int m37_target_prepare_gate(noun gate, const runtime_identity_t *identity,
                            uint8_t capability_profile, noun *out)
{ (void)gate; (void)identity; (void)capability_profile; (void)out; return -1; }
void m37_target_publish_gate(noun gate, const runtime_identity_t *identity,
                             uint8_t capability_profile)
{ (void)gate; (void)identity; (void)capability_profile; }
uint64_t m37_target_queue_len(void) { return UINT64_MAX; }
uint64_t m37_target_output(void) { return UINT64_MAX; }
uint64_t m37_target_sequence(void) { return 0; }
uint64_t m37_target_high_water(void) { return 0; }
uint64_t m37_target_error(void) { return 0; }
uint64_t m37_target_root_commits(void) { return 0; }
uint64_t m37_target_publications(void) { return 0; }
int m37_target_test_hold_processing(int enabled) { (void)enabled; return -1; }
int m37_target_test_clear_error(void) { return -1; }
int m37_target_test_rate_exhaust(void) { return -1; }
int m37_target_test_rate_reset(void) { return -1; }
int m37_target_test_allocation_pressure(void) { return -1; }
int m37_target_test_allocation_release(void) { return -1; }

#endif
