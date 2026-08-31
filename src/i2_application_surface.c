#include "i2_application_surface.h"

#include "noun.h"

#define SURFACE_MAX_TYPES 16u
#define SURFACE_MAX_FB_TYPES 16u
#define SURFACE_MAX_INSTANCES 4u
#define SURFACE_MAX_EVENTS 8u
#define SURFACE_MAX_VARS 8u
#define SURFACE_MAX_EVENT_EDGES I2_SURFACE_MAX_EVENT_EDGES
#define SURFACE_MAX_DATA_EDGES 8u

typedef struct {
    uint64_t id;
    uint32_t with_count;
    uint64_t with_vars[SURFACE_MAX_VARS];
} surface_event_t;

typedef struct {
    uint64_t id;
    uint64_t type;
} surface_var_t;

typedef struct {
    uint64_t id;
    uint32_t event_input_count;
    uint32_t event_output_count;
    uint32_t data_input_count;
    uint32_t data_output_count;
    surface_event_t event_inputs[SURFACE_MAX_EVENTS];
    surface_event_t event_outputs[SURFACE_MAX_EVENTS];
    surface_var_t data_inputs[SURFACE_MAX_VARS];
    surface_var_t data_outputs[SURFACE_MAX_VARS];
} surface_fb_t;

typedef struct {
    uint64_t id;
    uint64_t fb_type;
} surface_instance_t;

typedef struct {
    uint64_t ordinal;
    uint64_t source_instance;
    uint64_t source_event;
    uint64_t target_instance;
    uint64_t target_event;
} surface_event_edge_t;

typedef struct {
    uint64_t source_instance;
    uint64_t source_data;
    uint64_t target_instance;
    uint64_t target_data;
} surface_data_edge_t;

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail) return 0;
    cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = cell->head; *tail = cell->tail;
    return 1;
}

static int same_bytes(const uint8_t *a, const uint8_t *b, uint32_t length)
{
    uint8_t different = 0;
    for (uint32_t i = 0; i < length; i++) different |= a[i] ^ b[i];
    return different == 0;
}

static int positive(noun n, uint64_t *out)
{
    if (!noun_is_direct(n) || direct_val(n) == 0) return 0;
    if (out) *out = direct_val(n);
    return 1;
}

static int fixed_positive_fields(noun entry, uint64_t *fields, unsigned count)
{
    noun rest = entry, value;
    if (!fields || count == 0) return 0;
    for (unsigned i = 0; i + 1 < count; i++) {
        if (!take(rest, &value, &rest) || !positive(value, &fields[i])) return 0;
    }
    return positive(rest, &fields[count - 1]);
}

int i2_application_surface_tag_matches(noun tag, const char *text,
                                       uint32_t length)
{
    uint8_t bytes[32];
    if (!text || length > sizeof bytes
        || !noun_atom_read_fixed(tag, bytes, length)) return 0;
    for (uint32_t i = 0; i < length; i++)
        if (bytes[i] != (uint8_t)text[i]) return 0;
    return 1;
}

static int tag_is(noun tag, const char *text, uint32_t length)
{
    return i2_application_surface_tag_matches(tag, text, length);
}

static int wrapper_tag(noun tag)
{
    return tag_is(tag, "i2-resource-program-v1", 23)
        || tag_is(tag, "i2-m26-program", 14)
        || tag_is(tag, "i2-m27-program", 14)
        || tag_is(tag, "i2-m28-program", 14)
        || tag_is(tag, "i2-m25-program", 14);
}

static int parse_with_list(noun list, surface_event_t *event)
{
    event->with_count = 0;
    while (!noun_is_direct(list) || direct_val(list) != 0) {
        noun value, rest;
        uint64_t id;
        if (!take(list, &value, &list) || !positive(value, &id)
            || event->with_count >= SURFACE_MAX_VARS) return 0;
        for (uint32_t i = 0; i < event->with_count; i++)
            if (event->with_vars[i] == id) return 0;
        event->with_vars[event->with_count++] = id;
        (void)rest;
    }
    return 1;
}

static int parse_events(noun list, surface_event_t *events, uint32_t *count)
{
    *count = 0;
    while (!noun_is_direct(list) || direct_val(list) != 0) {
        noun entry, body, symbol, with;
        uint64_t id;
        if (*count >= SURFACE_MAX_EVENTS || !take(list, &entry, &list)
            || !take(entry, &body, &entry) || !positive(body, &id)
            || !take(entry, &symbol, &with) || !parse_with_list(with, &events[*count])) return 0;
        for (uint32_t i = 0; i < *count; i++)
            if (events[i].id == id) return 0;
        events[*count].id = id;
        (*count)++;
        (void)symbol;
    }
    return 1;
}

static int parse_vars(noun list, surface_var_t *vars, uint32_t *count)
{
    *count = 0;
    while (!noun_is_direct(list) || direct_val(list) != 0) {
        noun entry, body, symbol, type, initial;
        uint64_t id, type_id;
        if (*count >= SURFACE_MAX_VARS || !take(list, &entry, &list)
            || !take(entry, &body, &entry) || !positive(body, &id)
            || !take(entry, &symbol, &body) || !take(body, &type, &initial)
            || !positive(type, &type_id)) return 0;
        for (uint32_t i = 0; i < *count; i++)
            if (vars[i].id == id) return 0;
        vars[*count].id = id; vars[*count].type = type_id; (*count)++;
        (void)symbol; (void)initial;
    }
    return 1;
}

static int parse_fb_types(noun list, surface_fb_t *fbs, uint32_t *count)
{
    *count = 0;
    while (!noun_is_direct(list) || direct_val(list) != 0) {
        noun entry, descriptor, kind, rest, symbol, interface, body;
        noun event_inputs, event_outputs, data_inputs, data_outputs;
        uint64_t id;
        if (*count >= SURFACE_MAX_FB_TYPES || !take(list, &entry, &list)
            || !take(entry, &id, &descriptor) || !positive(id, &id)
            || !take(descriptor, &kind, &rest)
            || !take(rest, &symbol, &rest) || !take(rest, &interface, &body)
            || !take(interface, &event_inputs, &rest)
            || !take(rest, &event_outputs, &rest)
            || !take(rest, &data_inputs, &data_outputs)
            || !parse_events(event_inputs, fbs[*count].event_inputs,
                             &fbs[*count].event_input_count)
            || !parse_events(event_outputs, fbs[*count].event_outputs,
                             &fbs[*count].event_output_count)
            || !parse_vars(data_inputs, fbs[*count].data_inputs,
                           &fbs[*count].data_input_count)
            || !parse_vars(data_outputs, fbs[*count].data_outputs,
                           &fbs[*count].data_output_count)) return 0;
        for (uint32_t i = 0; i < *count; i++)
            if (fbs[i].id == id) return 0;
        fbs[*count].id = id;
        (*count)++;
        (void)body; (void)kind; (void)symbol;
    }
    return 1;
}

static int type_id_seen(const uint64_t *ids, uint32_t count, uint64_t id)
{
    for (uint32_t i = 0; i < count; i++) if (ids[i] == id) return 1;
    return 0;
}

static int parse_instances(noun list, surface_instance_t *instances, uint32_t *count)
{
    *count = 0;
    while (!noun_is_direct(list) || direct_val(list) != 0) {
        noun entry, body, symbol, type, parameters;
        uint64_t id, type_id;
        if (*count >= SURFACE_MAX_INSTANCES || !take(list, &entry, &list)
            || !take(entry, &body, &entry) || !positive(body, &id)
            || !take(entry, &symbol, &body) || !take(body, &type, &parameters)
            || !positive(type, &type_id)) return 0;
        for (uint32_t i = 0; i < *count; i++)
            if (instances[i].id == id) return 0;
        instances[*count].id = id; instances[*count].fb_type = type_id;
        (*count)++;
        (void)symbol; (void)parameters;
    }
    return 1;
}

static int parse_event_edges(noun list, surface_event_edge_t *edges, uint32_t *count)
{
    *count = 0;
    while (!noun_is_direct(list) || direct_val(list) != 0) {
        noun entry;
        uint64_t fields[5];
        if (*count >= SURFACE_MAX_EVENT_EDGES || !take(list, &entry, &list)) return 0;
        if (!fixed_positive_fields(entry, fields, 5)) return 0;
        for (uint32_t i = 0; i < *count; i++) {
            if (edges[i].ordinal == fields[0]
                || (edges[i].source_instance == fields[1]
                    && edges[i].source_event == fields[2]
                    && edges[i].target_instance == fields[3]
                    && edges[i].target_event == fields[4])) return 0;
        }
        edges[*count].ordinal = fields[0]; edges[*count].source_instance = fields[1];
        edges[*count].source_event = fields[2]; edges[*count].target_instance = fields[3];
        edges[*count].target_event = fields[4]; (*count)++;
    }
    return 1;
}

static int parse_data_edges(noun list, surface_data_edge_t *edges, uint32_t *count)
{
    *count = 0;
    while (!noun_is_direct(list) || direct_val(list) != 0) {
        noun entry;
        uint64_t fields[4];
        if (*count >= SURFACE_MAX_DATA_EDGES || !take(list, &entry, &list)) return 0;
        if (!fixed_positive_fields(entry, fields, 4)) return 0;
        for (uint32_t i = 0; i < *count; i++)
            if (edges[i].source_instance == fields[0] && edges[i].source_data == fields[1]
                && edges[i].target_instance == fields[2]
                && edges[i].target_data == fields[3]) return 0;
        edges[*count].source_instance = fields[0]; edges[*count].source_data = fields[1];
        edges[*count].target_instance = fields[2]; edges[*count].target_data = fields[3];
        (*count)++;
    }
    return 1;
}

static int parse_publications(noun list, i2_application_service_surface_t *surface)
{
    surface->publication_count = 0;
    while (!noun_is_direct(list) || direct_val(list) != 0) {
        noun entry;
        uint64_t fields[11];
        if (surface->publication_count >= I2_SURFACE_MAX_PUBLICATIONS
            || !take(list, &entry, &list)) return 0;
        if (!fixed_positive_fields(entry, fields, 11)) return 0;
        i2_publication_attachment_t *p =
            &surface->publications[surface->publication_count];
        p->source_instance = fields[0]; p->source_event = fields[1];
        p->source_ordinal = fields[2]; p->source_data = fields[3];
        p->source_type = fields[4]; p->source_service = fields[5];
        p->target_service = fields[6]; p->target_instance = fields[7];
        p->target_event = fields[8]; p->target_data = fields[9];
        p->target_type = fields[10];
        for (uint32_t i = 0; i < surface->publication_count; i++) {
            i2_publication_attachment_t *old = &surface->publications[i];
            if (same_bytes((const uint8_t *)old, (const uint8_t *)p,
                           (uint32_t)sizeof *p)) return 0;
        }
        surface->publication_count++;
    }
    return surface->publication_count != 0;
}

static surface_fb_t *find_fb(surface_fb_t *fbs, uint32_t count, uint64_t id)
{
    for (uint32_t i = 0; i < count; i++) if (fbs[i].id == id) return &fbs[i];
    return NULL;
}

static surface_fb_t *instance_fb(surface_fb_t *fbs, uint32_t fb_count,
                                  surface_instance_t *instances, uint32_t instance_count,
                                  uint64_t instance)
{
    for (uint32_t i = 0; i < instance_count; i++)
        if (instances[i].id == instance)
            return find_fb(fbs, fb_count, instances[i].fb_type);
    return NULL;
}

static surface_event_t *find_event(surface_event_t *events, uint32_t count, uint64_t id)
{
    for (uint32_t i = 0; i < count; i++) if (events[i].id == id) return &events[i];
    return NULL;
}

static surface_var_t *find_var(surface_var_t *vars, uint32_t count, uint64_t id)
{
    for (uint32_t i = 0; i < count; i++) if (vars[i].id == id) return &vars[i];
    return NULL;
}

static int instance_pos(surface_instance_t *instances, uint32_t count,
                        uint64_t id)
{
    for (uint32_t i = 0; i < count; i++)
        if (instances[i].id == id) return (int)i;
    return -1;
}

static int graph_cycle(uint8_t adjacency[SURFACE_MAX_INSTANCES][SURFACE_MAX_INSTANCES],
                       uint32_t count, uint32_t node,
                       uint8_t color[SURFACE_MAX_INSTANCES])
{
    color[node] = 1;
    for (uint32_t next = 0; next < count; next++) {
        if (!adjacency[node][next]) continue;
        if (color[next] == 1) return 1;
        if (color[next] == 0 && graph_cycle(adjacency, count, next, color)) return 1;
    }
    color[node] = 2;
    return 0;
}

static int has_with(const surface_event_t *event, uint64_t variable)
{
    for (uint32_t i = 0; i < event->with_count; i++)
        if (event->with_vars[i] == variable) return 1;
    return 0;
}

static int validate_surface(noun base, noun services,
                            i2_application_service_surface_t *surface)
{
    noun tag, rest, schema, schema_major, schema_minor;
    noun type_table, fb_table, instance_table;
    noun connections, external, subscriptions, event_connections, data_connections;
    surface_fb_t fbs[SURFACE_MAX_FB_TYPES];
    surface_instance_t instances[SURFACE_MAX_INSTANCES];
    surface_event_edge_t event_edges[SURFACE_MAX_EVENT_EDGES];
    surface_data_edge_t data_edges[SURFACE_MAX_DATA_EDGES];
    uint32_t type_count = 0, fb_count = 0, instance_count = 0;
    uint32_t event_count = 0, data_count = 0, external_count = 0;
    uint64_t type_ids[SURFACE_MAX_TYPES];
    int bool_type = 0;
#ifdef M37_A_R
    int typed_type = 0;
#endif

    if (!take(base, &tag, &rest) || !tag_is(tag, "i2-program", 10)
        || !take(rest, &schema, &rest) || !take(rest, &type_table, &rest)
        || !take(rest, &fb_table, &rest) || !take(rest, &instance_table, &rest)
        || !take(rest, &connections, &rest) || !take(rest, &external, &subscriptions)
        || !take(connections, &event_connections, &data_connections)
        || !take(schema, &schema_major, &schema_minor)
        || !noun_is_direct(schema_major) || direct_val(schema_major) != 1
        || !noun_is_direct(schema_minor) || direct_val(schema_minor) != 0) return 0;
    if (!parse_fb_types(fb_table, fbs, &fb_count)) return 0;
    if (!parse_instances(instance_table, instances, &instance_count)
        || instance_count == 0
        ) return 0;
    if (!parse_event_edges(event_connections, event_edges, &event_count)) return 0;
    if (!parse_data_edges(data_connections, data_edges, &data_count)) return 0;
    if (!parse_publications(services, surface)) return 0;
    (void)subscriptions;

    while (!noun_is_direct(type_table) || direct_val(type_table) != 0) {
        noun entry, descriptor, symbol, elementary, kind, dimensions, width, limit;
        uint64_t type_id;
        if (++type_count > SURFACE_MAX_TYPES || !take(type_table, &entry, &type_table)
            || !take(entry, &type_id, &descriptor) || !positive(type_id, &type_id)
            || type_id_seen(type_ids, type_count - 1, type_id)
            || !take(descriptor, &symbol, &descriptor)
            || !take(descriptor, &elementary, &descriptor)
            || !take(descriptor, &kind, &descriptor)
            || !take(descriptor, &dimensions, &descriptor)
            || !positive(dimensions, &width)) return 0;
        limit = descriptor;
        if (type_id == 1) {
            if (!tag_is(symbol, "elementary", 10)
                || !tag_is(kind, "bool", 4) || width != 1) return 0;
            bool_type = 1;
        }
#ifdef M37_A_R
        if (type_id == 4) {
            if (!tag_is(symbol, "elementary", 10)
                || !tag_is(kind, "uint", 4) || width != 16) return 0;
            typed_type = 1;
        }
#endif
        type_ids[type_count - 1] = type_id;
        (void)symbol; (void)elementary; (void)limit;
    }
    if (!bool_type
#ifdef M37_A_R
        && !typed_type
#endif
        ) return 0;

    noun ext = external;
    noun ext_entry;
    while (!noun_is_direct(ext) || direct_val(ext) != 0) {
        uint64_t fields[3];
        if (++external_count > 1 || !take(ext, &ext_entry, &ext)
            || !fixed_positive_fields(ext_entry, fields, 3)) return 0;
        surface->ingress.instance = fields[1];
        surface->ingress.event = fields[2];
        surface_fb_t *fb = instance_fb(fbs, fb_count, instances, instance_count, fields[1]);
        surface_event_t *event_decl = fb ? find_event(fb->event_inputs,
                                                       fb->event_input_count, fields[2]) : NULL;
        if (!event_decl || event_decl->with_count == 0
            || event_decl->with_count > I2_SURFACE_MAX_INGRESS_SAMPLES) return 0;
        surface->ingress.sample_count = event_decl->with_count;
        for (uint32_t i = 0; i < event_decl->with_count; i++) {
            surface_var_t *var = find_var(fb->data_inputs, fb->data_input_count,
                                          event_decl->with_vars[i]);
            if (!var || (var->type != 1
#ifdef M37_A_R
                         && var->type != 4
#endif
                         )) return 0;
            surface->ingress.sample_id[i] = var->id;
            surface->ingress.sample_type[i] = var->type;
        }
    }
    if (external_count != 1) return 0;

    if (instance_count == 1) {
        if (event_count != 0 || data_count != 0) return 0;
    } else {
        uint8_t adjacency[SURFACE_MAX_INSTANCES][SURFACE_MAX_INSTANCES] = {{0}};
        uint32_t indegree[SURFACE_MAX_INSTANCES] = {0};
        uint32_t outdegree[SURFACE_MAX_INSTANCES] = {0};
        int root = instance_pos(instances, instance_count, surface->ingress.instance);
        int sink = surface->publication_count == 1
            ? instance_pos(instances, instance_count,
                           surface->publications[0].source_instance) : -1;
        if (event_count == 0 || event_count > SURFACE_MAX_EVENT_EDGES
            || data_count == 0 || root < 0 || sink < 0) return 0;
        for (uint32_t i = 0; i < event_count; i++) {
            surface_event_edge_t *edge = &event_edges[i];
            int source_pos = instance_pos(instances, instance_count, edge->source_instance);
            int target_pos = instance_pos(instances, instance_count, edge->target_instance);
            surface_fb_t *source = instance_fb(fbs, fb_count, instances, instance_count,
                                                edge->source_instance);
            surface_fb_t *target = instance_fb(fbs, fb_count, instances, instance_count,
                                                edge->target_instance);
            surface_event_t *source_event = source ? find_event(source->event_outputs,
                                                                 source->event_output_count,
                                                                 edge->source_event) : NULL;
            surface_event_t *target_event = target ? find_event(target->event_inputs,
                                                                 target->event_input_count,
                                                                 edge->target_event) : NULL;
            uint32_t matched_data = 0;
            if (edge->ordinal != (uint64_t)(i + 1u) || source_pos < 0 || target_pos < 0
                || source_pos == target_pos || !source_event || !target_event
                || source_event->with_count == 0
                || source_event->with_count != target_event->with_count) return 0;
            adjacency[source_pos][target_pos] = 1;
            indegree[target_pos]++; outdegree[source_pos]++;
            for (uint32_t d = 0; d < data_count; d++) {
                surface_data_edge_t *data = &data_edges[d];
                if (data->source_instance != edge->source_instance
                    || data->target_instance != edge->target_instance) continue;
                surface_var_t *source_var = find_var(source->data_outputs,
                                                     source->data_output_count,
                                                     data->source_data);
                surface_var_t *target_var = find_var(target->data_inputs,
                                                     target->data_input_count,
                                                     data->target_data);
                if (!source_var || !target_var || (source_var->type != 1
#ifdef M37_A_R
                    && source_var->type != 4
#endif
                    ) || target_var->type != source_var->type
                    || !has_with(source_event, source_var->id)
                    || !has_with(target_event, target_var->id)) return 0;
                for (uint32_t prior = 0; prior < d; prior++)
                    if (data_edges[prior].source_instance == data->source_instance
                        && data_edges[prior].source_data == data->source_data
                        && data_edges[prior].target_instance == data->target_instance
                        && data_edges[prior].target_data == data->target_data) return 0;
                matched_data++;
            }
            if (matched_data != source_event->with_count) return 0;
            for (uint32_t with = 0; with < source_event->with_count; with++) {
                uint64_t source_var = source_event->with_vars[with];
                uint32_t source_hits = 0;
                for (uint32_t d = 0; d < data_count; d++)
                    if (data_edges[d].source_instance == edge->source_instance
                        && data_edges[d].target_instance == edge->target_instance
                        && data_edges[d].source_data == source_var) source_hits++;
                if (source_hits != 1) return 0;
            }
            for (uint32_t with = 0; with < target_event->with_count; with++) {
                uint64_t target_var = target_event->with_vars[with];
                uint32_t target_hits = 0;
                for (uint32_t d = 0; d < data_count; d++)
                    if (data_edges[d].source_instance == edge->source_instance
                        && data_edges[d].target_instance == edge->target_instance
                        && data_edges[d].target_data == target_var) target_hits++;
                if (target_hits != 1) return 0;
            }
        }
        for (uint32_t d = 0; d < data_count; d++) {
            int found = 0;
            for (uint32_t e = 0; e < event_count; e++)
                if (data_edges[d].source_instance == event_edges[e].source_instance
                    && data_edges[d].target_instance == event_edges[e].target_instance) {
                    found = 1; break;
                }
            if (!found) return 0;
        }
        if (indegree[root] != 0 || outdegree[sink] != 0
            || graph_cycle(adjacency, instance_count, (uint32_t)root,
                           (uint8_t[SURFACE_MAX_INSTANCES]){0})) return 0;
        uint8_t forward[SURFACE_MAX_INSTANCES] = {0};
        uint8_t reverse[SURFACE_MAX_INSTANCES] = {0};
        forward[root] = 1; reverse[sink] = 1;
        for (uint32_t pass = 0; pass < instance_count; pass++)
            for (uint32_t i = 0; i < instance_count; i++)
                for (uint32_t j = 0; j < instance_count; j++) {
                    if (adjacency[i][j] && forward[i]) forward[j] = 1;
                    if (adjacency[i][j] && reverse[j]) reverse[i] = 1;
                }
        for (uint32_t i = 0; i < instance_count; i++)
            if (!forward[i] || !reverse[i]) return 0;
        surface->event_edge_count = event_count;
        for (uint32_t i = 0; i < event_count; i++) {
            surface->event_edges[i].ordinal = event_edges[i].ordinal;
            surface->event_edges[i].source_instance = event_edges[i].source_instance;
            surface->event_edges[i].source_event = event_edges[i].source_event;
            surface->event_edges[i].target_instance = event_edges[i].target_instance;
            surface->event_edges[i].target_event = event_edges[i].target_event;
        }
    }

    for (uint32_t i = 0; i < surface->publication_count; i++) {
        i2_publication_attachment_t *p = &surface->publications[i];
        surface_fb_t *source = instance_fb(fbs, fb_count, instances, instance_count,
                                            p->source_instance);
        surface_event_t *event = source ? find_event(source->event_outputs,
                                                      source->event_output_count,
                                                      p->source_event) : NULL;
        surface_var_t *data = source ? find_var(source->data_outputs,
                                                source->data_output_count,
                                                p->source_data) : NULL;
        if (!source || !event || !data || p->source_type != p->target_type
#ifndef M37_A_R
            || p->source_type != 1
#else
            || (p->source_type != 1 && p->source_type != 4)
#endif
            || p->source_service != 8 || p->target_service != 9
            || !has_with(event, p->source_data) || data->type != p->source_type) return 0;
        if (instance_count > 1 && p->source_instance != surface->publications[0].source_instance)
            return 0;
        if ((surface->publication_count == 1 && p->source_ordinal != 8)
            || (surface->publication_count == 2
                && p->source_ordinal != (i == 0 ? 8 : 9))) return 0;
    }
    return 1;
}

int i2_application_surface_from_gate(noun gate,
                                     i2_application_service_surface_t *out)
{
    noun battery, sample, zero, state, state_tag, state_rest;
    noun header, dynamic, program, program_tag, program_rest;
    noun base, tables, routes, specs, owners, exports, services;
    (void)battery; (void)state_tag; (void)header; (void)routes;
    (void)specs; (void)owners; (void)exports;
    if (!out || !take(gate, &battery, &sample) || !take(sample, &zero, &state)
        || !noun_is_direct(zero) || direct_val(zero) != 0
        || !take(state, &state_tag, &state_rest)
        || !take(state_rest, &header, &dynamic)
        || !take(dynamic, &program, &dynamic)
        || !take(program, &program_tag, &program_rest)
        || !wrapper_tag(program_tag)
        || !take(program_rest, &base, &tables)
        || !take(tables, &routes, &tables) || !take(tables, &specs, &tables)
        || !take(tables, &owners, &tables) || !take(tables, &exports, &services)) return 0;
    for (uint32_t i = 0; i < sizeof *out; i++) ((uint8_t *)out)[i] = 0;
    return validate_surface(base, services, out);
}

static int publication_equal(const i2_publication_attachment_t *p,
                             const uint64_t fields[11])
{
    const uint64_t actual[11] = {
        p->source_instance, p->source_event, p->source_ordinal, p->source_data,
        p->source_type, p->source_service, p->target_service, p->target_instance,
        p->target_event, p->target_data, p->target_type,
    };
    for (unsigned i = 0; i < 11; i++) if (actual[i] != fields[i]) return 0;
    return 1;
}

int i2_application_surface_publication_matches(
    const i2_application_service_surface_t *surface,
    uint64_t source_instance, uint64_t source_event, uint64_t source_ordinal,
    uint64_t source_data, uint64_t source_type, uint64_t source_service,
    uint64_t target_service, uint64_t target_instance, uint64_t target_event,
    uint64_t target_data, uint64_t target_type)
{
    const uint64_t fields[11] = {
        source_instance, source_event, source_ordinal, source_data, source_type,
        source_service, target_service, target_instance, target_event, target_data,
        target_type,
    };
    if (!surface || surface->publication_count == 0
        || surface->publication_count > I2_SURFACE_MAX_PUBLICATIONS) return 0;
    for (uint32_t i = 0; i < surface->publication_count; i++)
        if (publication_equal(&surface->publications[i], fields)) return 1;
    return 0;
}
