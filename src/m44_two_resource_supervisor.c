#include "m44_two_resource_supervisor.h"
#if defined(M44_TWO_RESOURCE)
#include "bounded_cue.h"
#include "jam.h"
#include "memory.h"
#if defined(M49_MANAGED_DELAY)
#include "m49_clock_adapter.h"
#endif
static void byte_copy(void *destination, const void *source, size_t count) {
  uint8_t *to = destination;
  const uint8_t *from = source;
  for (size_t i = 0; i < count; i++)
    to[i] = from[i];
}
static void byte_fill(void *destination, int value, size_t count) {
  uint8_t *to = destination;
  for (size_t i = 0; i < count; i++)
    to[i] = (uint8_t)value;
}
static int byte_compare(const void *left, const void *right, size_t count) {
  const uint8_t *a = left, *b = right;
  for (size_t i = 0; i < count; i++)
    if (a[i] != b[i])
      return 1;
  return 0;
}
/* All durable objects are C copies. No noun survives a public call. */
static struct {
  ResourceSession *session;
#if defined(M46_LIVE_REPLACEMENT)
  ResourceSession *candidate;
  M44Descriptor candidate_descriptor;
  M44Saved candidate_handles[2];
  uint8_t compatibility[32], candidate_old_identity[32];
  uint32_t deployment_generation, candidate_generation, candidate_token, candidate_serial;
#if defined(M52_RESIDENT_REPLACEMENT)
  uint32_t resident_replacement, replacement_call;
#if defined(M54_RESIDENT_REPLACEMENT)
  M54Policy policy;
#endif
#endif
#if defined(M44_G0_TEST_CONTROLS)
  uint32_t replacement_fault, replacement_busy_mask;
#endif
#endif
#if defined(M47_MANAGED_SERVICES)
  uint32_t services;
  M47ProviderBinding bindings[2];
  uint32_t receive_holds;
#endif
#if defined(M49_MANAGED_DELAY)
  uint32_t timed, clock_valid;
#if defined(M50_PERIODIC)
  uint32_t periodic;
#endif
  M49TimerBinding timer_binding;
#if defined(M51_CONTROLLER)
  uint32_t controller, controller_cnf;
  M51TimerBinding timer_bindings[2];
  M51ReturnBinding completion;
#endif
  uint64_t clock_ms, clock_turn;
#endif
  M44Descriptor descriptor;
  M44Saved handles[2], snapshots[2][2];
  M44State roots[2], checkpoints[2];
  uint32_t live, snapshot_bank, token, busy, initialized, operation, selected;
  uint32_t copy_fault, retire_fault, turn_fault;
#if defined(M45_MANAGED_LIFECYCLE)
  uint32_t managed, checkpoint_valid;
#if defined(M44_G0_TEST_CONTROLS)
  uint32_t management_busy_mask;
#endif
#endif
#if defined(M44_G0_TEST_CONTROLS)
  uint32_t busy_probe, busy_mask;
#endif
} authority;
enum { OP_TURN = 1, OP_RETIRE, OP_CAPTURE, OP_RESTORE, OP_ENQUEUE
#if defined(M45_MANAGED_LIFECYCLE)
, OP_MANAGE, OP_RESET
#endif
};
static size_t textlen(const char *s) {
  size_t n = 0;
  while (s[n])
    n++;
  return n;
}
static noun cord(const char *s) { return cord_from_bytes(s, textlen(s)); }
static int pair(noun n, noun *a, noun *b) {
  if (!noun_is_cell(n))
    return 0;
  cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
  *a = c->head;
  *b = c->tail;
  return 1;
}
static int record(noun n, noun *out, uint32_t count) {
  for (uint32_t i = 0; i < count; i++)
    if (!pair(n, &out[i], &n))
      return 0;
  return n == NOUN_ZERO;
}
static int list(noun n, noun *out, uint32_t max, uint32_t *count) {
  *count = 0;
  while (n != NOUN_ZERO) {
    if (*count == max || !pair(n, &out[*count], &n))
      return 0;
    (*count)++;
  }
  return 1;
}
static int scalar(noun n, uint32_t max, uint32_t *out) {
  if (!noun_is_direct(n) || direct_val(n) > max)
    return 0;
  *out = direct_val(n);
  return 1;
}
static int textis(noun n, const char *s) {
  uint8_t bytes[128];
  if (!noun_atom_read_fixed(n, bytes, sizeof(bytes)))
    return 0;
  size_t len = textlen(s);
  for (uint32_t i = 0; i < sizeof(bytes); i++)
    if (bytes[i] != (i < len ? (uint8_t)s[i] : 0))
      return 0;
  return 1;
}
static int build(const noun *v, uint32_t n, noun *out) {
  *out = NOUN_ZERO;
  while (n)
    if (!alloc_cell_checked(v[--n], *out, out))
      return 0;
  return 1;
}
static int tagged(const char *tag, const char *schema, const noun *v,
                  uint32_t n, noun *out) {
  noun row[5], body;
  if (n > 4)
    return 0;
  row[0] = cord(schema);
  for (uint32_t i = 0; i < n; i++)
    row[i + 1] = v[i];
  return build(row, n + 1, &body) && alloc_cell_checked(cord(tag), body, out);
}
static int fields(noun n, const char *tag, const char *schema, noun *out,
                  uint32_t count) {
  noun t, b, r[5];
  if (count > 4 || !pair(n, &t, &b) || !textis(t, tag) ||
      !record(b, r, count + 1) || !textis(r[0], schema))
    return 0;
  for (uint32_t i = 0; i < count; i++)
    out[i] = r[i + 1];
  return 1;
}
static int save(noun n, M44Saved *out) {
  const uint8_t *bytes;
  uint64_t size;
  jam_admission_budget_t budget;
  jam_admission_budget_init(&budget, 2000000);
  if (jam_encode_bytes_identity_bounded(n, &bytes, &size, &budget) ||
      size > M44_SAVED_BYTES)
    return 0;
  byte_copy(out->jam, bytes, size);
  out->bytes = size;
  return 1;
}
static int decode(const M44Saved *in, noun *out) {
  if (!in->bytes || in->bytes > M44_SAVED_BYTES ||
      cue_bounded_bytes(in->jam, in->bytes, &cue_i2_limits, HEAP_MODE_PERSIST,
                        out) != CUE_BOUNDED_OK)
    return 0;
  noun_tx_commit();
  return 1;
}
static M44State *live(void) { return &authority.roots[authority.live]; }
static M44State *stage(void) { return &authority.roots[authority.live ^ 1u]; }
static const char *value_schema(uint32_t slot) {
#if defined(M49_MANAGED_DELAY)
  if (authority.descriptor.time_values[slot]) return "m49-numeric-value-schema-v1";
#endif
  return authority.descriptor.signed_values[slot]
             ? "m41-numeric-value-schema-v1"
             : "m38-resource-abi-v1-numeric-value-schema-v1";
}
static const M44Boundary *boundary(uint32_t slot, uint32_t event, int output) {
  const M44Descriptor *d = &authority.descriptor;
  uint32_t n = output ? d->output_count[slot] : d->ingress_count[slot];
  const M44Boundary *rows = output ? d->outputs[slot] : d->ingress[slot];
  for (uint32_t i = 0; i < n; i++)
    if (rows[i].event == event)
      return &rows[i];
  return 0;
}
static int valid_row(uint32_t slot, const M44Row *row, int output) {
  const M44Boundary *b = boundary(slot, row->event, output);
  if (!b || row->count != b->count || row->count > 16)
    return 0;
  for (uint32_t i = 0; i < row->count; i++)
    if (row->values[i].id != b->values[i].id ||
        row->values[i].type != b->values[i].type ||
        row->values[i].raw > (row->values[i].type == 1 ? 1u :
#if defined(M49_MANAGED_DELAY)
          (authority.timed && authority.descriptor.time_values[slot] && row->values[i].type == 4) ? UINT32_MAX :
#endif
          65535u))
      return 0;
  return 1;
}
#if defined(M47_MANAGED_SERVICES)
#if defined(M49_MANAGED_DELAY)
#if defined(M51_CONTROLLER)
static int m51_private(uint32_t slot,uint32_t event);
static int m51_active(void);
static uint32_t m51_capacity(uint32_t slot,int consuming);
static int m51_output(uint32_t slot,const M44Row *row);
static int m51_consumed(uint32_t slot);
static int m51_crossing(uint32_t slot,const M44Row *row);
static M44Status m51_clock(void);
#endif
static uint32_t m49_event(uint32_t ordinal) {
  return authority.timer_binding.instance_id*1024u+ordinal;
}
static int m49_private(uint32_t slot,uint32_t event) {
#if defined(M51_CONTROLLER)
  if (authority.controller) return m51_private(slot,event);
#endif
  return authority.timed && slot+1==authority.timer_binding.slot && event==m49_event(3);
}
static void m49_clear(M49TimerLedger *timer) {
  uint64_t highwater=timer->highwater;
  *timer=(M49TimerLedger){0}; timer->highwater=highwater;
}
#endif
static uint32_t m47_event(uint32_t slot, uint32_t ordinal) {
  return authority.bindings[slot].instance_id * 1024u + ordinal;
}
static int m47_private(uint32_t slot, uint32_t event) {
  return authority.services &&
      (event == m47_event(slot, 3) || event == m47_event(slot, 4) ||
       (authority.bindings[slot].kind == 2 && event == m47_event(slot, 2)));
}
static int m47_public_release(uint32_t slot,const M44Row *row) {
  return authority.services && row->event==m47_event(slot,1) &&
      row->count==2 && row->values[0].raw==0;
}
static uint32_t m47_capacity(uint32_t slot,int consuming) {
#if defined(M51_CONTROLLER)
  if (authority.controller) return m51_capacity(slot,consuming);
#endif
  if (!authority.services || slot+1!=authority.descriptor.target_slot) return 16;
  uint32_t source=authority.descriptor.source_slot-1;
#if defined(M49_MANAGED_DELAY)
  if (authority.timed && live()->timer.phase==M49_TIMER_QUEUED) {
    if (consuming && authority.selected+1==authority.timer_binding.slot &&
        live()->counts[authority.selected] &&
        live()->queues[authority.selected][0].event==m49_event(3) &&
        ((uint64_t)live()->queues[authority.selected][0].values[0].raw |
         ((uint64_t)live()->queues[authority.selected][0].values[1].raw<<16) |
         ((uint64_t)live()->queues[authority.selected][0].values[2].raw<<32) |
         ((uint64_t)live()->queues[authority.selected][0].values[3].raw<<48))==live()->timer.generation) return 16;
    return 16-authority.descriptor.batch_bound;
  }
#endif
#if defined(M49_MANAGED_DELAY)
  if (authority.timed) return 16; /* delayed crossing is reserved at EXPIRE */
#endif
  if (live()->providers[source].rx_state!=1) return 16;
  if (consuming && authority.selected==source && live()->counts[source] &&
      live()->queues[source][0].event==m47_event(source,3)) return 16;
  return 16-authority.descriptor.batch_bound;
}
static uint64_t m47_token(const M44Row *row, uint32_t offset) {
  return (uint64_t)row->values[offset].raw |
      ((uint64_t)row->values[offset+1].raw << 16) |
      ((uint64_t)row->values[offset+2].raw << 32) |
      ((uint64_t)row->values[offset+3].raw << 48);
}
#if defined(M49_MANAGED_DELAY)
static int m49_output(uint32_t slot,const M44Row *row) {
#if defined(M51_CONTROLLER)
  if (authority.controller) return m51_output(slot,row);
#endif
  if (!authority.timed || slot+1!=authority.timer_binding.slot) return 1;
  M49TimerLedger *timer=&stage()->timer;
  if (row->event==m49_event(5)) { /* ARM: DT then four token limbs */
    uint64_t token=m47_token(row,1);
    M49ClockArm candidate={0};
#if defined(M50_PERIODIC)
    if (authority.periodic) {
      if (row->count!=5 || !row->values[0].raw) return 0;
      /* A matching consumed expiry may replace its own ledger in this same
       * unpublished transaction. A stale row cannot retire a newer arm. */
      const M44Row *cause=&live()->queues[slot][0];
      if (timer->phase==M49_TIMER_QUEUED && live()->counts[slot] &&
          m49_private(slot,cause->event) && cause->count==4 &&
          m47_token(cause,0)==timer->generation) m49_clear(timer);
    }
#endif
    if (row->count!=5 || row->values[0].type!=4 || !authority.clock_valid ||
        timer->phase!=M49_TIMER_FREE || token!=timer->highwater+1 ||
        !m49_clock_prepare_arm(live()->epoch,token,authority.clock_ms,
            row->values[0].raw,authority.clock_turn,&candidate)) return 0;
    timer->phase=M49_TIMER_ARMED; timer->generation=token; timer->highwater=token;
    timer->duration_ms=row->values[0].raw; timer->deadline_ms=candidate.deadline_ms;
    timer->not_before_turn=candidate.not_before_turn;
  } else if (row->event==m49_event(6)) { /* CANCEL */
    uint64_t token=m47_token(row,0);
    if (row->count!=4 || (timer->phase!=M49_TIMER_ARMED && timer->phase!=M49_TIMER_QUEUED)
        || token!=timer->generation) return 0;
    m49_clear(timer);
  }
  return 1;
}
static int m49_consumed(uint32_t slot) {
#if defined(M51_CONTROLLER)
  if (authority.controller) return m51_consumed(slot);
#endif
  if (!authority.timed) return 1;
  const M44Row *row=&live()->queues[slot][0];
  if (m49_private(slot,row->event) && stage()->timer.phase==M49_TIMER_QUEUED &&
      m47_token(row,0)==stage()->timer.generation) m49_clear(&stage()->timer);
  return 1;
}
#endif
static int m47_output(uint32_t slot, const M44Row *row) {
  if (!authority.services) return 1;
  M47ProviderLedger *p = &stage()->providers[slot];
  if (row->event == m47_event(slot, 5)) {
    if ((row->values[0].raw && p->phase != 0) ||
        (!row->values[0].raw && (p->tx_state || p->rx_state))) return 0;
    p->phase = row->values[0].raw ? 1u : 2u;
  } else if (authority.bindings[slot].kind == 1 &&
             row->event == m47_event(slot, 7)) {
    uint64_t token = m47_token(row, 0);
#if defined(M51_CONTROLLER)
    if (authority.controller && !stage()->publish_roundtrip) return 0;
#endif
    if (p->phase != 1 || p->tx_state || !token || token >> 63 ||
        p->release_queued || row->values[5].raw != 0) return 0;
    p->tx_state = 1; p->tx_token = token; p->tx_value = row->values[4].raw;
  }
  return 1;
}
static int m47_consumed(uint32_t slot) {
  if (!authority.services) return 1;
  const M44Row *row = &live()->queues[slot][0];
  M47ProviderLedger *p = &stage()->providers[slot];
  if (row->event == m47_event(slot, 3)) {
    if (authority.bindings[slot].kind == 1) {
      uint32_t cnf = 0;
#if defined(M51_CONTROLLER)
      if (authority.controller) cnf=authority.controller_cnf;
#endif
      for (uint32_t i=0;i<stage()->output_count;i++)
        if (stage()->output_slots[i] == slot+1 &&
            stage()->outputs[i].event == m47_event(slot,6)) cnf++;
      if (p->tx_state != 3 || cnf != 1) return 0;
      p->tx_state=0; p->tx_token=0; p->tx_value=0;
    } else {
      if (p->rx_state != 1) return 0;
      p->rx_state=2;
    }
  } else if (authority.bindings[slot].kind == 2 && row->event == m47_event(slot,2)) {
    if (p->rx_state != 3) return 0;
    p->rx_state=0; p->rx_token=0;
  } else if (row->event == m47_event(slot,4) || m47_public_release(slot,row)) {
    if (!p->release_queued || p->phase != 2) return 0;
    p->release_queued=0;
  }
  return 1;
}
#endif
static void retire(M44State *s, uint32_t slot) {
  for (uint32_t i = 1; i < s->counts[slot]; i++)
    s->queues[slot][i - 1] = s->queues[slot][i];
  s->counts[slot]--;
  byte_fill(&s->queues[slot][s->counts[slot]], 0, sizeof(M44Row));
  s->cursor = 2u - slot;
}
static int parse_outputs(noun result) {
  noun rf[2], body[4], ef[1], rows[32];
  uint32_t count, wire;
  M44State *s = stage();
  uint32_t slot = authority.selected;
  if (!fields(result, "m38-resource-abi-v1-result",
              "m38-resource-abi-v1-result-schema-v1", rf, 2) ||
      !scalar(rf[0], 255, &wire) || wire != 2 || !record(rf[1], body, 4) ||
      !fields(body[1], "m38-resource-abi-v1-numeric-effects",
              "m38-resource-abi-v1-numeric-effects-schema-v1", ef, 1) ||
      !list(ef[0], rows, 32, &count))
    return 0;
#if defined(M51_CONTROLLER)
  authority.controller_cnf=0;
#endif
  uint32_t internal = 0;
  const M44Descriptor *d = &authority.descriptor;
  for (uint32_t i = 0; i < count; i++) {
    noun of[2], vs[16];
    M44Row row = {0};
    if (!fields(rows[i], "m38-resource-abi-v1-numeric-effect",
                "m38-resource-abi-v1-numeric-effect-schema-v1", of, 2) ||
        !scalar(of[0], 65535, &row.event) || !list(of[1], vs, 16, &row.count))
      return 0;
    for (uint32_t j = 0; j < row.count; j++) {
      noun vf[3];
      if (!fields(vs[j], "m38-resource-abi-v1-numeric-value",
                  value_schema(slot), vf, 3) ||
          !scalar(vf[0], 65535, &row.values[j].id) ||
          !scalar(vf[1],
#if defined(M49_MANAGED_DELAY)
              authority.timed ? 4 :
#endif
              3, &row.values[j].type) ||
          !scalar(vf[2],
#if defined(M49_MANAGED_DELAY)
              authority.timed && row.values[j].type==4 ? UINT32_MAX :
#endif
              65535, &row.values[j].raw))
        return 0;
    }
    if (!valid_row(slot, &row, 1))
      return 0;
#if defined(M47_MANAGED_SERVICES)
    if (!m47_output(slot, &row)) return 0;
#if defined(M49_MANAGED_DELAY)
    if (!m49_output(slot, &row)) return 0;
#endif
#endif
#if defined(M51_CONTROLLER)
    if (authority.controller) {
      int routed=m51_crossing(slot,&row);
      if (routed<0) return 0;
      if (routed) continue;
    }
#endif
    if (slot + 1 == d->source_slot && row.event == d->source_event) {
      uint32_t dest = d->target_slot - 1;
      if (++internal > d->batch_bound || s->counts[dest] >=
#if defined(M47_MANAGED_SERVICES)
          m47_capacity(dest,1)
#else
          16
#endif
          ||
          s->sequence == UINT32_MAX) {
        authority.turn_fault = M44_FAULT_DELIVERY_RESERVATION;
        return 0;
      }
      M44Row delivery = {0};
      delivery.event = d->target_event;
      delivery.count = d->value_count;
      delivery.sequence = ++s->sequence;
      for (uint32_t j = 0; j < d->value_count; j++) {
        uint32_t found = 0;
        for (uint32_t k = 0; k < row.count; k++)
          if (row.values[k].id == d->source_ids[j] &&
              row.values[k].type == d->types[j]) {
            delivery.values[j] =
                (M44Value){d->target_ids[j], d->types[j], row.values[k].raw};
            found++;
          }
        if (found != 1)
          return 0;
      }
      if (!valid_row(dest, &delivery, 0))
        return 0;
      s->queues[dest][s->counts[dest]++] = delivery;
    } else {
      if (s->output_count == 32)
        return 0;
      s->output_slots[s->output_count] = slot + 1;
      s->outputs[s->output_count++] = row;
    }
  }
  return 1;
}
static int prepare(void *context, noun result) {
  (void)context;
#if defined(M44_G0_TEST_CONTROLS)
  if (authority.busy_probe) {
    authority.busy_probe = 0;
    uint32_t token = 0;
    M44Row row = {0};
    authority.busy_mask =
        (m44_supervisor_enqueue(1, &row) == M44_BUSY ? 1u : 0u) |
        (m44_supervisor_dispatch() == M44_BUSY ? 2u : 0u) |
        (m44_supervisor_capture(&token) == M44_BUSY ? 4u : 0u) |
        (m44_supervisor_restore(authority.token) == M44_BUSY ? 8u : 0u);
#if defined(M45_MANAGED_LIFECYCLE)
    if (authority.managed)
      authority.management_busy_mask =
          (m45_supervisor_manage(2, 0) == M45_OVERFLOW ? 1u : 0u) |
          (m45_supervisor_manage(3, 0) == M45_OVERFLOW ? 2u : 0u) |
          (m45_supervisor_manage(7, 0) == M45_OVERFLOW ? 4u : 0u) |
          (m45_supervisor_manage(8, 0) == M45_OVERFLOW ? 8u : 0u);
#endif
  }
#endif
  if (authority.operation == OP_TURN) {
    authority.turn_fault = M44_FAULT_PRODUCT;
    if (!parse_outputs(result))
      return 0;
#if defined(M47_MANAGED_SERVICES)
    if (!m47_consumed(authority.selected)) return 0;
#if defined(M49_MANAGED_DELAY)
    if (!m49_consumed(authority.selected)) return 0;
#endif
#endif
    authority.turn_fault = M44_FAULT_PUBLICATION;
  }
  if (authority.operation == OP_CAPTURE) {
    noun tag, body, results[2], rf[2];
    if (!pair(result, &tag, &body) || !textis(tag, "m44-resource-group-v1") ||
        !record(body, results, 2))
      return 0;
    for (uint32_t i = 0; i < 2; i++)
      if (!fields(results[i], "m38-resource-abi-v1-result",
                  "m38-resource-abi-v1-result-schema-v1", rf, 2) ||
          !save(rf[1], &authority.snapshots[authority.snapshot_bank ^ 1u][i]))
        return 0;
  }
#if defined(M44_G0_TEST_CONTROLS)
  uint32_t fault = authority.operation == OP_RETIRE ? authority.retire_fault
                                                    : authority.copy_fault;
  if (fault)
    m44_resource_test_fail_publication(authority.session, fault);
  if (authority.operation == OP_RETIRE)
    authority.retire_fault = 0;
  else
    authority.copy_fault = 0;
#endif
  return 1;
}
static void commit(void *context) {
  (void)context;
  if (authority.operation == OP_CAPTURE) {
    authority.snapshot_bank ^= 1u;
    authority.token++;
#if defined(M45_MANAGED_LIFECYCLE)
    authority.checkpoint_valid = 1;
#endif
  } else
    authority.live ^= 1u;
#if defined(M45_MANAGED_LIFECYCLE)
  if (authority.operation == OP_RESET)
    authority.checkpoint_valid = 0;
#endif
}
static M44PublicationHooks hooks(void) {
  return (M44PublicationHooks){prepare, commit, 0};
}
static M44Status ready(void) {
  if (!authority.initialized)
    return M44_INVALID;
  if (authority.busy)
    return M44_BUSY;
  if (live()->fenced)
    return M44_FENCED;
  return M44_OK;
}
static int request(uint32_t slot, uint32_t op, noun argument, noun *out) {
  noun handle, args, af[2], rf[2];
  if (!decode(&authority.handles[slot], &handle))
    return 0;
  af[0] = handle;
  af[1] = argument;
  if (!build(af, 2, &args))
    return 0;
  rf[0] = direct(op);
  rf[1] = args;
  return tagged("m38-resource-abi-v1-request",
                "m38-resource-abi-v1-request-schema-v1", rf, 2, out);
}
M44Status m44_supervisor_init(ResourceSession *session, const M44Descriptor *d,
                              const M44Saved handles[2]) {
  if (authority.initialized || !session || !d || !handles ||
      d->source_slot < 1 || d->source_slot > 2 || d->target_slot < 1 ||
      d->target_slot > 2 || d->source_slot == d->target_slot ||
      !d->batch_bound || d->batch_bound > 16 || d->value_count > 16)
    return M44_INVALID;
  for (uint32_t i = 0; i < 2; i++) {
    if (d->ingress_count[i] > 128 || d->output_count[i] > 128 ||
        !handles[i].bytes || handles[i].bytes > M44_SAVED_BYTES)
      return M44_INVALID;
    for (uint32_t j = 0; j < d->ingress_count[i]; j++)
      if (d->ingress[i][j].count > 16)
        return M44_INVALID;
    for (uint32_t j = 0; j < d->output_count[i]; j++)
      if (d->outputs[i][j].count > 16)
        return M44_INVALID;
  }
  authority.session = session;
  authority.descriptor = *d;
  const M44Boundary *source = boundary(d->source_slot - 1, d->source_event, 1);
  const M44Boundary *target = boundary(d->target_slot - 1, d->target_event, 0);
  if (!source || !target || source->count != d->value_count ||
      target->count != d->value_count)
    return M44_INVALID;
  for (uint32_t i = 0; i < d->value_count; i++) {
    if (target->values[i].id != d->target_ids[i] ||
        target->values[i].type != d->types[i])
      return M44_INVALID;
    uint32_t matches = 0;
    for (uint32_t j = 0; j < source->count; j++)
      if (source->values[j].id == d->source_ids[i] &&
          source->values[j].type == d->types[i])
        matches++;
    if (matches != 1)
      return M44_INVALID;
    for (uint32_t j = 0; j < i; j++)
      if (d->source_ids[j] == d->source_ids[i] ||
          d->target_ids[j] == d->target_ids[i])
        return M44_INVALID;
  }
  noun decoded[2];
  for (uint32_t i = 0; i < 2; i++)
    if (!decode(&handles[i], &decoded[i]) || !save(decoded[i], &authority.handles[i]))
      return M44_INVALID;
  authority.roots[0].cursor = 1;
  if (m44_resource_claim(session, &authority, decoded) != M38_STATUS_OK)
    return M44_INVALID;
  authority.initialized = 1;
  return M44_OK;
}
#if defined(M47_MANAGED_SERVICES)
static int m47_signature(const M44Descriptor *d, uint32_t slot, uint32_t iid,
                         uint32_t event, int output, const uint32_t *ids,
                         const uint32_t *types, uint32_t count) {
  const M44Boundary *rows=output ? d->outputs[slot] : d->ingress[slot];
  uint32_t n=output ? d->output_count[slot] : d->ingress_count[slot];
  if (n>128) return 0;
  uint32_t matches=0, base=iid*1024u;
  for (uint32_t i=0;i<n;i++) if (rows[i].event==base+event) {
    if (rows[i].count!=count) return 0;
    for (uint32_t j=0;j<count;j++)
      if (rows[i].values[j].id!=base+ids[j] || rows[i].values[j].type!=types[j]) return 0;
    matches++;
  }
  return matches==1;
}
M44Status m47_supervisor_init(ResourceSession *session, const M44Descriptor *d,
                             const M44Saved handles[2],
                             const M47ProviderBinding bindings[2]) {
  if (authority.initialized || !d || !bindings ||
      bindings[0].slot!=1 || bindings[1].slot!=2 ||
      bindings[0].kind+bindings[1].kind!=3 ||
      bindings[0].kind<1 || bindings[0].kind>2 ||
      bindings[1].kind<1 || bindings[1].kind>2) return M44_INVALID;
  const uint32_t init_ids[]={1,2}, init_types[]={1,2};
#if defined(M55_SIGNED_RESIDENT)
  if (d->service_value_type && d->service_value_type!=3) return M44_INVALID;
  const uint32_t data_type=d->service_value_type?d->service_value_type:2;
  const uint32_t cause_ids[]={11,12,13,14,3,5}, uint_types[]={2,2,2,2,data_type,2};
#else
  const uint32_t cause_ids[]={11,12,13,14,3,5}, uint_types[]={2,2,2,2,2,2};
#endif
  const uint32_t release_ids[]={5}, rsp_ids[]={1,11,12,13,14}, rsp_types[]={1,2,2,2,2};
  const uint32_t intent_ids[]={7,8,9,10,3,5};
  const uint32_t inito_ids[]={4,5}, inito_types[]={1,2};
#if defined(M55_SIGNED_RESIDENT)
  const uint32_t cnf_ids[]={4,5,6}, cnf_types[]={1,2,data_type};
  const uint32_t req_ids[]={1,3}, req_types[]={1,data_type};
#else
  const uint32_t cnf_ids[]={4,5,6}, cnf_types[]={1,2,2};
  const uint32_t req_ids[]={1,3}, req_types[]={1,2};
#endif
  for (uint32_t slot=0;slot<2;slot++) {
    uint32_t iid=bindings[slot].instance_id;
    if (!iid || iid>63 ||
#if defined(M55_SIGNED_RESIDENT)
        (d->signed_values[slot] && data_type!=3) ||
#else
        d->signed_values[slot] ||
#endif
        (bindings[slot].kind==1 && d->target_slot!=slot+1) ||
        !m47_signature(d,slot,iid,1,0,init_ids,init_types,2) ||
        !m47_signature(d,slot,iid,3,0,cause_ids,uint_types,6) ||
        !m47_signature(d,slot,iid,4,0,release_ids,uint_types,1) ||
        !m47_signature(d,slot,iid,5,1,inito_ids,inito_types,2)) return M44_INVALID;
    if (bindings[slot].kind==1) {
      if (d->target_event != iid*1024+2 ||
          !m47_signature(d,slot,iid,2,0,req_ids,req_types,2) ||
          !m47_signature(d,slot,iid,7,1,intent_ids,uint_types,6) ||
          !m47_signature(d,slot,iid,6,1,cnf_ids,cnf_types,3)) return M44_INVALID;
    } else if (!m47_signature(d,slot,iid,2,0,rsp_ids,rsp_types,5)) return M44_INVALID;
  }
  M44Status status=m45_supervisor_init(session,d,handles);
  if (!status) {
    authority.bindings[0]=bindings[0]; authority.bindings[1]=bindings[1];
    authority.services=1;
  }
  return status;
}
#if defined(M55_SIGNED_RESIDENT)
uint32_t m47_service_value_type(void) {
  return authority.services && authority.descriptor.service_value_type==3?3:2;
}
#endif
static M44Status m47_ready(uint32_t slot, uint32_t epoch) {
  M44Status status=ready();
  if (status) return status;
  if (!authority.services || slot<1 || slot>2 || epoch!=live()->epoch ||
      (live()->lifecycle!=1 && live()->lifecycle!=2)) return M44_INVALID;
  return M44_OK;
}
static M44Status m47_publish(void) {
  authority.operation=OP_ENQUEUE;
  M44PublicationHooks h=hooks();
  M38Status result=m44_resource_publish(authority.session,&authority,&h);
  authority.busy=0;
  return result ? M44_PUBLICATION : M44_OK;
}
#if defined(M49_MANAGED_DELAY)
M44Status m49_supervisor_init(ResourceSession *session,const M44Descriptor *d,
    const M44Saved handles[2],const M47ProviderBinding bindings[2],M49TimerBinding timer) {
  const uint32_t expire_ids[]={7,8,9,10}, uint_types[]={2,2,2,2};
  const uint32_t arm_ids[]={1,3,4,5,6}, arm_types[]={4,2,2,2,2};
  const uint32_t cancel_ids[]={3,4,5,6};
  if (!d || timer.slot<1 || timer.slot>2 || !timer.instance_id || timer.instance_id>63 ||
      timer.slot!=d->source_slot || !d->time_values[timer.slot-1] ||
      !m47_signature(d,timer.slot-1,timer.instance_id,2,0,0,0,0) ||
      !m47_signature(d,timer.slot-1,timer.instance_id,3,0,expire_ids,uint_types,4) ||
      !m47_signature(d,timer.slot-1,timer.instance_id,5,1,arm_ids,arm_types,5) ||
      !m47_signature(d,timer.slot-1,timer.instance_id,6,1,cancel_ids,uint_types,4)) return M44_INVALID;
  M44Status status=m47_supervisor_init(session,d,handles,bindings);
  if (!status) { authority.timed=1; authority.timer_binding=timer; }
  return status;
}
#if defined(M50_PERIODIC)
M44Status m50_supervisor_init(ResourceSession *session,const M44Descriptor *d,
    const M44Saved handles[2],const M47ProviderBinding bindings[2],M49TimerBinding timer) {
  M44Status status=m49_supervisor_init(session,d,handles,bindings,timer);
  if (!status) authority.periodic=1;
  return status;
}
#endif
M44Status m49_supervisor_clock(uint32_t epoch,uint64_t now_ms,uint64_t turn) {
  M44Status status=ready();
  if (status) return status;
  if (!authority.timed || epoch!=live()->epoch ||
      (authority.clock_valid && (now_ms<authority.clock_ms || turn<=authority.clock_turn))) return M44_INVALID;
  authority.clock_ms=now_ms; authority.clock_turn=turn; authority.clock_valid=1;
#if defined(M51_CONTROLLER)
  if (authority.controller) return m51_clock();
#endif
  const M49TimerLedger *timer=&live()->timer;
  if (timer->phase!=M49_TIMER_ARMED || now_ms<timer->deadline_ms || turn<timer->not_before_turn) return M44_NO_WORK;
  uint32_t slot=authority.timer_binding.slot-1;
  if (live()->counts[slot]>=16 || live()->counts[authority.descriptor.target_slot-1]+authority.descriptor.batch_bound>16) return M44_FULL;
  M44Row row={0}; row.event=m49_event(3); row.count=4;
  for (uint32_t n=0;n<4;n++) row.values[n]=(M44Value){authority.timer_binding.instance_id*1024u+7+n,2,(uint32_t)((timer->generation>>(16*n))&65535)};
  if (!valid_row(slot,&row,0)) return M44_INVALID;
  authority.busy=1; *stage()=*live(); stage()->timer.phase=M49_TIMER_QUEUED;
  stage()->queues[slot][stage()->counts[slot]++]=row;
  return m47_publish();
}
#endif
#include "m51_controller_authority.inc"
uint32_t m47_provider_receive_holds(void) { return authority.receive_holds; }
M44Status m47_provider_receive_hold(uint32_t slot,uint32_t epoch,uint32_t pending) {
  M44Status status=m47_ready(slot,epoch);
  if (status) return status;
  if (pending>1 || authority.bindings[slot-1].kind!=2 ||
      live()->providers[slot-1].phase!=1 ||
      (pending && (live()->providers[slot-1].rx_state || live()->providers[slot-1].release_queued)) ||
      (!pending && live()->providers[slot-1].rx_state!=1)) return M44_INVALID;
  uint32_t bit=1u<<(slot-1);
  if (pending) authority.receive_holds|=bit;
  else authority.receive_holds&=~bit;
  return M44_OK;
}
M44Status m47_provider_claim(uint32_t slot, uint32_t epoch, uint64_t token) {
  M44Status status=m47_ready(slot,epoch);
  if (status) return status;
  const M47ProviderLedger *p=&live()->providers[slot-1];
  if (authority.bindings[slot-1].kind!=1 || p->phase!=1 || p->tx_state!=1 ||
      !token || p->tx_token!=token) return M44_INVALID;
  authority.busy=1; *stage()=*live();
  stage()->providers[slot-1].tx_state=2;
  return m47_publish();
}
M44Status m47_provider_enqueue(uint32_t slot, uint32_t epoch, const M44Row *row) {
  M44Status status=m47_ready(slot,epoch);
  if (status) return status;
  uint32_t index=slot-1;
  if (!row || row->sequence || !m47_private(index,row->event) ||
      !valid_row(index,row,0)) return M44_INVALID;
  const M47ProviderLedger *p=&live()->providers[index];
  if (p->phase!=1 || p->release_queued) return M44_INVALID;
  uint32_t kind=authority.bindings[index].kind;
  uint64_t token=0;
  if (row->event==m47_event(index,3)) {
    token=m47_token(row,0);
    if (!token || token>>63 || row->values[5].raw>2) return M44_INVALID;
    if (kind==1) {
      if (p->tx_state!=2 || token!=p->tx_token || row->values[4].raw!=p->tx_value) return M44_INVALID;
    } else {
      if (p->rx_state || token<=p->rx_highwater) return M44_INVALID;
#if defined(M49_MANAGED_DELAY)
      if (!authority.timed)
#endif
      if (live()->counts[authority.descriptor.target_slot-1]+authority.descriptor.batch_bound>16) return M44_FULL;
    }
  } else if (row->event==m47_event(index,2)) {
    token=m47_token(row,1);
    if (kind!=2 || p->rx_state!=2 || token!=p->rx_token || row->values[0].raw!=1) return M44_INVALID;
  } else {
#if defined(M49_MANAGED_DELAY)
    /* A future expiry still owns the provider path, including private RELEASE. */
#if defined(M52_RESIDENT_REPLACEMENT)
    if (authority.resident_replacement && authority.candidate) return M44_INVALID;
#endif
    if (authority.timed && (
#if defined(M51_CONTROLLER)
        authority.controller ? m51_active() :
#endif
        live()->timer.phase)) return M44_INVALID;
#endif
    if ((authority.receive_holds & (1u<<index)) || p->tx_state || p->rx_state || live()->counts[index] ||
        row->values[0].raw>2) return M44_INVALID;
  }
  if (live()->counts[index]>=m47_capacity(index,0)) return M44_FULL;
  authority.busy=1; *stage()=*live();
  M47ProviderLedger *next=&stage()->providers[index];
  if (row->event==m47_event(index,3)) {
    if (kind==1) next->tx_state=3;
    else { next->rx_state=1; next->rx_token=token; next->rx_highwater=token; }
  } else if (row->event==m47_event(index,2)) next->rx_state=3;
  else next->release_queued=1;
  stage()->queues[index][stage()->counts[index]++]=*row;
  return m47_publish();
}
#endif
M44Status m44_supervisor_enqueue(uint32_t slot, const M44Row *row) {
  M44Status status = ready();
  if (status)
    return status;
#if defined(M45_MANAGED_LIFECYCLE)
  if (authority.managed && live()->lifecycle != 1)
    return M44_INVALID;
#endif
  if (slot < 1 || slot > 2 || !row || row->sequence ||
      !valid_row(slot - 1, row, 0) ||
      (slot == authority.descriptor.target_slot &&
       row->event == authority.descriptor.target_event))
    return M44_INVALID;
#if defined(M47_MANAGED_SERVICES)
#if defined(M49_MANAGED_DELAY)
  if (m49_private(slot-1,row->event)) return M44_INVALID;
#if defined(M51_CONTROLLER)
  if (authority.controller && slot==authority.completion.target_slot &&
      row->event==authority.completion.target_event) return M44_INVALID;
#endif
#endif
  if (m47_private(slot-1,row->event) ||
      (authority.services && row->event == m47_event(slot-1,1) &&
       live()->providers[slot-1].release_queued)) return M44_INVALID;
#endif
#if defined(M47_MANAGED_SERVICES)
  if (m47_public_release(slot-1,row)) {
#if defined(M52_RESIDENT_REPLACEMENT)
    if (authority.resident_replacement && authority.candidate) return M44_INVALID;
#endif
#if defined(M49_MANAGED_DELAY)
    if (authority.timed && (
#if defined(M51_CONTROLLER)
        authority.controller ? m51_active() :
#endif
        live()->timer.phase)) return M44_INVALID;
#endif
    const M47ProviderLedger *p=&live()->providers[slot-1];
    if ((authority.receive_holds & (1u<<(slot-1))) || p->phase!=1 || p->tx_state || p->rx_state || live()->counts[slot-1]) return M44_INVALID;
  }
#endif
#if defined(M47_MANAGED_SERVICES)
  if (live()->counts[slot - 1] >= m47_capacity(slot-1,0))
#else
  if (live()->counts[slot - 1] == 16)
#endif
    return M44_FULL;
  authority.busy = 1;
  *stage() = *live();
  stage()->queues[slot - 1][stage()->counts[slot - 1]++] = *row;
#if defined(M47_MANAGED_SERVICES)
  if (m47_public_release(slot-1,row)) stage()->providers[slot-1].release_queued=1;
#endif
  authority.operation = OP_ENQUEUE;
  M44PublicationHooks h = hooks();
  M38Status r = m44_resource_publish(authority.session, &authority, &h);
  authority.busy = 0;
  return r ? M44_PUBLICATION : M44_OK;
}
M44Status m44_supervisor_dispatch(void) {
  M44Status status = ready();
  if (status)
    return status;
#if defined(M45_MANAGED_LIFECYCLE)
  if (authority.managed && live()->lifecycle != 1)
    return M44_INVALID;
#endif
  uint32_t slot = live()->cursor - 1;
  if (!live()->counts[slot])
    slot ^= 1u;
  if (!live()->counts[slot])
    return M44_NO_WORK;
  authority.busy = 1;
  authority.selected = slot;
  *stage() = *live();
  retire(stage(), slot);
  stage()->output_count = 0;
  byte_fill(stage()->outputs, 0, sizeof(stage()->outputs));
  byte_fill(stage()->output_slots, 0, sizeof(stage()->output_slots));
  stage()->fault = 0;
  authority.operation = OP_TURN;
  authority.turn_fault = M44_FAULT_NONE;
  const M44Row *row = &live()->queues[slot][0];
  noun values[16] = {0}, value_list = NOUN_ZERO, stimulus = NOUN_ZERO,
       req = NOUN_ZERO;
  int built = 1;
  heap_set_mode(HEAP_MODE_PERSIST);
  for (uint32_t i = 0; i < row->count; i++) {
    noun vf[3] = {direct(row->values[i].id), direct(row->values[i].type),
                  direct(row->values[i].raw)};
    if (!tagged("m38-resource-abi-v1-numeric-value", value_schema(slot), vf, 3,
                &values[i]))
      built = 0;
  }
  noun sf[2];
  if (!build(values, row->count, &value_list))
    built = 0;
  sf[0] = direct(row->event);
  sf[1] = value_list;
  if (!tagged("m38-resource-abi-v1-numeric-stimulus",
              "m38-resource-abi-v1-numeric-stimulus-schema-v1", sf, 2,
              &stimulus) ||
      !request(slot, 2, stimulus, &req))
    built = 0;
  M44PublicationHooks h = hooks();
  const ResourceResultView *view = 0;
  M38Status r = built ? m44_resource_dispatch(authority.session, &authority,
                                              req, &h, &view)
                      : M38_STATUS_REQUEST_INVALID;
  if (!r && view && view->wire_status == 2) {
    authority.busy = 0;
    return M44_OK;
  }
  *stage() = *live();
  retire(stage(), slot);
#if defined(M47_MANAGED_SERVICES)
  if (m47_private(slot,row->event) || m47_public_release(slot,row)
#if defined(M49_MANAGED_DELAY)
      || m49_private(slot,row->event)
#if defined(M51_CONTROLLER)
      || (authority.controller && row->sequence &&
          ((slot+1==authority.descriptor.target_slot && row->event==authority.descriptor.target_event) ||
           (slot+1==authority.completion.target_slot && row->event==authority.completion.target_event)))
#endif
#endif
      ) stage()->fenced=1;
#endif
  stage()->fault = authority.turn_fault
                       ? authority.turn_fault
                       : (!built ? M44_FAULT_PUBLICATION
                                 : (!r || r == M38_STATUS_EVALUATOR_ABORT
                                        ? M44_FAULT_EVALUATION
                                        : M44_FAULT_PUBLICATION));
  stage()->output_count = 0;
  byte_fill(stage()->outputs, 0, sizeof(stage()->outputs));
  byte_fill(stage()->output_slots, 0, sizeof(stage()->output_slots));
  authority.operation = OP_RETIRE;
  r = m44_resource_publish(authority.session, &authority, &h);
  if (r)
    live()->fenced = 1;
  authority.busy = 0;
#if defined(M47_MANAGED_SERVICES)
  return r || live()->fenced ? M44_FENCED : M44_RETIRED;
#else
  return r ? M44_FENCED : M44_RETIRED;
#endif
}
M44Status m44_supervisor_capture(uint32_t *token) {
#if defined(M47_MANAGED_SERVICES)
  if (authority.services) return M44_INVALID;
#endif
  M44Status status = ready();
  if (status)
    return status;
#if defined(M45_MANAGED_LIFECYCLE)
  if (authority.managed && live()->lifecycle != 2)
    return M44_INVALID;
#endif
  if (!token || authority.token == UINT32_MAX)
    return M44_INVALID;
  authority.busy = 1;
  authority.operation = OP_CAPTURE;
  authority.checkpoints[authority.snapshot_bank ^ 1u] = *live();
  noun handles[2], snapshots[2] = {NOUN_ZERO, NOUN_ZERO};
  int ok = decode(&authority.handles[0], &handles[0]) &&
           decode(&authority.handles[1], &handles[1]);
  M44PublicationHooks h = hooks();
  const ResourceResultView *view = 0;
  M38Status r = ok ? m44_resource_group(authority.session, &authority, 0,
                                        handles, snapshots, &h, &view)
                   : M38_STATUS_REQUEST_INVALID;
  authority.busy = 0;
  if (r)
    return M44_PUBLICATION;
  *token = authority.token;
  return M44_OK;
}
M44Status m44_supervisor_restore(uint32_t token) {
#if defined(M47_MANAGED_SERVICES)
  if (authority.services) return M44_INVALID;
#endif
  M44Status status = ready();
  if (status)
    return status;
#if defined(M45_MANAGED_LIFECYCLE)
  if (authority.managed && live()->lifecycle != 2)
    return M44_INVALID;
#endif
#if defined(M45_MANAGED_LIFECYCLE)
  if (authority.managed && (!authority.checkpoint_valid ||
      authority.checkpoints[authority.snapshot_bank].epoch != live()->epoch))
    return M44_INVALID;
#endif
  if (!token || token != authority.token)
    return M44_INVALID;
  authority.busy = 1;
  authority.operation = OP_RESTORE;
  *stage() = authority.checkpoints[authority.snapshot_bank];
#if defined(M45_MANAGED_LIFECYCLE)
  if (authority.managed) {
    stage()->lifecycle = 2;
    stage()->epoch = live()->epoch;
  }
#endif
  noun handles[2], snapshots[2];
  int ok = 1;
  for (uint32_t i = 0; i < 2; i++)
    if (!decode(&authority.handles[i], &handles[i]) ||
        !decode(&authority.snapshots[authority.snapshot_bank][i],
                &snapshots[i]))
      ok = 0;
  M44PublicationHooks h = hooks();
  const ResourceResultView *view = 0;
  M38Status r = ok ? m44_resource_group(authority.session, &authority, 1,
                                        handles, snapshots, &h, &view)
                   : M38_STATUS_REQUEST_INVALID;
  authority.busy = 0;
  return r ? M44_PUBLICATION : M44_OK;
}
#if defined(M45_MANAGED_LIFECYCLE)
M44Status m45_supervisor_init(ResourceSession *session, const M44Descriptor *d,
                             const M44Saved handles[2]) {
  M44Status status = m44_supervisor_init(session, d, handles);
  if (!status) {
    authority.managed = 1;
    live()->lifecycle = 0;
    live()->epoch = 1;
  }
  return status;
}
uint32_t m45_supervisor_is_managed(void) {
  return authority.initialized && authority.managed;
}
M45Status m45_supervisor_manage(uint32_t command, uint32_t target) {
  if (authority.busy)
    return M45_OVERFLOW;
  if (!authority.initialized || !authority.managed)
    return M45_NOT_READY;
  if (target)
    return M45_NO_SUCH_OBJECT;
  if (command != 2 && command != 3 && command != 7 && command != 8)
    return M45_UNSUPPORTED_CMD;
  if (command == 7)
    return M45_RDY;
  if (live()->fenced)
    return M45_NOT_READY;
  if ((command == 2 && live()->lifecycle != 0 && live()->lifecycle != 2) ||
      (command == 3 && live()->lifecycle != 1) ||
      (command == 8 && live()->lifecycle != 2))
    return M45_INVALID_STATE;
#if defined(M47_MANAGED_SERVICES)
  if (authority.services && command == 8) {
#if defined(M52_RESIDENT_REPLACEMENT)
    if (authority.resident_replacement && authority.candidate) return M45_NOT_READY;
#endif
    if (authority.receive_holds) return M45_NOT_READY;
    for (uint32_t i=0;i<2;i++) {
      const M47ProviderLedger *p=&live()->providers[i];
      if (live()->counts[i] || p->phase!=2 || p->tx_state || p->rx_state ||
          p->release_queued) return M45_NOT_READY;
    }
  }
#endif
#if defined(M49_MANAGED_DELAY)
  if (authority.timed && command==8 && (
#if defined(M51_CONTROLLER)
        authority.controller ? m51_active() :
#endif
        live()->timer.phase)) return M45_NOT_READY;
#endif
  if (command == 8 && live()->epoch == UINT32_MAX)
    return M45_NOT_READY;
  authority.busy = 1;
  *stage() = *live();
  M44PublicationHooks h = hooks();
  M38Status result;
  if (command == 8) {
    byte_fill(stage(), 0, sizeof(*stage()));
    stage()->epoch = live()->epoch + 1;
    stage()->cursor = 1;
    authority.operation = OP_RESET;
    noun handles[2];
    const ResourceResultView *view = 0;
    int ok = decode(&authority.handles[0], &handles[0]) &&
             decode(&authority.handles[1], &handles[1]);
    result = ok ? m45_resource_reinitialize(authority.session, &authority,
                                            handles, &h, &view)
                : M38_STATUS_REQUEST_INVALID;
  } else {
    stage()->lifecycle = command == 2 ? 1 : 2;
    authority.operation = OP_MANAGE;
    result = m44_resource_publish(authority.session, &authority, &h);
  }
  authority.busy = 0;
  return result ? M45_NOT_READY : M45_RDY;
}
#endif
const M44State *m44_supervisor_state(void) {
  return authority.initialized && !authority.busy ? live() : 0;
}
M44Status m44_supervisor_inspect(M44ResourceInspection *out) {
  if (!authority.initialized || !out)
    return M44_INVALID;
  if (authority.busy)
    return M44_BUSY;
  authority.busy = 1;
  M38Status r = m44_resource_inspect(authority.session, &authority, out);
  authority.busy = 0;
  return r ? M44_PUBLICATION : M44_OK;
}
M44Status m44_supervisor_restore_checked(uint32_t token,
                                         const uint8_t identity[32],
                                         uint64_t capability) {
#if defined(M47_MANAGED_SERVICES)
  if (authority.services) return M44_INVALID;
#endif
  if (!identity || byte_compare(identity, authority.descriptor.identity, 32))
    return M44_INVALID;
  M44ResourceInspection inspection;
  M44Status status = m44_supervisor_inspect(&inspection);
  if (status)
    return status;
  if (inspection.capability != capability)
    return M44_INVALID;
  return m44_supervisor_restore(token);
}
size_t m44_supervisor_storage_bytes(void) { return sizeof(authority); }
#if defined(M44_G0_TEST_CONTROLS)
void m44_supervisor_test_fault(uint32_t point, uint32_t retirement) {
  if (!authority.busy) {
    authority.copy_fault = point;
    authority.retire_fault = retirement;
  }
}
void m44_supervisor_test_busy(void) {
  if (!authority.busy) {
    authority.busy_probe = 1;
    authority.busy_mask = 0;
  }
}
uint32_t m44_supervisor_test_busy_mask(void) { return authority.busy_mask; }
#if defined(M45_MANAGED_LIFECYCLE)
uint32_t m45_supervisor_test_busy_mask(void) { return authority.management_busy_mask; }
void m45_supervisor_test_epoch(uint32_t epoch) {
  if (authority.initialized && !authority.busy && authority.managed &&
      !live()->fenced && epoch)
    live()->epoch = epoch;
}
M44Status m45_supervisor_test_resource_control(uint32_t point) {
  M44Status status = ready();
  if (status)
    return status;
  if (!authority.managed || (point != 1 && point != 2))
    return M44_INVALID;
  M38Status result = m45_resource_test_control(authority.session, &authority, point);
  return result ? M44_INVALID : M44_OK;
}
#endif
void m44_supervisor_test_sequence(uint32_t sequence) {
  if (authority.initialized && !authority.busy)
    live()->sequence = sequence;
}
#endif
#if defined(M46_LIVE_REPLACEMENT)
M44Status m46_supervisor_init(ResourceSession *s, const M44Descriptor *d,
                              const M44Saved handles[2],
                              const uint8_t compatibility[32]) {
  if (!compatibility)
    return M44_INVALID;
  M44Status status = m45_supervisor_init(s, d, handles);
  if (!status) {
    byte_copy(authority.compatibility, compatibility, 32);
    authority.deployment_generation = 1;
  }
  return status;
}
ResourceSession *m46_supervisor_active_session(void) {
  return authority.session;
}
const M44Descriptor *m46_supervisor_active_descriptor(void) {
  return &authority.descriptor;
}
M44Status m46_supervisor_diagnostics(M46ResourceDiagnostics *out) {
  M44Status status = ready();
  if (status != M44_OK
#if defined(M52_RESIDENT_REPLACEMENT)
      && !(authority.resident_replacement && status == M44_FENCED)
#endif
      )
    return status;
  return m46_resource_diagnostics(authority.session, &authority, out) ==
                 M38_STATUS_OK
             ? M44_OK
             : M44_INVALID;
}
uint32_t m46_supervisor_generation(void) {
  return authority.deployment_generation;
}
uint32_t m46_supervisor_candidate_token(void) {
  return authority.candidate ? authority.candidate_token : 0;
}
M44Status m46_supervisor_stage(ResourceSession *candidate,
                               const M44Descriptor *d,
                               const M44Saved handles[2],
                               const uint8_t compatibility[32],
                               uint32_t expected_generation, uint32_t *token) {
#if defined(M47_MANAGED_SERVICES)
  if (authority.services
#if defined(M52_RESIDENT_REPLACEMENT)
      && !authority.replacement_call
#endif
     ) return M44_INVALID;
#endif
  if (token)
    *token = 0;
  M44Status status = ready();
  if (status)
    return status;
  if (!token || !candidate || !d || !handles || !compatibility ||
      !authority.managed || live()->lifecycle != 1 || authority.candidate ||
      candidate == authority.session ||
      expected_generation != authority.deployment_generation ||
      expected_generation == UINT32_MAX ||
      !byte_compare(d->identity, authority.descriptor.identity, 32) ||
      authority.candidate_serial == UINT32_MAX)
    return M44_INVALID;
  noun decoded[2];
  authority.busy = 1;
  for (uint32_t i = 0; i < 2; i++)
    if (!decode(&handles[i], &decoded[i])) {
      authority.busy = 0;
      return M44_INVALID;
    }
  M38Status r = m44_resource_claim(candidate, &authority, decoded);
  if (r) {
    authority.busy = 0;
    return M44_INVALID;
  }
  size_t offset = offsetof(M44Descriptor, source_slot);
  if (byte_compare(compatibility, authority.compatibility, 32) ||
      byte_compare((const uint8_t *)d + offset,
                   (const uint8_t *)&authority.descriptor + offset,
                   sizeof(*d) - offset) ||
#if defined(M52_RESIDENT_REPLACEMENT)
      (authority.replacement_call ?
#if defined(M54_RESIDENT_REPLACEMENT)
       (authority.resident_replacement==2 ?
        m54_validate_replacement_pair(authority.session,candidate,&authority,&authority.policy) :
        m52_validate_replacement_pair(authority.session,candidate,&authority)) :
#else
       m52_validate_replacement_pair(authority.session,candidate,&authority) :
#endif
#endif
      m46_validate_replacement_pair(authority.session, candidate, &authority)
#if defined(M52_RESIDENT_REPLACEMENT)
      )
#endif
      ) {
    M38Status cleanup = m46_resource_cancel(candidate, &authority);
    authority.busy = 0;
    return cleanup == M38_STATUS_OK ? M44_INVALID : M44_PUBLICATION;
  }
  authority.candidate = candidate;
  authority.candidate_descriptor = *d;
  authority.candidate_handles[0] = handles[0];
  authority.candidate_handles[1] = handles[1];
  authority.candidate_token = ++authority.candidate_serial;
  authority.candidate_generation = expected_generation;
  byte_copy(authority.candidate_old_identity, authority.descriptor.identity,
            32);
  *token = authority.candidate_token;
  authority.busy = 0;
  return M44_OK;
}
static int m46_prepare(void *context, noun result) {
  (void)context;
  (void)result;
#if defined(M44_G0_TEST_CONTROLS)
  uint32_t point = authority.replacement_fault;
  authority.replacement_fault = 0;
  if (point == 1)
    return 0;
  if (point == 5) {
    uint32_t token = 0;
    authority.replacement_busy_mask =
        (m46_supervisor_activate(authority.candidate_token,
                                 authority.deployment_generation) == M44_BUSY
             ? 1u
             : 0u) |
        (m46_supervisor_cancel(authority.candidate_token,
                               authority.deployment_generation) == M44_BUSY
             ? 2u
             : 0u) |
        (m44_supervisor_dispatch() == M44_BUSY ? 4u : 0u) |
        (m46_supervisor_stage(0, 0, 0, 0, 0, &token) == M44_BUSY ? 8u : 0u) |
        (m45_supervisor_manage(3, 0) == M45_OVERFLOW ? 16u : 0u);
#if defined(M52_RESIDENT_REPLACEMENT)
    if (authority.resident_replacement) authority.replacement_busy_mask |=
        (m49_supervisor_clock(live()->epoch,authority.clock_ms,authority.clock_turn+1)==M44_BUSY?32u:0u) |
        (m47_provider_receive_hold(1,live()->epoch,1)==M44_BUSY?64u:0u) |
        (m52_supervisor_activate(authority.candidate_token,authority.deployment_generation,0)==M44_BUSY?128u:0u);
#endif
    return 0;
  }
  if (point == 2 || point == 3)
    m44_resource_test_fail_publication(authority.candidate, point == 2 ? 2 : 1);
#endif
  return 1;
}
static void m46_commit(void *context) {
  (void)context;
  authority.session = authority.candidate;
  authority.descriptor = authority.candidate_descriptor;
  authority.handles[0] = authority.candidate_handles[0];
  authority.handles[1] = authority.candidate_handles[1];
  authority.deployment_generation++;
  authority.candidate = 0;
  authority.checkpoint_valid = 0;
}
M44Status m46_supervisor_activate(uint32_t token,
                                  uint32_t expected_generation) {
#if defined(M47_MANAGED_SERVICES)
  if (authority.services
#if defined(M52_RESIDENT_REPLACEMENT)
      && !authority.replacement_call
#endif
     ) return M44_INVALID;
#endif
  M44Status s = ready();
  if (s)
    return s;
  if (!authority.managed || live()->lifecycle != 1 || !authority.candidate ||
      !token || token != authority.candidate_token ||
      expected_generation != authority.deployment_generation ||
      expected_generation != authority.candidate_generation ||
      expected_generation == UINT32_MAX ||
      byte_compare(authority.candidate_old_identity,
                   authority.descriptor.identity, 32))
    return M44_INVALID;
  authority.busy = 1;
  noun handles[2];
  int ok = decode(&authority.candidate_handles[0], &handles[0]) &&
           decode(&authority.candidate_handles[1], &handles[1]);
  const ResourceResultView *view;
  M44PublicationHooks h = {m46_prepare, m46_commit, 0};
  M38Status r = ok ? m46_resource_rebind(authority.session, authority.candidate,
                                         &authority, handles, &h, &view)
                   : M38_STATUS_REQUEST_INVALID;
  authority.busy = 0;
  return r ? M44_PUBLICATION : M44_OK;
}
M44Status m46_supervisor_cancel(uint32_t token, uint32_t expected_generation) {
#if defined(M47_MANAGED_SERVICES)
  if (authority.services
#if defined(M52_RESIDENT_REPLACEMENT)
      && !authority.replacement_call
#endif
     ) return M44_INVALID;
#endif
  M44Status s = ready();
  if (s
#if defined(M52_RESIDENT_REPLACEMENT)
      && !(s==M44_FENCED && authority.replacement_call)
#endif
     ) return s;
  if (!authority.candidate || !token || token != authority.candidate_token ||
      expected_generation != authority.deployment_generation)
    return M44_INVALID;
  M38Status r = m46_resource_cancel(authority.candidate, &authority);
  if (!r)
    authority.candidate = 0;
  return r ? M44_PUBLICATION : M44_OK;
}
#if defined(M44_G0_TEST_CONTROLS)
void m46_supervisor_test_fault(uint32_t point) {
  if (!authority.busy && (point <= 3 || point == 5))
    authority.replacement_fault = point;
}
uint32_t m46_supervisor_test_busy_mask(void) {
  return authority.replacement_busy_mask;
}
void m46_supervisor_test_generation(uint32_t generation) {
  if (!authority.busy)
    authority.deployment_generation = generation;
}
void m46_supervisor_test_ticket_serial(uint32_t serial) {
  if (!authority.busy)
    authority.candidate_serial = serial;
}
#endif
#if defined(M52_RESIDENT_REPLACEMENT)
#include "m52_supervisor_replacement.inc"
#if defined(M54_RESIDENT_REPLACEMENT)
#include "m54_supervisor_replacement.inc"
#endif
#endif
#endif

#endif
