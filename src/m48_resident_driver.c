#include "m48_resident_driver.h"
#if defined(M47_MANAGED_SERVICES)
static M44Row cause(uint32_t iid,uint32_t event,uint64_t token,uint32_t value) {
  M44Row row={0};
  row.event=iid*1024+event;
  if (event==4) {
    row.count=1; row.values[0]=(M44Value){iid*1024+5,2,0};
  } else {
    uint32_t start=event==2?1:0;
    if (start) row.values[0]=(M44Value){iid*1024+1,1,1};
    for (uint32_t i=0;i<4;i++)
      row.values[start+i]=(M44Value){iid*1024+11+i,2,(uint32_t)(token>>(16*i))&65535u};
    row.count=start+4;
    if (event==3) {
      row.values[4]=(M44Value){iid*1024+3,2,value};
      row.values[5]=(M44Value){iid*1024+5,2,0}; row.count=6;
    }
  }
  return row;
}
M44Status m48_resident_init(M48ResidentDriver *d,const M47ProviderBinding b[2],
                            const M48Adapter *a) {
  if (!d || !b || !a || !a->receive || !a->completion || !a->submit || !a->release_ready ||
      b[0].slot!=1 || b[1].slot!=2 || !b[0].kind || !b[1].kind ||
      b[0].kind>2 || b[1].kind>2 || b[0].kind==b[1].kind ||
      !b[0].instance_id || b[0].instance_id>8 ||
      !b[1].instance_id || b[1].instance_id>8 || !m44_supervisor_state()) return M44_INVALID;
  *d=(M48ResidentDriver){0};
  d->bindings[0]=b[0]; d->bindings[1]=b[1]; d->adapter=*a; d->initialized=1;
  return M44_OK;
}
static uint32_t local(M48ResidentDriver *d,const M48LocalRequest *r) {
  const M44State *s=m44_supervisor_state();
  if (!r || r->kind==M48_LOCAL_NONE) return M48_SKIPPED;
  if (!s || r->epoch!=s->epoch) return M44_INVALID;
  if (r->kind==M48_LOCAL_MANAGE) return m45_supervisor_manage(r->command,r->target);
  if (r->kind==M48_LOCAL_INGRESS) return m44_supervisor_enqueue(r->slot,&r->row);
  if (r->kind==M48_LOCAL_RELEASE && r->slot>=1 && r->slot<=2) {
    if (d->adapter.release_ready(d->adapter.context)!=M48_READY) return M44_INVALID;
    M44Row row=cause(d->bindings[r->slot-1].instance_id,4,0,0);
    return m47_provider_enqueue(r->slot,r->epoch,&row);
  }
  return M44_INVALID;
}
M48TurnResult m48_resident_turn(M48ResidentDriver *d,const M48LocalRequest *r) {
  M48TurnResult out={M48_SKIPPED,M48_SKIPPED,M48_SKIPPED,M48_SKIPPED,
    M48_SKIPPED,M48_SKIPPED,M48_SKIPPED,M48_SKIPPED,M48_SKIPPED};
  if (!d || !d->initialized) { out.local=M44_INVALID; return out; }
  out.local=local(d,r);
  const M44State *s=m44_supervisor_state();
  if (!s || s->fenced || (s->lifecycle!=1 && s->lifecycle!=2)) return out;
  uint32_t pub=d->bindings[0].kind==1?0:1,sub=1-pub;
  uint32_t epoch=s->epoch;
  M47ProviderLedger p=s->providers[pub],q=s->providers[sub];
  /* Old completion storage becomes reusable only after its admitted cause
   * was consumed. Never turn a failed submit into a fresh attempt. */
  if (d->tx_valid && p.tx_state==M47_TX_NONE) {
    d->tx_valid=0; d->tx_observed=0;
  }
  if (d->tx_valid && !d->tx_observed && d->tx_epoch==epoch &&
      p.tx_state==M47_TX_CLAIMED && p.tx_token==d->tx_token) {
    out.completion_poll=d->adapter.completion(d->adapter.context,epoch,d->tx_token,d->tx_value);
    if (out.completion_poll==M48_READY) d->tx_observed=1;
  }
  if (!d->rx_valid && q.phase==M47_SERVICE_OPEN && !q.rx_state && !q.release_queued) {
    uint64_t token=0; uint32_t value=0;
    out.receive_poll=d->adapter.receive(d->adapter.context,epoch,&token,&value);
    if (out.receive_poll==M48_READY) {
      if (!token || token>>63 || token<=q.rx_highwater || value>65535u)
        out.receive_poll=M48_REFUSED;
      else {
        /* Synchronous callbacks cannot reenter authority; eligible hold is
         * acquired before any subsequent local command can run. */
        M44Status held=m47_provider_receive_hold(sub+1,epoch,1);
        if (held!=M44_OK) { out.receive_admit=held; return out; }
        d->rx_valid=1; d->rx_epoch=epoch; d->rx_token=token; d->rx_value=value;
      }
    }
  }
  if (d->tx_valid && d->tx_observed && d->tx_epoch==epoch &&
      p.tx_state==M47_TX_CLAIMED && p.tx_token==d->tx_token) {
    M44Row row=cause(d->bindings[pub].instance_id,3,d->tx_token,d->tx_value);
    out.completion_admit=m47_provider_enqueue(pub+1,epoch,&row);
  }
  if (d->rx_valid) {
    M44Row row=cause(d->bindings[sub].instance_id,3,d->rx_token,d->rx_value);
    out.receive_admit=m47_provider_enqueue(sub+1,d->rx_epoch,&row);
    if (out.receive_admit==M44_OK) {
      M44Status cleared=m47_provider_receive_hold(sub+1,d->rx_epoch,0);
      if (cleared!=M44_OK) { out.receive_admit=cleared; return out; }
      d->rx_valid=0;
    }
  }
  s=m44_supervisor_state(); q=s->providers[sub];
  if (q.rx_state==M47_RX_INDICATED) {
    M44Row row=cause(d->bindings[sub].instance_id,2,q.rx_token,0);
    out.response_admit=m47_provider_enqueue(sub+1,epoch,&row);
  }
  s=m44_supervisor_state();
#if defined(M49_MANAGED_DELAY)
  if (d->before_dispatch) {
    d->before_dispatch_status=d->before_dispatch(d->before_dispatch_context);
    if (d->before_dispatch_status!=M44_OK && d->before_dispatch_status!=M44_NO_WORK && d->before_dispatch_status!=M44_FULL) {
      out.dispatch=d->before_dispatch_status; return out;
    }
  }
#endif
  if (s->lifecycle==1) out.dispatch=m44_supervisor_dispatch();
  s=m44_supervisor_state(); p=s->providers[pub];
  if (!s->fenced && p.phase==M47_SERVICE_OPEN && p.tx_state==M47_TX_COMMITTED) {
    out.claim=m47_provider_claim(pub+1,epoch,p.tx_token);
    if (out.claim==M44_OK) {
      d->tx_valid=1; d->tx_observed=0; d->tx_epoch=epoch;
      d->tx_token=p.tx_token; d->tx_value=p.tx_value;
      out.submit=d->adapter.submit(d->adapter.context,epoch,p.tx_token,p.tx_value);
    }
  }
  return out;
}
#endif
