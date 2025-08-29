#ifndef NET_THREAT_DETECT_DECODE_THREAD_VAR_H
#define NET_THREAT_DETECT_DECODE_THREAD_VAR_H
#include <stdint.h>
#include "decode-events.h"

typedef struct DecodeThreadVars_
{
  /** Specific context for udp protocol detection (here atm) */
  //AppLayerThreadCtx *app_tctx;

  /** stats/counters */
  uint16_t counter_pkts;
  uint16_t counter_bytes;
  uint16_t counter_avg_pkt_size;
  uint16_t counter_max_pkt_size;
  uint16_t counter_max_mac_addrs_src;
  uint16_t counter_max_mac_addrs_dst;

  uint16_t counter_invalid;

  uint16_t counter_eth;
  uint16_t counter_chdlc;
  uint16_t counter_ipv4;
  uint16_t counter_ipv6;
  uint16_t counter_tcp;
  uint16_t counter_udp;
  uint16_t counter_icmpv4;
  uint16_t counter_icmpv6;

  uint16_t counter_sll;
  uint16_t counter_raw;
  uint16_t counter_null;
  uint16_t counter_sctp;
  uint16_t counter_ppp;
  uint16_t counter_geneve;
  uint16_t counter_gre;
  uint16_t counter_vlan;
  uint16_t counter_vlan_qinq;
  uint16_t counter_vxlan;
  uint16_t counter_vntag;
  uint16_t counter_ieee8021ah;
  uint16_t counter_pppoe;
  uint16_t counter_teredo;
  uint16_t counter_mpls;
  uint16_t counter_ipv4inipv6;
  uint16_t counter_ipv6inipv6;
  uint16_t counter_erspan;

  /** frag stats - defrag runs in the context of the decoder. */
  uint16_t counter_defrag_ipv4_fragments;
  uint16_t counter_defrag_ipv4_reassembled;
  uint16_t counter_defrag_ipv4_timeouts;
  uint16_t counter_defrag_ipv6_fragments;
  uint16_t counter_defrag_ipv6_reassembled;
  uint16_t counter_defrag_ipv6_timeouts;
  uint16_t counter_defrag_max_hit;

  uint16_t counter_flow_memcap;

  uint16_t counter_flow_tcp;
  uint16_t counter_flow_udp;
  uint16_t counter_flow_icmp4;
  uint16_t counter_flow_icmp6;
  uint16_t counter_flow_tcp_reuse;
  uint16_t counter_flow_get_used;
  uint16_t counter_flow_get_used_eval;
  uint16_t counter_flow_get_used_eval_reject;
  uint16_t counter_flow_get_used_eval_busy;
  uint16_t counter_flow_get_used_failed;

  uint16_t counter_flow_spare_sync;
  uint16_t counter_flow_spare_sync_empty;
  uint16_t counter_flow_spare_sync_incomplete;
  uint16_t counter_flow_spare_sync_avg;

  uint16_t counter_engine_events[DECODE_EVENT_MAX];

  /* thread data for flow logging api: only used at forced
     * flow recycle during lookups */
  void *output_flow_thread_data;

} DecodeThreadVars;

typedef struct ThreadVars_ ThreadVars;
DecodeThreadVars *DecodeThreadVarsAlloc(ThreadVars *);
void DecodeThreadVarsFree(ThreadVars *, DecodeThreadVars *);

#endif // NET_THREAT_DETECT_DECODE_THREAD_VAR_H
