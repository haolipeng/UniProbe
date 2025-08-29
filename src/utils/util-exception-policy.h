#ifndef __UTIL_EXCEPTION_POLICY_H__
#define __UTIL_EXCEPTION_POLICY_H__

#include "common/packet-define.h"

enum ExceptionPolicy {
    EXCEPTION_POLICY_IGNORE = 0,
    EXCEPTION_POLICY_PASS_PACKET,
    EXCEPTION_POLICY_PASS_FLOW,
    EXCEPTION_POLICY_BYPASS_FLOW,
    EXCEPTION_POLICY_DROP_PACKET,
    EXCEPTION_POLICY_DROP_FLOW,
    EXCEPTION_POLICY_REJECT,
};

#ifdef DEBUG
extern uint64_t g_eps_applayer_error_offset_ts;
extern uint64_t g_eps_applayer_error_offset_tc;
extern uint64_t g_eps_pcap_packet_loss;
extern uint64_t g_eps_stream_ssn_memcap;
extern uint64_t g_eps_stream_reassembly_memcap;
extern uint64_t g_eps_flow_memcap;
extern uint64_t g_eps_defrag_memcap;
extern bool g_eps_is_alert_queue_fail_mode;
#endif

enum ExceptionPolicy ExceptionPolicyParse(const char *option, const bool support_flow);

#endif
