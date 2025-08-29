#ifndef __FLOW_UTIL_H__
#define __FLOW_UTIL_H__

#define COPY_TIMESTAMP(src,dst) ((dst)->tv_sec = (src)->tv_sec, (dst)->tv_usec = (src)->tv_usec)

#define RESET_COUNTERS(f) do { \
        (f)->todstpktcnt = 0; \
        (f)->tosrcpktcnt = 0; \
        (f)->todstbytecnt = 0; \
        (f)->tosrcbytecnt = 0; \
    } while (0)

#define FLOW_INITIALIZE(f) do { \
        (f)->sp = 0; \
        (f)->dp = 0; \
        (f)->proto = 0; \
        (f)->livedev = NULL; \
        (f)->timeout_at = 0; \
        (f)->timeout_policy = 0; \
        (f)->vlan_idx = 0; \
        (f)->next = NULL; \
        (f)->flow_state = 0; \
        (f)->use_cnt = 0; \
        (f)->tenant_id = 0; \
        (f)->parent_id = 0; \
        (f)->probing_parser_toserver_alproto_masks = 0; \
        (f)->probing_parser_toclient_alproto_masks = 0; \
        (f)->flags = 0; \
        (f)->file_flags = 0; \
        (f)->protodetect_dp = 0; \
        (f)->lastts.tv_sec = 0; \
        (f)->lastts.tv_usec = 0; \
        FLOWLOCK_INIT((f)); \
        (f)->protoctx = NULL; \
        (f)->flow_end_flags = 0; \
        (f)->alproto = 0; \
        (f)->alproto_ts = 0; \
        (f)->alproto_tc = 0; \
        (f)->alproto_orig = 0; \
        (f)->alproto_expect = 0; \
        (f)->de_ctx_version = 0; \
        (f)->thread_id[0] = 0; \
        (f)->thread_id[1] = 0; \
        (f)->alparser = NULL; \
        (f)->alstate = NULL; \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        RESET_COUNTERS((f)); \
    } while (0)

#define FLOW_RECYCLE(f) do { \
        FlowCleanupAppLayer((f)); \
        (f)->sp = 0; \
        (f)->dp = 0; \
        (f)->proto = 0; \
        (f)->livedev = NULL; \
        (f)->vlan_idx = 0; \
        (f)->ffr = 0; \
        (f)->next = NULL; \
        (f)->timeout_at = 0; \
        (f)->timeout_policy = 0; \
        (f)->flow_state = 0; \
        (f)->use_cnt = 0; \
        (f)->tenant_id = 0; \
        (f)->parent_id = 0; \
        (f)->probing_parser_toserver_alproto_masks = 0; \
        (f)->probing_parser_toclient_alproto_masks = 0; \
        (f)->flags = 0; \
        (f)->file_flags = 0; \
        (f)->protodetect_dp = 0; \
        (f)->lastts.tv_sec = 0; \
        (f)->lastts.tv_usec = 0; \
        (f)->protoctx = NULL; \
        (f)->flow_end_flags = 0; \
        (f)->alparser = NULL; \
        (f)->alstate = NULL; \
        (f)->alproto = 0; \
        (f)->alproto_ts = 0; \
        (f)->alproto_tc = 0; \
        (f)->alproto_orig = 0; \
        (f)->alproto_expect = 0; \
        (f)->de_ctx_version = 0; \
        (f)->thread_id[0] = 0; \
        (f)->thread_id[1] = 0; \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        RESET_COUNTERS((f)); \
    } while(0)

#define FLOW_DESTROY(f) do { \
        FlowCleanupAppLayer((f)); \
        \
        FLOWLOCK_DESTROY((f)); \
    } while(0)

/** \brief check if a memory alloc would fit in the memcap
 *
 *  \param size memory allocation size to check
 *
 *  \retval 1 it fits
 *  \retval 0 no fit
 */
#define FLOW_CHECK_MEMCAP(size) \
    ((((uint64_t)SC_ATOMIC_GET(flow_memuse) + (uint64_t)(size)) <= SC_ATOMIC_GET(flow_config.memcap)))

Flow *FlowAlloc(void);
Flow *FlowAllocDirect(void);
void FlowFree(Flow *);
uint8_t FlowGetProtoMapping(uint8_t);
void FlowInit(Flow *, const Packet *);
uint8_t FlowGetReverseProtoMapping(uint8_t rproto);

#endif /* __FLOW_UTIL_H__ */

