#ifndef NET_THREAT_DETECT_THREADVARS_H
#define NET_THREAT_DETECT_THREADVARS_H

#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

#include "utils/packet-queue.h"
#include "modules/tm-queues.h"
#include "utils/util-atomic.h"
#include "modules/tm-threads.h"

#define THV_USE                 BIT_U32(0)  /** thread is in use */
#define THV_INIT_DONE           BIT_U32(1)  /** thread initialization done */
#define THV_PAUSE               BIT_U32(2)  /** signal thread to pause itself */
#define THV_PAUSED              BIT_U32(3)  /** the thread is paused atm */
#define THV_KILL                BIT_U32(4)  /** thread has been asked to cleanup and exit */
#define THV_FAILED              BIT_U32(5)  /** thread has encountered an error and failed */
#define THV_CLOSED              BIT_U32(6)  /** thread done, should be joinable */
#define THV_DEINIT              BIT_U32(7)
#define THV_RUNNING_DONE        BIT_U32(8)
#define THV_KILL_PKTACQ         BIT_U32(9)  /**< flag thread to stop packet acq */
#define THV_FLOW_LOOP           BIT_U32(10) /**< thread is in flow shutdown loop */

/** signal thread's capture method to create a fake packet to force through
 *  the engine. This is to force timely handling of maintenance taks like
 *  rule reloads even if no packets are read by the capture method. */
#define THV_CAPTURE_INJECT_PKT  BIT_U32(11)
#define THV_DEAD                BIT_U32(12) /**< thread has been joined with pthread_join() */

typedef struct ThreadVars_ {
    pthread_t t;
    void *(*tm_func)(void *);

    char name[16];

    /** the type of thread as defined in tm-threads.h (TVT_PPT, TVT_MGMT) */
    uint8_t type;

    uint16_t cpu_affinity; /** cpu or core number to set affinity to */
    int thread_priority; /** priority (real time) for this thread. Look at threads.h */


    /** TmModule::flags for each module part of this thread */
    uint8_t tmm_flags;

    uint8_t inq_id;
    uint8_t outq_id;

    /** local id */
    int id;

    /** incoming queue and handler */
    Tmq *inq;
    struct Packet_ * (*tmqh_in)(struct ThreadVars_ *);

    SC_ATOMIC_DECLARE(uint32_t, flags);

    struct TmSlot_ *tm_slots;

    /** pointer to the flowworker in the pipeline. Used as starting point
     *  for injected packets. Can be NULL if the flowworker is not part
     *  of this thread. */
    struct TmSlot_ *tm_flowworker;

    /** outgoing queue and handler */
    Tmq *outq;
    void *outctx;
    void (*tmqh_out)(struct ThreadVars_ *, struct Packet_ *);

    PacketQueueNoLock decode_pq;

    struct PacketQueue_ *stream_pq;
    struct PacketQueue_ *stream_pq_local;

    /** pointer to the next thread */
    struct ThreadVars_ *next;

    struct FlowQueue_ *flow_queue;
    bool break_loop;

    uint16_t counter_ipv4;
    uint16_t counter_ipv6;
    uint16_t counter_tcp;
    uint16_t counter_udp;
    uint16_t counter_icmpv4;
    uint16_t counter_others;
}ThreadVars;

#endif // NET_THREAT_DETECT_THREADVARS_H
