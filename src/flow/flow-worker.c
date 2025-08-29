#include "detect/detect.h"
#include "utils/packet-queue.h"
#include "flow/flow-spare-pool.h"
#include "flow/flow-timeout.h"
#include "flow/flow-util.h"
#include "reassemble/stream-tcp.h"
#include "reassemble/stream.h"
#include "modules/tmqh-packetpool.h"
#include "modules/tm-modules.h"
#include "utils/util-time.h"
#include "output/output-flow.h"
#include "output/output.h"
#include <stdint.h>

typedef DetectEngineThreadCtx* DetectEngineThreadCtxPtr;

typedef struct FlowTimeoutCounters {
    uint32_t flows_aside_needs_work;
    uint32_t flows_aside_pkt_inject;
} FlowTimeoutCounters;

typedef struct FlowWorkerThreadData_ {
    DecodeThreadVars *dtv;

    union {
        StreamTcpThread *stream_thread;
        void *stream_thread_ptr;
    };

    SC_ATOMIC_DECLARE(DetectEngineThreadCtxPtr, detect_thread);

    void *output_thread; /* Output thread data. */
    void *output_thread_flow; /* Output thread data. */

    uint16_t local_bypass_pkts;
    uint16_t local_bypass_bytes;
    uint16_t both_bypass_pkts;
    uint16_t both_bypass_bytes;

    PacketQueueNoLock pq;
    FlowLookupStruct fls;

    struct {
        uint16_t flows_injected;
        uint16_t flows_removed;
        uint16_t flows_aside_needs_work;
        uint16_t flows_aside_pkt_inject;
    } cnt;

} FlowWorkerThreadData;

static void FlowWorkerFlowTimeout(ThreadVars *tv,Packet *p, FlowWorkerThreadData *fw, void *detect_thread);
Packet *FlowForceReassemblyPseudoPacketGet(int direction, Flow *f, TcpSession *ssn);

/**
 * \internal
 * \brief Forces reassembly for flow if it needs it.
 *
 *        The function requires flow to be locked beforehand.
 *
 * \param f Pointer to the flow.
 *
 * \retval cnt number of packets injected
 */
static int FlowFinish(ThreadVars *tv,Flow *f, FlowWorkerThreadData *fw, void *detect_thread)
{
    Packet *p1 = NULL, *p2 = NULL;
    const int server = f->ffr_tc;
    const int client = f->ffr_ts;

    /* Get the tcp session for the flow */
    TcpSession *ssn = (TcpSession *)f->protoctx;

    if (client == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
        p1 = FlowForceReassemblyPseudoPacketGet(0, f, ssn);
        if (p1 == NULL) {
            return 0;
        }
        PKT_SET_SRC(p1, PKT_SRC_FFR);

        if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
            p2 = FlowForceReassemblyPseudoPacketGet(1, f, ssn);
            if (p2 == NULL) {
                FlowDeReference(&p1->flow);
                //TmqhOutputPacketpool(NULL, p1);//TODO:modify by haolipeng
                return 0;
            }
            PKT_SET_SRC(p2, PKT_SRC_FFR);
            p2->flowflags |= FLOW_PKT_LAST_PSEUDO;
        } else {
            p1->flowflags |= FLOW_PKT_LAST_PSEUDO;
        }
    } else {
        if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
            p1 = FlowForceReassemblyPseudoPacketGet(1, f, ssn);
            if (p1 == NULL) {
                return 0;
            }
            PKT_SET_SRC(p1, PKT_SRC_FFR);
            p1->flowflags |= FLOW_PKT_LAST_PSEUDO;
        } else {
            /* impossible */
            BUG_ON(1);
        }
    }
    f->flags |= FLOW_TIMEOUT_REASSEMBLY_DONE;

    FlowWorkerFlowTimeout(tv,p1, fw, detect_thread);
    PacketPoolReturnPacket(p1);
    if (p2) {
        FlowWorkerFlowTimeout(tv,p2, fw, detect_thread);
        PacketPoolReturnPacket(p2);
        return 2;
    }
    return 1;
}

static void CheckWorkQueue(ThreadVars *tv,FlowWorkerThreadData *fw,
                           void *detect_thread, // TODO proper type?
                           FlowTimeoutCounters *counters,
                           FlowQueuePrivate *fq)
{
    Flow *f;
    while ((f = FlowQueuePrivateGetFromTop(fq)) != NULL) {
        FLOWLOCK_WRLOCK(f);
        f->flow_end_flags |= FLOW_END_FLAG_TIMEOUT; //TODO emerg

        if (f->proto == IPPROTO_TCP) {
            if (!(f->flags & FLOW_TIMEOUT_REASSEMBLY_DONE) && !FlowIsBypassed(f) &&
                FlowForceReassemblyNeedReassembly(f) == 1 && f->ffr != 0) {
                int cnt = FlowFinish(tv, f, fw, detect_thread);
                counters->flows_aside_pkt_inject += cnt;
                counters->flows_aside_needs_work++;
            }
        }

        /* this should not be possible */
        BUG_ON(f->use_cnt > 0);

        /* no one is referring to this flow, use_cnt 0, removed from hash
         * so we can unlock it and pass it to the flow recycler */

        if (fw->output_thread_flow != NULL)
            (void)OutputFlowLog(tv, fw->output_thread_flow, f);

        FlowClearMemory (f, f->protomap);
        FLOWLOCK_UNLOCK(f);
        if (fw->fls.spare_queue.len >= 200) { // TODO match to API? 200 = 2 * block size
            FlowSparePoolReturnFlow(f);
        } else {
            FlowQueuePrivatePrependFlow(&fw->fls.spare_queue, f);
        }
    }
}

/** \brief handle flow for packet
 *
 *  Handle flow creation/lookup
 */
static inline TmEcode FlowUpdate(ThreadVars *tv, FlowWorkerThreadData *fw, Packet *p)
{
    FlowHandlePacketUpdate(p->flow, p, tv, fw->dtv);

    int state = p->flow->flow_state;
    switch (state) {
        case FLOW_STATE_LOCAL_BYPASSED: {
            Flow *f = p->flow;
            FlowDeReference(&p->flow);
            FLOWLOCK_UNLOCK(f);
            return TM_ECODE_DONE;
        }
        default:
            return TM_ECODE_OK;
    }
}

static TmEcode FlowWorkerThreadDeinit(ThreadVars *tv, void *data);

static TmEcode FlowWorkerThreadInit(ThreadVars *tv,const void *initdata, void **data)
{
    FlowWorkerThreadData *fw = calloc(1, sizeof(*fw));
    if (fw == NULL)
        return TM_ECODE_FAILED;

    //SC_ATOMIC_INITPTR(fw->detect_thread);
    //SC_ATOMIC_SET(fw->detect_thread, NULL);

    fw->fls.dtv = fw->dtv = DecodeThreadVarsAlloc(tv);
    if (fw->dtv == NULL) {
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }

    /* setup TCP */
    if (StreamTcpThreadInit(tv, NULL, &fw->stream_thread_ptr) != TM_ECODE_OK) {
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }

    //judge detect engine is Enable or not
    /*if (DetectEngineEnabled()) {
        *//* setup DETECT *//*
        void *detect_thread = NULL;
        if (DetectEngineThreadCtxInit(tv, NULL, &detect_thread) != TM_ECODE_OK) {
            FlowWorkerThreadDeinit(tv, fw);
            return TM_ECODE_FAILED;
        }
        SC_ATOMIC_SET(fw->detect_thread, detect_thread);
    }*/

    /* Setup outputs for this thread. */
    /*if (OutputLoggerThreadInit(tv, initdata, &fw->output_thread) != TM_ECODE_OK) {
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }*/

    if (OutputFlowLogThreadInit(tv, NULL, &fw->output_thread_flow) != TM_ECODE_OK) {
        SCLogError(SC_ERR_THREAD_INIT, "initializing flow log API for thread failed");
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }

    //DecodeRegisterPerfCounters(fw->dtv, tv);
    //AppLayerRegisterThreadCounters(tv);

    /* setup pq for stream end pkts */
    memset(&fw->pq, 0, sizeof(PacketQueueNoLock));
    *data = fw;
    return TM_ECODE_OK;
}

static TmEcode FlowWorkerThreadDeinit(ThreadVars *tv, void *data)
{
    FlowWorkerThreadData *fw = data;

    DecodeThreadVarsFree(tv, fw->dtv);

    /* free TCP */
    StreamTcpThreadDeinit(tv, (void *)fw->stream_thread);

    /* free DETECT function*/
    /*void *detect_thread = SC_ATOMIC_GET(fw->detect_thread);
    if (detect_thread != NULL) {
        DetectEngineThreadCtxDeinit(tv, detect_thread);
        SC_ATOMIC_SET(fw->detect_thread, NULL);
    }*/

    /* Free output function */
    OutputLoggerThreadDeinit(tv, fw->output_thread);
    OutputFlowLogThreadDeinit(tv, fw->output_thread_flow);

    /* free pq */
    BUG_ON(fw->pq.len);

    Flow *f;
    while ((f = FlowQueuePrivateGetFromTop(&fw->fls.spare_queue)) != NULL) {
        FlowFree(f);
    }

    free(fw);
    return TM_ECODE_OK;
}

//TODO: modify by haolipeng
//TmEcode Detect(ThreadVars *tv, Packet *p, void *data);
TmEcode StreamTcp (ThreadVars *,Packet *, void *, PacketQueueNoLock *pq);

static void FlowPruneFiles(Packet *p)
{
    if (p->flow && p->flow->alstate) {
        //TODO:modify by haolipeng app layer parser
        /*Flow *f = p->flow;
        FileContainer *fc = AppLayerParserGetFiles(f,
                                                   PKT_IS_TOSERVER(p) ? STREAM_TOSERVER : STREAM_TOCLIENT);
        if (fc != NULL) {
            FilePrune(fc);
        }*/
    }
}

static inline void FlowWorkerStreamTCPUpdate(ThreadVars *tv,FlowWorkerThreadData *fw, Packet *p,
                                             void *detect_thread, const bool timeout)
{
    StreamTcp(tv, p, fw->stream_thread, &fw->pq);

    if (FlowChangeProto(p->flow)) {
        StreamTcpDetectLogFlush(tv, fw->stream_thread, p->flow, p, &fw->pq);
        //TODO:App Layer modify by haolipeng,this function is used for app layer parser
        //AppLayerParserStateSetFlag(p->flow->alparser, APP_LAYER_PARSER_EOF_TS);
        //AppLayerParserStateSetFlag(p->flow->alparser, APP_LAYER_PARSER_EOF_TC);
    }

    /* Packets here can safely access p->flow as it's locked */
    SCLogDebug("packet %"PRIu64": extra packets %u", p->pcap_cnt, fw->pq.len);
    Packet *x;
    while ((x = PacketDequeueNoLock(&fw->pq))) {
        SCLogDebug("packet %"PRIu64" extra packet %p", p->pcap_cnt, x);

        if (detect_thread != NULL) {
            //TODO:Detect modify by haolipeng
            //Detect(tv, x, detect_thread);
        }

        //TODO:modify by haolipeng output log
        //OutputLoggerLog(tv, x, fw->output_thread);

        if (timeout) {
            PacketPoolReturnPacket(x);
        } else {
            /* put these packets in the preq queue so that they are
             * by the other thread modules before packet 'p'. */
            PacketEnqueueNoLock(&tv->decode_pq, x);
        }
    }
}

static void FlowWorkerFlowTimeout(ThreadVars *tv, Packet *p, FlowWorkerThreadData *fw,void *detect_thread)
{
    DEBUG_VALIDATE_BUG_ON(p->pkt_src != PKT_SRC_FFR);

    SCLogDebug("packet %"PRIu64" is TCP. Direction %s", p->pcap_cnt, PKT_IS_TOSERVER(p) ? "TOSERVER" : "TOCLIENT");
    DEBUG_VALIDATE_BUG_ON(!(p->flow && PKT_IS_TCP(p)));

    /* handle TCP and app layer */
    FlowWorkerStreamTCPUpdate(tv, fw, p, detect_thread, true);

    //TODO:modify by haolipeng
    //PacketUpdateEngineEventCounters(tv, fw->dtv, p);

    /* handle Detect */
    SCLogDebug("packet %"PRIu64" calling Detect", p->pcap_cnt);
    if (detect_thread != NULL) {
        //TODO:Detect modify by haolipeng
        //Detect(tv, p, detect_thread);
    }

    // Outputs.
    //OutputLoggerLog(tv, p, fw->output_thread);

    /* Prune any stored files. */
    //FlowPruneFiles(p);

    /*  Release tcp segments. Done here after alerting can use them. */
    StreamTcpPruneSession(p->flow, p->flowflags & FLOW_PKT_TOSERVER ? STREAM_TOSERVER : STREAM_TOCLIENT);

    /* run tx cleanup last */
    //TODO:modify by haolipeng app layer parser
    //AppLayerParserTransactionsCleanup(p->flow);

    FlowDeReference(&p->flow);
    /* flow is unlocked later in FlowFinish() */
}

/** \internal
 *  \brief process flows injected into our queue by other threads
 */
static inline void FlowWorkerProcessInjectedFlows(ThreadVars *tv,FlowWorkerThreadData *fw,
                                                  Packet *p, void *detect_thread)
{
    /* take injected flows and append to our work queue */
    FlowQueuePrivate injected = { NULL, NULL, 0 };
    if (SC_ATOMIC_GET(tv->flow_queue->non_empty) == true)
        injected = FlowQueueExtractPrivate(tv->flow_queue);
    if (injected.len > 0) {
        FlowTimeoutCounters counters = { 0, 0, };
        CheckWorkQueue(tv, fw, detect_thread, &counters, &injected);
    }
}

/** \internal
 *  \brief process flows set aside locally during flow lookup
 */
static inline void FlowWorkerProcessLocalFlows(ThreadVars *tv,
                                               FlowWorkerThreadData *fw, Packet *p, void *detect_thread)
{
    if (fw->fls.work_queue.len) {
        //StatsAddUI64(tv, fw->cnt.flows_removed, (uint64_t)fw->fls.work_queue.len);

        FlowTimeoutCounters counters = { 0, 0, };
        CheckWorkQueue(tv, fw, detect_thread, &counters, &fw->fls.work_queue);
    }
}

TmEcode FlowWorker(ThreadVars *tv, Packet *p, void *data)
{
    FlowWorkerThreadData *fw = data;
    void *detect_thread = SC_ATOMIC_GET(fw->detect_thread);

    DEBUG_VALIDATE_BUG_ON(p == NULL);
    DEBUG_VALIDATE_BUG_ON(tv->flow_queue == NULL);

    SCLogDebug("packet %"PRIu64, p->pcap_cnt);

    /* update time */
    if (!(PKT_IS_PSEUDOPKT(p))) {
        TimeSetByThread(tv->id, &p->ts);
    }

    /* handle Flow 处理flow数据流*/
    if (p->flags & PKT_WANTS_FLOW) {
        FlowHandlePacket(tv, &fw->fls, p);
        if (likely(p->flow != NULL)) {
            if (FlowUpdate(tv, fw, p) == TM_ECODE_DONE) {
                goto housekeeping;
            }
        }
        /* Flow is now LOCKED */

        /* if PKT_WANTS_FLOW is not set, but PKT_HAS_FLOW is, then this is a
         * pseudo packet created by the flow manager. */
    } else if (p->flags & PKT_HAS_FLOW) {
        FLOWLOCK_WRLOCK(p->flow);
        DEBUG_VALIDATE_BUG_ON(p->pkt_src != PKT_SRC_FFR);
    }

    SCLogDebug("packet %"PRIu64" has flow? %s", p->pcap_cnt, p->flow ? "yes" : "no");

    /* handle TCP and app layer */
    if (p->flow && PKT_IS_TCP(p)) {
        SCLogDebug("packet %"PRIu64" is TCP. Direction %s", p->pcap_cnt, PKT_IS_TOSERVER(p) ? "TOSERVER" : "TOCLIENT");

        /* if detect is disabled, we need to apply file flags to the flow
         * here on the first packet. */
        if (detect_thread == NULL &&
            ((PKT_IS_TOSERVER(p) && (p->flowflags & FLOW_PKT_TOSERVER_FIRST)) ||
             (PKT_IS_TOCLIENT(p) && (p->flowflags & FLOW_PKT_TOCLIENT_FIRST))))
        {
            //TODO:modify by haolipeng
            //DisableDetectFlowFileFlags(p->flow);
        }

        FlowWorkerStreamTCPUpdate(tv, fw, p, detect_thread, false);

        /* handle the app layer part of the UDP packet payload */
    } else if (p->flow && p->proto == IPPROTO_UDP) {
        //TODO:modify by haolipeng
        //AppLayerHandleUdp(tv, fw->stream_thread->ra_ctx->app_tctx, p, p->flow);
    }

    //TODO:modify by haolipeng
    //PacketUpdateEngineEventCounters(tv, fw->dtv, p);

    /* handle Detect */
    SCLogDebug("packet %"PRIu64" calling Detect", p->pcap_cnt);
    //TODO:modify by haolipeng,Detect
    if (detect_thread != NULL) {
        //Detect(tv, p, detect_thread);
    }

    // Outputs.
    //OutputLoggerLog(tv, p, fw->output_thread);

    //TODO: modify by haolipeng ,flow prune files
    /* Prune any stored files. */
    //FlowPruneFiles(p);

    /*  Release tcp segments. Done here after alerting can use them. */
    if (p->flow != NULL) {
        if (FlowIsBypassed(p->flow)) {
            FlowCleanupAppLayer(p->flow);
            if (p->proto == IPPROTO_TCP) {
                StreamTcpSessionCleanup(p->flow->protoctx);
            }
        } else if (p->proto == IPPROTO_TCP && p->flow->protoctx) {
            StreamTcpPruneSession(p->flow, p->flowflags & FLOW_PKT_TOSERVER ?
                                           STREAM_TOSERVER : STREAM_TOCLIENT);
        }

        /* run tx cleanup last */
        //TODO:modify by haolipeng
        //AppLayerParserTransactionsCleanup(p->flow);

        Flow *f = p->flow;
        FlowDeReference(&p->flow);
        FLOWLOCK_UNLOCK(f);
    }

housekeeping:
    /* take injected flows and process them */
    FlowWorkerProcessInjectedFlows(tv, fw, p, detect_thread);

    /* process local work queue */
    FlowWorkerProcessLocalFlows(tv, fw, p, detect_thread);

    return TM_ECODE_OK;
}

void FlowWorkerReplaceDetectCtx(void *flow_worker, void *detect_ctx)
{
    FlowWorkerThreadData *fw = flow_worker;

    SC_ATOMIC_SET(fw->detect_thread, detect_ctx);
}

void *FlowWorkerGetDetectCtxPtr(void *flow_worker)
{
    FlowWorkerThreadData *fw = flow_worker;

    return SC_ATOMIC_GET(fw->detect_thread);
}

void TmModuleFlowWorkerRegister (void)
{
    tmm_modules[TMM_FLOWWORKER].name = "FlowWorker";
    tmm_modules[TMM_FLOWWORKER].ThreadInit = FlowWorkerThreadInit;
    tmm_modules[TMM_FLOWWORKER].Func = FlowWorker;
    tmm_modules[TMM_FLOWWORKER].ThreadDeinit = FlowWorkerThreadDeinit;
    tmm_modules[TMM_FLOWWORKER].flags = TM_FLAG_STREAM_TM|TM_FLAG_DETECT_TM;
}

