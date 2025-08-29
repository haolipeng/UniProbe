#include <pcap/dlt.h>
#include <stdbool.h>
#include <stdio.h>

#include "utils/packet-queue.h"
#include "utils/util-pool-thread.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-sack.h"
#include "stream-tcp.h"
#include "modules/tmqh-packetpool.h"
#include "modules/tm-threads-common.h"
#include "utils/conf.h"
#include "utils/util-misc.h"
#include "utils/util-random.h"
#include "utils/util-mem.h"

#define STREAMTCP_DEFAULT_PREALLOC              2048
#define STREAMTCP_DEFAULT_MEMCAP                (64 * 1024 * 1024)  /* 64mb */
#define STREAMTCP_DEFAULT_REASSEMBLY_MEMCAP     (256 * 1024 * 1024) /* 256mb */
#define STREAMTCP_DEFAULT_TOSERVER_CHUNK_SIZE   2560
#define STREAMTCP_DEFAULT_TOCLIENT_CHUNK_SIZE   2560
#define STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED     5

TcpStreamCnf stream_config;
SC_ATOMIC_DECLARE(uint64_t, st_memuse);
static PoolThread *ssn_pool = NULL;
static SCMutex ssn_pool_mutex = SCMUTEX_INITIALIZER; /**< init only, protect initializing and growing pool */

/*********************函数声明区**********************/
static int StreamTcpPacketStateNone(ThreadVars *tv, Packet *p,StreamTcpThread *stt, TcpSession *ssn,PacketQueueNoLock *pq);
static int StreamTcpStateDispatch(ThreadVars *tv, Packet *p,StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq,uint8_t state);
static inline void StreamTcpCloseSsnWithReset(Packet *p, TcpSession *ssn);
static void StreamTcpPacketSetState(Packet *p, TcpSession *ssn,uint8_t state);
static int StreamTcpHandleTimestamp (TcpSession *ssn, Packet *p);
static int StreamTcpValidateTimestamp (TcpSession *ssn, Packet *p);
static int StreamTcpHandleFin(ThreadVars *tv, StreamTcpThread *, TcpSession *, Packet *, PacketQueueNoLock *);
static inline int StreamTcpValidateAck(TcpSession *ssn, TcpStream *, Packet *);

static int StreamTcp3whsQueueSynAck(TcpSession *ssn, Packet *p);

#define OS_POLICY_DEFAULT   OS_POLICY_BSD

void StreamTcpInitMemuse(void)
{
    SC_ATOMIC_INIT(st_memuse);
}

void StreamTcpIncrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_ADD(st_memuse, size);
    SCLogDebug("STREAM %"PRIu64", incr %"PRIu64, StreamTcpMemuseCounter(), size);
    return;
}

void StreamTcpDecrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_SUB(st_memuse, size);
    SCLogDebug("STREAM %"PRIu64", decr %"PRIu64, StreamTcpMemuseCounter(), size);
    return;
}

void StreamTcpStreamCleanup(TcpStream *stream)
{
    if (stream != NULL) {
        //StreamTcpSackFreeList(stream);
        StreamTcpReturnStreamSegments(stream);
        StreamingBufferClear(&stream->sb);
    }
}

void StreamTcpSessionCleanup(TcpSession *ssn)
{
    TcpStateQueue *q, *q_next;

    if (ssn == NULL)
        return;

    StreamTcpStreamCleanup(&ssn->client);
    StreamTcpStreamCleanup(&ssn->server);

    q = ssn->queue;
    while (q != NULL) {
        q_next = q->next;
        free(q);
        q = q_next;
        StreamTcpDecrMemuse((uint64_t)sizeof(TcpStateQueue));
    }
    ssn->queue = NULL;
    ssn->queue_len = 0;

    return ;
}

void StreamTcpSetOSPolicy(TcpStream *stream, Packet *p)
{
  if (PKT_IS_IPV4(p)) {
    stream->os_policy = OS_POLICY_DEFAULT;

  } else if (PKT_IS_IPV6(p)) {
    stream->os_policy = OS_POLICY_DEFAULT;
  }

  if (stream->os_policy == OS_POLICY_BSD_RIGHT)
    stream->os_policy = OS_POLICY_BSD;

  SCLogDebug("Policy is %"PRIu8"", stream->os_policy);
}

/**
 *  \brief macro to update last_ack only if the new value is higher
 *
 *  \param ssn session
 *  \param stream stream to update
 *  \param ack ACK value to test and set
 */
#define StreamTcpUpdateLastAck(ssn, stream, ack) { \
    if (SEQ_GT((ack), (stream)->last_ack)) \
    { \
        printf("ssn %p: last_ack set to %"PRIu32", moved %u forward", (ssn), (ack), (ack) - (stream)->last_ack); \
        if ((SEQ_LEQ((stream)->last_ack, (stream)->next_seq) && SEQ_GT((ack),(stream)->next_seq))) { \
            printf("last_ack just passed next_seq: %u (was %u) > %u", (ack), (stream)->last_ack, (stream)->next_seq); \
        } else { \
            printf("next_seq (%u) <> last_ack now %d", (stream)->next_seq, (int)(stream)->next_seq - (ack)); \
        }\
        (stream)->last_ack = (ack); \
        StreamTcpSackPruneList((stream)); \
    } else { \
        printf("ssn %p: no update: ack %u, last_ack %"PRIu32", next_seq %u (state %u)", \
                    (ssn), (ack), (stream)->last_ack, (stream)->next_seq, (ssn)->state); \
    }\
}

#define StreamTcpAsyncLastAckUpdate(ssn, stream) {                              \
    if ((ssn)->flags & STREAMTCP_FLAG_ASYNC) {                                  \
        if (SEQ_GT((stream)->next_seq, (stream)->last_ack)) {                   \
            uint32_t ack_diff = (stream)->next_seq - (stream)->last_ack;        \
            (stream)->last_ack += ack_diff;                                     \
            printf("ssn %p: ASYNC last_ack set to %"PRIu32", moved %u forward",     \
                    (ssn), (stream)->next_seq, ack_diff);                               \
        }                                                                       \
    }                                                                           \
}

#define StreamTcpUpdateNextSeq(ssn, stream, seq) {                      \
    (stream)->next_seq = seq;                                           \
    printf("ssn %p: next_seq %" PRIu32, (ssn), (stream)->next_seq); \
    StreamTcpAsyncLastAckUpdate((ssn), (stream));                       \
}

/**
 *  \brief macro to update next_win only if the new value is higher
 *
 *  \param ssn session
 *  \param stream stream to update
 *  \param win window value to test and set
 */
#define StreamTcpUpdateNextWin(ssn, stream, win) { \
    uint32_t sacked_size__ = StreamTcpSackedSize((stream)); \
    if (SEQ_GT(((win) + sacked_size__), (stream)->next_win)) { \
        (stream)->next_win = ((win) + sacked_size__); \
    } \
}

int StreamTcpCheckMemcap(uint64_t size)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(stream_config.memcap);
    if (memcapcopy == 0 || size + SC_ATOMIC_GET(st_memuse) <= memcapcopy)
        return 1;
    return 0;
}

uint64_t StreamTcpMemuseCounter(void)
{
    uint64_t memusecopy = SC_ATOMIC_GET(st_memuse);
    return memusecopy;
}

static int RandomGetWrap(void)
{
    unsigned long r;

    do {
        r = RandomGet();
    } while(r >= ULONG_MAX - (ULONG_MAX % RAND_MAX));

    return r % RAND_MAX;
}

/** \internal
 *  \brief Setup TcpStateQueue based on SYN/ACK packet
 */
static inline void StreamTcp3whsSynAckToStateQueue(Packet *p, TcpStateQueue *q)
{
    q->flags = 0;
    q->wscale = 0;
    q->ts = 0;
    q->win = TCP_GET_WINDOW(p);
    q->seq = TCP_GET_SEQ(p);
    q->ack = TCP_GET_ACK(p);
    q->pkt_ts = p->ts.tv_sec;

    if (TCP_GET_SACKOK(p) == 1)
        q->flags |= STREAMTCP_QUEUE_FLAG_SACK;

    if (TCP_HAS_WSCALE(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_WS;
        q->wscale = TCP_GET_WSCALE(p);
    }
    if (TCP_HAS_TS(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_TS;
        q->ts = TCP_GET_TSVAL(p);
    }
}

static inline uint32_t StreamTcpResetGetMaxAck(TcpStream *stream, uint32_t seq)
{
    uint32_t ack = seq;

    if (STREAM_HAS_SEEN_DATA(stream)) {
        const uint32_t tail_seq = STREAM_SEQ_RIGHT_EDGE(stream);
        if (SEQ_GT(tail_seq, ack)) {
            ack = tail_seq;
        }
    }

    return ack;
}

static void StreamTcp3whsSynAckUpdate(TcpSession *ssn, Packet *p, TcpStateQueue *q)
{
    TcpStateQueue update;
    if (likely(q == NULL)) {
        StreamTcp3whsSynAckToStateQueue(p, &update);
        q = &update;
    }

    if (ssn->state != TCP_SYN_RECV) {
        /* update state */
        StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
        SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_RECV", ssn);
    }
    /* sequence number & window */
    ssn->server.isn = q->seq;
    STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
    ssn->server.next_seq = ssn->server.isn + 1;

    ssn->client.window = q->win;
    SCLogDebug("ssn %p: window %" PRIu32 "", ssn, ssn->server.window);

    /* Set the timestamp values used to validate the timestamp of
     * received packets.*/
    if ((q->flags & STREAMTCP_QUEUE_FLAG_TS) &&
        (ssn->client.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP))
    {
        ssn->server.last_ts = q->ts;
        /*SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" "
                   "ssn->client.last_ts %" PRIu32"", ssn,
                   ssn->server.last_ts, ssn->client.last_ts);*/
        ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
        ssn->server.last_pkt_ts = q->pkt_ts;
        if (ssn->server.last_ts == 0)
            ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
    } else {
        ssn->client.last_ts = 0;
        ssn->server.last_ts = 0;
        ssn->client.flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
    }

    ssn->client.last_ack = q->ack;
    ssn->server.last_ack = ssn->server.isn + 1;

    /** check for the presense of the ws ptr to determine if we
     *  support wscale at all */
    if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) &&
        (q->flags & STREAMTCP_QUEUE_FLAG_WS))
    {
        ssn->client.wscale = q->wscale;
    } else {
        ssn->client.wscale = 0;
    }

    if ((ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) &&
        (q->flags & STREAMTCP_QUEUE_FLAG_SACK)) {
        ssn->flags |= STREAMTCP_FLAG_SACKOK;
        SCLogDebug("ssn %p: SACK permitted for session", ssn);
    } else {
        ssn->flags &= ~STREAMTCP_FLAG_SACKOK;
    }

    ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
    ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
    /*SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 "", ssn,
               ssn->server.next_win);
    SCLogDebug("ssn %p: ssn->client.next_win %" PRIu32 "", ssn,
               ssn->client.next_win);
    SCLogDebug("ssn %p: ssn->server.isn %" PRIu32 ", "
               "ssn->server.next_seq %" PRIu32 ", "
               "ssn->server.last_ack %" PRIu32 " "
               "(ssn->client.last_ack %" PRIu32 ")", ssn,
               ssn->server.isn, ssn->server.next_seq,
               ssn->server.last_ack, ssn->client.last_ack);*/
}

/** \internal
 *  \brief Find the Queued SYN/ACK that goes with this ACK
 *  \retval q or NULL */
static TcpStateQueue *StreamTcp3whsFindSynAckByAck(TcpSession *ssn, Packet *p)
{
    uint32_t ack = TCP_GET_SEQ(p);
    uint32_t seq = TCP_GET_ACK(p) - 1;
    TcpStateQueue *q = ssn->queue;

    while (q != NULL) {
        if (seq == q->seq &&
            ack == q->ack) {
            return q;
        }

        q = q->next;
    }

    return NULL;
}

/** \internal
 *  \brief detect timestamp anomalies when processing responses to the
 *         SYN packet.
 *  \retval true packet is ok
 *  \retval false packet is bad
 */
static inline bool StateSynSentValidateTimestamp(TcpSession *ssn, Packet *p)
{
    /* we only care about evil server here, so skip TS packets */
    if (PKT_IS_TOSERVER(p) || !(TCP_HAS_TS(p))) {
        return true;
    }

    TcpStream *receiver_stream = &ssn->client;
    uint32_t ts_echo = TCP_GET_TSECR(p);
    if ((receiver_stream->flags & STREAMTCP_STREAM_FLAG_TIMESTAMP) != 0) {
        if (receiver_stream->last_ts != 0 && ts_echo != 0 &&
            ts_echo != receiver_stream->last_ts)
        {
            SCLogDebug("ssn %p: BAD TSECR echo %u recv %u", ssn,ts_echo, receiver_stream->last_ts);
            return false;
        }
    } else {
        if (receiver_stream->last_ts == 0 && ts_echo != 0) {
            SCLogDebug("ssn %p: BAD TSECR echo %u recv %u", ssn,ts_echo, receiver_stream->last_ts);
            return false;
        }
    }
    return true;
}

static int StreamTcpPacketStateSynSent(Packet *p,TcpSession *ssn,PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    SCLogDebug("ssn %p: pkt received: %s", ssn, PKT_IS_TOCLIENT(p) ?"toclient":"toserver");

    /* check for bad responses */
    if (StateSynSentValidateTimestamp(ssn, p) == false)
        return -1;

    /* RST */
    if (p->tcph->th_flags & TH_RST) {
        //TODO:modify by haolipeng
        //if (!StreamTcpValidateRst(ssn, p))
        //    return -1;

        if (PKT_IS_TOSERVER(p)) {
            if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn) &&
                SEQ_EQ(TCP_GET_WINDOW(p), 0) &&
                SEQ_EQ(TCP_GET_ACK(p), (ssn->client.isn + 1)))
            {
                SCLogDebug("ssn->server.flags |= STREAMTCP_STREAM_FLAG_RST_RECV");
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_RST_RECV;
                StreamTcpCloseSsnWithReset(p, ssn);
            }
        } else {
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_RST_RECV;
            SCLogDebug("ssn->client.flags |= STREAMTCP_STREAM_FLAG_RST_RECV");
            StreamTcpCloseSsnWithReset(p, ssn);
        }

        /* FIN */
    } else if (p->tcph->th_flags & TH_FIN) {
        /** \todo */

        /* SYN/ACK */
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        if (PKT_IS_TOSERVER(p)) {
            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_IN_WRONG_DIRECTION);
            SCLogDebug("ssn %p: SYN/ACK received in the wrong direction", ssn);
            return -1;
        }

        if (!(TCP_HAS_TFO(p) || (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN))) {
            /* Check if the SYN/ACK packet ack's the earlier
             * received SYN packet. */
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.isn + 1))) {
                StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_WITH_WRONG_ACK);
                SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                          "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                          ssn->client.isn + 1);
                return -1;
            }
        } else {
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.next_seq))) {
                StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_WITH_WRONG_ACK);
                SCLogDebug("ssn %p: (TFO) ACK mismatch, packet ACK %" PRIu32 " != "
                           "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                          ssn->client.next_seq);
                return -1;
            }
            SCLogDebug("ssn %p: (TFO) ACK match, packet ACK %" PRIu32 " == "
                       "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                       ssn->client.next_seq);

            ssn->flags |= STREAMTCP_FLAG_TCP_FAST_OPEN;
            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
        }
        StreamTcp3whsSynAckUpdate(ssn, p, /* no queue override */NULL);//no queue override

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state SYN_SENT... resent", ssn);

        if (PKT_IS_TOCLIENT(p)) {
            /* indicate that we're dealing with 4WHS here */
        } else if (PKT_IS_TOSERVER(p)) {
            /*
             * On retransmitted SYN packets, the timestamp value must be updated,
             * to avoid dropping any SYN+ACK packets that respond to a retransmitted SYN
             * with an updated timestamp in StateSynSentValidateTimestamp.
             */
            if ((ssn->client.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP) && TCP_HAS_TS(p)) {
                uint32_t ts_val = TCP_GET_TSVAL(p);

                // Check whether packets have been received in the correct order (only ever update)
                if (ssn->client.last_ts < ts_val) {
                    ssn->client.last_ts = ts_val;
                    ssn->client.last_pkt_ts = p->ts.tv_sec;
                }

                SCLogDebug("ssn %p: Retransmitted SYN. Updated timestamp from packet %" PRIu64, ssn,p->pcap_cnt);
            }
        }

        /** \todo check if it's correct or set event */

    } else if (p->tcph->th_flags & TH_ACK) {
        /* Handle the asynchronous stream, when we receive a  SYN packet
           and now istead of receving a SYN/ACK we receive a ACK from the
           same host, which sent the SYN, this suggests the ASNYC streams.*/
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

static int StreamTcpPacketStateSynRecv(ThreadVars *tv,Packet *p,StreamTcpThread *stt,TcpSession *ssn,PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        //TODO:modify by haolipeng
        //if (!StreamTcpValidateRst(ssn, p))
        //    return -1;

        uint8_t reset = TRUE;
        /* After receiveing the RST in SYN_RECV state and if detection
           evasion flags has been set, then the following operating
           systems will not closed the connection. As they consider the
           packet as stray packet and not belonging to the current
           session, for more information check
           http://www.packetstan.com/2010/06/recently-ive-been-on-campaign-to-make.html */
        if (ssn->flags & STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT) {
            if (PKT_IS_TOSERVER(p)) {
                if ((ssn->server.os_policy == OS_POLICY_LINUX) ||
                    (ssn->server.os_policy == OS_POLICY_OLD_LINUX)
                    )
                {
                    reset = FALSE;
                    SCLogDebug("Detection evasion has been attempted, so"
                               " not resetting the connection !!");
                }
            } else {
                if ((ssn->client.os_policy == OS_POLICY_LINUX) ||
                    (ssn->client.os_policy == OS_POLICY_OLD_LINUX)
                    )
                {
                    reset = FALSE;
                    SCLogDebug("Detection evasion has been attempted, so"
                               " not resetting the connection !!");
                }
            }
        }

        if (reset == TRUE) {
            StreamTcpCloseSsnWithReset(p, ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        /* FIN is handled in the same way as in TCP_ESTABLISHED case */;
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if ((StreamTcpHandleFin(tv,stt,ssn, p, pq)) == -1)
            return -1;
      /* SYN/ACK */
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        SCLogDebug("ssn %p: SYN/ACK packet on state SYN_RECV. resent", ssn);

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK-pkt to server in SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_TOSERVER_ON_SYN_RECV);
            return -1;
        }

        /* Check if the SYN/ACK packets ACK matches the earlier
         * received SYN/ACK packet. */
        if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack))) {
            SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                      "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                      ssn->client.isn + 1);

            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_RESEND_WITH_DIFFERENT_ACK);
            return -1;
        }

        /* Check if the SYN/ACK packet SEQ the earlier
         * received SYN/ACK packet, server resend with different ISN. */
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.isn))) {
            SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                                                                   "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p),ssn->client.isn);

            if (StreamTcp3whsQueueSynAck(ssn, p) == -1)
                return -1;
            SCLogDebug("ssn %p: queued different SYN/ACK", ssn);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state SYN_RECV... resent", ssn);

        if (PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: SYN-pkt to client in SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYN_TOCLIENT_ON_SYN_RECV);
            return -1;
        }

        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
            SCLogDebug("ssn %p: SYN with different SEQ on SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV);
            return -1;
        }

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->queue_len) {
            SCLogDebug("ssn %p: checking ACK against queued SYN/ACKs", ssn);
            TcpStateQueue *q = StreamTcp3whsFindSynAckByAck(ssn, p);
            if (q != NULL) {
                SCLogDebug("ssn %p: here we update state against queued SYN/ACK", ssn);
                StreamTcp3whsSynAckUpdate(ssn, p, /* using queue to update state */q);
            } else {
                SCLogDebug("ssn %p: none found, now checking ACK against original SYN/ACK (state)", ssn);
            }
        }


        /* If the timestamp option is enabled for both the streams, then
         * validate the received packet timestamp value against the
         * stream->last_ts. If the timestamp is valid then process the
         * packet normally otherwise the drop the packet (RFC 1323)*/
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!(StreamTcpValidateTimestamp(ssn, p))) {
                return -1;
            }
        }

        bool ack_indicates_missed_3whs_ack_packet = false;
        /* Check if the ACK received is in right direction. But when we have
         * picked up a mid stream session after missing the initial SYN pkt,
         * in this case the ACK packet can arrive from either client (normal
         * case) or from server itself (asynchronous streams). Therefore
         *  the check has been avoided in this case */
        if (PKT_IS_TOCLIENT(p)) {
            /* special case, handle 4WHS, so SYN/ACK in the opposite
             * direction */
            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK) {
                /*SCLogDebug("ssn %p: ACK received on midstream SYN/ACK "
                           "pickup session",ssn);*/
                /* fall through */
            } else if (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN) {
                SCLogDebug("ssn %p: ACK received on TFO session",ssn);
                /* fall through */

            } else {
                ack_indicates_missed_3whs_ack_packet = true;
            }
        }

        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ""
                   ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                    TCP_GET_ACK(p));

        /* Check both seq and ack number before accepting the packet and
           changing to ESTABLISHED state */
        if ((SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)) &&
            SEQ_EQ(TCP_GET_ACK(p), ssn->server.next_seq)) {
            SCLogDebug("normal pkt");

            /* process the packet normal, No Async streams :) */

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));
            StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
                ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
                ssn->server.next_win = ssn->server.last_ack +
                                       ssn->server.window;
                if (!(ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK)) {
                    /* window scaling for midstream pickups, we can't do much
                     * other than assume that it's set to the max value: 14 */
                    ssn->server.wscale = TCP_WSCALE_MAX;
                    ssn->client.wscale = TCP_WSCALE_MAX;
                    ssn->flags |= STREAMTCP_FLAG_SACKOK;
                }
            }

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx,ssn,&ssn->client, p, pq);

            /* If asynchronous stream handling is allowed then set the session,
               if packet's seq number is equal the expected seq no.*/
        } else if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)){
            ssn->flags |= STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT;
            SCLogDebug("ssn %p: wrong ack nr on packet, possible evasion!!",ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_RIGHT_SEQ_WRONG_ACK_EVASION);
            return -1;

            /* SYN/ACK followed by more TOCLIENT suggesting packet loss */
        } else if (PKT_IS_TOCLIENT(p) &&
                   SEQ_GT(TCP_GET_SEQ(p), ssn->client.next_seq) &&
                   SEQ_GT(TCP_GET_ACK(p), ssn->client.last_ack)) {
            SCLogDebug("ssn %p: ACK for missing data", ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            SCLogDebug("ssn %p: ACK for missing data: ssn->server.next_seq %u", ssn,ssn->server.next_seq);
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

            ssn->client.window = TCP_GET_WINDOW(p);
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

            /* if we get a packet with a proper ack, but a seq that is beyond
             * next_seq but in-window, we probably missed some packets */
        } else if (SEQ_GT(TCP_GET_SEQ(p), ssn->client.next_seq) &&
                   SEQ_LEQ(TCP_GET_SEQ(p), ssn->client.next_win) &&
                   SEQ_EQ(TCP_GET_ACK(p), ssn->server.next_seq)) {
            SCLogDebug("ssn %p: ACK for missing data", ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            SCLogDebug("ssn %p: ACK for missing data: ssn->client.next_seq %u", ssn, ssn->client.next_seq);
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->client.window = TCP_GET_WINDOW(p);
                ssn->server.next_win = ssn->server.last_ack +
                                       ssn->server.window;
                /* window scaling for midstream pickups, we can't do much
                 * other than assume that it's set to the max value: 14 */
                ssn->server.wscale = TCP_WSCALE_MAX;
                ssn->client.wscale = TCP_WSCALE_MAX;
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
            }

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx,ssn,&ssn->client, p, pq);

            /* toclient packet: after having missed the 3whs's final ACK */
        } else if ((ack_indicates_missed_3whs_ack_packet ||
                    (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN)) &&
                   SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack) &&
                   SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
            if (ack_indicates_missed_3whs_ack_packet) {
                SCLogDebug("ssn %p: packet fits perfectly after a missed 3whs-ACK", ssn);
            } else {
                SCLogDebug("ssn %p: (TFO) expected packet fits perfectly after SYN/ACK", ssn);
            }

            StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));

            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx,ssn, &ssn->server, p, pq);

        } else {
            SCLogDebug("ssn %p: wrong seq nr on packet", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_WRONG_SEQ_WRONG_ACK);
            return -1;
        }

        SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 ", ssn->server.last_ack %"PRIu32"", ssn,
                  ssn->server.next_win, ssn->server.last_ack);
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

static TcpStateQueue *StreamTcp3whsFindSynAckBySynAck(TcpSession *ssn, Packet *p)
{
    TcpStateQueue *q = ssn->queue;
    TcpStateQueue search;

    StreamTcp3whsSynAckToStateQueue(p, &search);

    while (q != NULL) {
        if (search.flags == q->flags &&
            search.wscale == q->wscale &&
            search.win == q->win &&
            search.seq == q->seq &&
            search.ack == q->ack &&
            search.ts == q->ts) {
            return q;
        }

        q = q->next;
    }

    return q;
}

static int StreamTcp3whsQueueSynAck(TcpSession *ssn, Packet *p)
{
    /* first see if this is already in our list */
    if (StreamTcp3whsFindSynAckBySynAck(ssn, p) != NULL)
        return 0;

    if (ssn->queue_len == stream_config.max_synack_queued) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue limit reached", ssn);
        StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_FLOOD);
        return -1;
    }

    if (StreamTcpCheckMemcap((uint32_t)sizeof(TcpStateQueue)) == 0) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue failed: stream memcap reached", ssn);
        return -1;
    }

    TcpStateQueue *q = malloc(sizeof(*q));
    if (unlikely(q == NULL)) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue failed: alloc failed", ssn);
        return -1;
    }
    memset(q, 0x00, sizeof(*q));
    StreamTcpIncrMemuse((uint64_t)sizeof(TcpStateQueue));

    StreamTcp3whsSynAckToStateQueue(p, q);

    /* put in list */
    q->next = ssn->queue;
    ssn->queue = q;
    ssn->queue_len++;
    return 0;
}

static int HandleEstablishedPacketToServer(ThreadVars *tv,TcpSession *ssn, Packet *p,StreamTcpThread *stt ,PacketQueueNoLock *pq)
{
    SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ","
               "ACK %" PRIu32 ", WIN %"PRIu16"", ssn, p->payload_len,
               TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));

    if (StreamTcpValidateAck(ssn, &(ssn->server), p) == -1) {
        SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
        StreamTcpSetEvent(p, STREAM_EST_INVALID_ACK);
        return -1;
    }

    /* check for Keep Alive */
    if ((p->payload_len == 0 || p->payload_len == 1) &&
        (TCP_GET_SEQ(p) == (ssn->client.next_seq - 1))) {
        SCLogDebug("ssn %p: pkt is keep alive", ssn);

        /* normal pkt */
    } else if (!(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->client.last_ack))) {
        if (SEQ_GT(ssn->client.last_ack, ssn->client.next_seq) &&
            SEQ_GT((TCP_GET_SEQ(p)+p->payload_len),ssn->client.next_seq))
        {
            SCLogDebug("ssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16
                       " before last_ack %"PRIu32", after next_seq %"PRIu32":"
                       " acked data that we haven't seen before",
                       ssn, TCP_GET_SEQ(p), p->payload_len, ssn->client.last_ack, ssn->client.next_seq);
            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->client.next_seq)) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
            }
        } else {
            SCLogDebug("ssn %p: server => SEQ before last_ack, packet SEQ"
                       " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                       "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                       "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                       p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                       ssn->client.last_ack, ssn->client.next_win,
                       TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);

            SCLogDebug("ssn %p: rejecting because pkt before last_ack", ssn);
            StreamTcpSetEvent(p, STREAM_EST_PKT_BEFORE_LAST_ACK);
            return -1;
        }
    }

    int zerowindowprobe = 0;
    /* zero window probe */
    if (p->payload_len == 1 && TCP_GET_SEQ(p) == ssn->client.next_seq && ssn->client.window == 0) {
        SCLogDebug("ssn %p: zero window probe", ssn);
        zerowindowprobe = 1;

        /* expected packet */
    } else if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
        StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));

        /* not completely as expected, but valid */
    } else if (SEQ_LT(TCP_GET_SEQ(p),ssn->client.next_seq) &&
               SEQ_GT((TCP_GET_SEQ(p)+p->payload_len), ssn->client.next_seq))
    {
        StreamTcpUpdateNextSeq(ssn, &ssn->client, (TCP_GET_SEQ(p) + p->payload_len));
        SCLogDebug("ssn %p: ssn->client.next_seq %"PRIu32
                   " (started before next_seq, ended after)",
                   ssn, ssn->client.next_seq);

        /* if next_seq has fallen behind last_ack, we got some catching up to do */
    } else if (SEQ_LT(ssn->client.next_seq, ssn->client.last_ack)) {
        StreamTcpUpdateNextSeq(ssn, &ssn->client, (TCP_GET_SEQ(p) + p->payload_len));
        SCLogDebug("ssn %p: ssn->client.next_seq %"PRIu32
                   " (next_seq had fallen behind last_ack)",
                   ssn, ssn->client.next_seq);

    } else {
        SCLogDebug("ssn %p: no update to ssn->client.next_seq %"PRIu32
                   " SEQ %u SEQ+ %u last_ack %u",
                   ssn, ssn->client.next_seq,
                   TCP_GET_SEQ(p), TCP_GET_SEQ(p)+p->payload_len, ssn->client.last_ack);
    }

    /* in window check */
    if (zerowindowprobe) {
        SCLogDebug("ssn %p: zero window probe, skipping oow check", ssn);
    } else if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) ||
               (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM)))
    {
        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win "
                   "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
        SCLogDebug("ssn %p: ssn->server.window %"PRIu32"", ssn,ssn->server.window);

        /* Check if the ACK value is sane and inside the window limit */
        StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));
        SCLogDebug("ack %u last_ack %u next_seq %u", TCP_GET_ACK(p), ssn->server.last_ack, ssn->server.next_seq);

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        StreamTcpSackUpdatePacket(&ssn->server, p);

        /* update next_win */
        StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

        /* handle data (if any) */
        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

    } else {
        SCLogDebug("ssn %p: toserver => SEQ out of window, packet SEQ "
                   "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                   "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                   "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                   p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                   ssn->client.last_ack, ssn->client.next_win,
                   (TCP_GET_SEQ(p) + p->payload_len) - ssn->client.next_win);
        SCLogDebug("ssn %p: window %u sacked %u", ssn, ssn->client.window,
                   StreamTcpSackedSize(&ssn->client));
        StreamTcpSetEvent(p, STREAM_EST_PACKET_OUT_OF_WINDOW);
        return -1;
    }
    return 0;
}

static int HandleEstablishedPacketToClient(ThreadVars *tv, TcpSession *ssn, Packet *p,
                                            StreamTcpThread *stt, PacketQueueNoLock *pq)
{
    /*SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ","
               " ACK %" PRIu32 ", WIN %"PRIu16"", ssn, p->payload_len,
               TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));*/

    if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
        SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
        StreamTcpSetEvent(p, STREAM_EST_INVALID_ACK);
        return -1;
    }

    /* To get the server window value from the servers packet, when connection
       is picked up as midstream */
    if ((ssn->flags & STREAMTCP_FLAG_MIDSTREAM) &&
        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED))
    {
        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
        ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
        ssn->flags &= ~STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;
        SCLogDebug("ssn %p: adjusted midstream ssn->server.next_win to "
                   "%" PRIu32 "", ssn, ssn->server.next_win);
    }

    /* check for Keep Alive */
    if ((p->payload_len == 0 || p->payload_len == 1) &&
        (TCP_GET_SEQ(p) == (ssn->server.next_seq - 1))) {
        SCLogDebug("ssn %p: pkt is keep alive", ssn);

        /* normal pkt */
    } else if (!(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->server.last_ack))) {
        if (SEQ_GT(ssn->server.last_ack, ssn->server.next_seq) &&
            SEQ_GT((TCP_GET_SEQ(p)+p->payload_len),ssn->server.next_seq))
        {
            /*SCLogDebug("ssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16
                       " before last_ack %"PRIu32", after next_seq %"PRIu32":"
                       " acked data that we haven't seen before",
                       ssn, TCP_GET_SEQ(p), p->payload_len, ssn->server.last_ack, ssn->server.next_seq);*/
            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->server.next_seq)) {
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));
            }
        } else {
            /*SCLogDebug("ssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16
                       " before last_ack %"PRIu32". next_seq %"PRIu32,
                       ssn, TCP_GET_SEQ(p), p->payload_len, ssn->server.last_ack, ssn->server.next_seq);*/
            StreamTcpSetEvent(p, STREAM_EST_PKT_BEFORE_LAST_ACK);
            return -1;
        }
    }

    int zerowindowprobe = 0;
    /* zero window probe */
    if (p->payload_len == 1 && TCP_GET_SEQ(p) == ssn->server.next_seq && ssn->server.window == 0) {
        SCLogDebug("ssn %p: zero window probe", ssn);
        zerowindowprobe = 1;

        /* expected packet */
    } else if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
        StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));

        /* not completely as expected, but valid */
    } else if (SEQ_LT(TCP_GET_SEQ(p),ssn->server.next_seq) &&
               SEQ_GT((TCP_GET_SEQ(p)+p->payload_len), ssn->server.next_seq))
    {
        StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));
        /*SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32
                   " (started before next_seq, ended after)",
                   ssn, ssn->server.next_seq);*/

        /* if next_seq has fallen behind last_ack, we got some catching up to do */
    } else if (SEQ_LT(ssn->server.next_seq, ssn->server.last_ack)) {
        StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));
        /*SCLogDebug("ssn %p: ssn->server.next_seq %"PRIu32
                   " (next_seq had fallen behind last_ack)",
                   ssn, ssn->server.next_seq);*/

    } else {
        /*SCLogDebug("ssn %p: no update to ssn->server.next_seq %"PRIu32
                   " SEQ %u SEQ+ %u last_ack %u",
                   ssn, ssn->server.next_seq,
                   TCP_GET_SEQ(p), TCP_GET_SEQ(p)+p->payload_len, ssn->server.last_ack);*/
    }

    if (zerowindowprobe) {
        SCLogDebug("ssn %p: zero window probe, skipping oow check", ssn);
    } else if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) ||
               (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM)))
    {
        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win "
                   "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
        SCLogDebug("ssn %p: ssn->client.window %"PRIu32"", ssn, ssn->client.window);

        StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        StreamTcpSackUpdatePacket(&ssn->client, p);

        StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
    } else {
        StreamTcpSetEvent(p, STREAM_EST_PACKET_OUT_OF_WINDOW);
        return -1;
    }
    return 0;
}

static int StreamTcpPacketStateEstablished(ThreadVars *tv, Packet *p,
                                            StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    /* RST */
    if (p->tcph->th_flags & TH_RST) {
        //TODO:modify by haolipeng
        /*if (!StreamTcpValidateRst(ssn, p))
            return -1;*/

        if (PKT_IS_TOSERVER(p)) {
            StreamTcpCloseSsnWithReset(p, ssn);

            ssn->server.next_seq = TCP_GET_ACK(p);
            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn, ssn->server.next_seq);
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
            StreamTcpUpdateLastAck(ssn, &ssn->server,StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,&ssn->client, p, pq);
            /*SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                       "%" PRIu32 "", ssn, ssn->client.next_seq,
                       ssn->server.last_ack);*/
        } else {
            StreamTcpCloseSsnWithReset(p, ssn);

            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
            ssn->client.next_seq = TCP_GET_ACK(p);

            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
            StreamTcpUpdateLastAck(ssn, &ssn->client,StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
        }
        /* FIN */
    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if ((StreamTcpHandleFin(tv, stt, ssn, p, pq)) == -1)
            return -1;

        /* SYN/ACK */
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        SCLogDebug("ssn %p: SYN/ACK packet on state ESTABLISHED... resent",ssn);

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK-pkt to server in ESTABLISHED state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYNACK_TOSERVER);
            return -1;
        }

        /* Check if the SYN/ACK packets ACK matches the earlier
         * received SYN/ACK packet. */
        if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack))) {
            /*SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                       "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                       ssn->client.isn + 1);*/

            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND_WITH_DIFFERENT_ACK);
            return -1;
        }

        /* Check if the SYN/ACK packet SEQ the earlier
         * received SYN packet. */
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.isn))) {
            /*SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                       "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                       ssn->client.isn + 1);*/

            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND_WITH_DIFF_SEQ);
            return -1;
        }

        if (ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED) {
            /* a resend of a SYN while we are established already -- fishy */
            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND);
            return -1;
        }

        /*SCLogDebug("ssn %p: SYN/ACK packet on state ESTABLISHED... resent. "
                   "Likely due server not receiving final ACK in 3whs", ssn);*/
        return 0;

        /* SYN */
    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state ESTABLISHED... resent", ssn);
        if (PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: SYN-pkt to client in EST state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYN_TOCLIENT);
            return -1;
        }

        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
            SCLogDebug("ssn %p: SYN with different SEQ on SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYN_RESEND_DIFF_SEQ);
            return -1;
        }

        /* a resend of a SYN while we are established already -- fishy */
        StreamTcpSetEvent(p, STREAM_EST_SYN_RESEND);
        return -1;
        /* ACK */
    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            /* Process the received packet to server */
            HandleEstablishedPacketToServer(tv, ssn, p, stt, pq);

        } else {
            if (!(ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED)) {
                ssn->flags |= STREAMTCP_FLAG_3WHS_CONFIRMED;
                SCLogDebug("3whs is now confirmed by server");
            }

            /* Process the received packet to client */
            HandleEstablishedPacketToClient(tv, ssn, p, stt, pq);
        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

static int StreamTcpHandleFin(ThreadVars *tv, StreamTcpThread *stt,
                              TcpSession *ssn, Packet *p, PacketQueueNoLock *pq)
{
    if (PKT_IS_TOSERVER(p)) {
        /*SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ","
                   " ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                   TCP_GET_ACK(p));*/

        if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_FIN_INVALID_ACK);
            return -1;
        }

        if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
            SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
        {
            /*SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != "
                       "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p),
                       ssn->client.next_seq);*/

            StreamTcpSetEvent(p, STREAM_FIN_OUT_OF_WINDOW);
            return -1;
        }

        if (p->tcph->th_flags & TH_SYN) {
            SCLogDebug("ssn %p: FIN+SYN", ssn);
            StreamTcpSetEvent(p, STREAM_FIN_SYN);
            return -1;
        }
        StreamTcpPacketSetState(p, ssn, TCP_CLOSE_WAIT);
        SCLogDebug("ssn %p: state changed to TCP_CLOSE_WAIT", ssn);

        if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))
            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;

        SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "", ssn,ssn->client.next_seq);
        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

        StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        /* Update the next_seq, in case if we have missed the client packet
           and server has already received and acked it */
        if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
            ssn->server.next_seq = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

        /*SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                   ssn, ssn->client.next_seq, ssn->server.last_ack);*/
    } else { /* implied to client */
        /*SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", "
                   "ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                   TCP_GET_ACK(p));*/

        if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_FIN_INVALID_ACK);
            return -1;
        }

        if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
            SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
        {
            SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != "
                       "%" PRIu32 " from stream (last_ack %u win %u = %u)", ssn, TCP_GET_SEQ(p),
                       ssn->server.next_seq, ssn->server.last_ack, ssn->server.window, (ssn->server.last_ack + ssn->server.window));

            StreamTcpSetEvent(p, STREAM_FIN_OUT_OF_WINDOW);
            return -1;
        }

        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT1);
        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT1", ssn);

        if (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq))
            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len;

        /*SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                   ssn->server.next_seq);*/
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

        StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        /* Update the next_seq, in case if we have missed the client packet
           and server has already received and acked it */
        if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
            ssn->client.next_seq = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

        SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                   ssn, ssn->server.next_seq, ssn->client.last_ack);
    }

    return 0;
}

/**
 *  \brief Function to check the validity of the received timestamp based on
 *         the target OS of the given stream and update the session.
 *
 *  \param ssn TCP session to which the given packet belongs
 *  \param p Packet which has to be checked for its validity
 *
 *  \retval 1 if the timestamp is valid
 *  \retval 0 if the timestamp is invalid
 */
static int StreamTcpHandleTimestamp (TcpSession *ssn, Packet *p)
{
    TcpStream *sender_stream;
    TcpStream *receiver_stream;
    uint8_t ret = 1;
    uint8_t check_ts = 1;

    if (PKT_IS_TOSERVER(p)) {
        sender_stream = &ssn->client;
        receiver_stream = &ssn->server;
    } else {
        sender_stream = &ssn->server;
        receiver_stream = &ssn->client;
    }

    /* Set up the os_policy to be used in validating the timestamps based on
       the target system */
    if (receiver_stream->os_policy == 0) {
        StreamTcpSetOSPolicy(receiver_stream, p);
    }

    if (TCP_HAS_TS(p)) {
        uint32_t ts = TCP_GET_TSVAL(p);

        if (sender_stream->flags & STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP) {
            /* The 3whs used the timestamp with 0 value. */
            switch (receiver_stream->os_policy) {
                case OS_POLICY_LINUX:
                case OS_POLICY_WINDOWS2K3:
                    /* Linux and windows 2003 does not allow the use of 0 as
                     * timestamp in the 3whs. */
                    ssn->flags &= ~STREAMTCP_FLAG_TIMESTAMP;
                    check_ts = 0;
                    break;

                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_VISTA:
                    sender_stream->flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
                    if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) {
                        sender_stream->last_ts = ts;
                        check_ts = 0; /*next packet will be checked for validity
                                        and stream TS has been updated with this
                                        one.*/
                    }
                    break;
                default:
                    break;
            }
        }

        if (ts == 0) {
            switch (receiver_stream->os_policy) {
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_VISTA:
                    /* Old Linux and windows allowed packet with 0 timestamp. */
                    break;
                default:
                    /* other OS simply drop the pakcet with 0 timestamp, when
                     * 3whs has valid timestamp*/
                    goto invalid;
            }
        }

        if (check_ts) {
            int32_t result = 0;

            SCLogDebug("ts %"PRIu32", last_ts %"PRIu32"", ts, sender_stream->last_ts);

            if (receiver_stream->os_policy == OS_POLICY_LINUX) {
                /* Linux accepts TS which are off by one.*/
                result = (int32_t) ((ts - sender_stream->last_ts) + 1);
            } else {
                result = (int32_t) (ts - sender_stream->last_ts);
            }

            SCLogDebug("result %"PRIi32", p->ts.tv_sec %"PRIuMAX"", result, (uintmax_t)p->ts.tv_sec);

            if (sender_stream->last_pkt_ts == 0 &&
                (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
            {
                sender_stream->last_pkt_ts = p->ts.tv_sec;
            }

            if (result < 0) {
                /*SCLogDebug("timestamp is not valid sender_stream->last_ts "
                           "%" PRIu32 " p->tcpvars->ts %" PRIu32 " result "
                           "%" PRId32 "", sender_stream->last_ts, ts, result);*/
                /* candidate for rejection */
                ret = 0;
            } else if ((sender_stream->last_ts != 0) &&
                       (((uint32_t) p->ts.tv_sec) >
                        sender_stream->last_pkt_ts + PAWS_24DAYS))
            {
                /*SCLogDebug("packet is not valid sender_stream->last_pkt_ts "
                           "%" PRIu32 " p->ts.tv_sec %" PRIu32 "",
                           sender_stream->last_pkt_ts, (uint32_t) p->ts.tv_sec);*/
                /* candidate for rejection */
                ret = 0;
            }

            if (ret == 1) {
                /* Update the timestamp and last seen packet time for this
                 * stream */
                if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                    sender_stream->last_ts = ts;

                sender_stream->last_pkt_ts = p->ts.tv_sec;

            } else if (ret == 0) {
                /* if the timestamp of packet is not valid then, check if the
                 * current stream timestamp is not so old. if so then we need to
                 * accept the packet and update the stream->last_ts (RFC 1323)*/
                if ((SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) &&
                    (((uint32_t) p->ts.tv_sec > (sender_stream->last_pkt_ts + PAWS_24DAYS))))
                {
                    sender_stream->last_ts = ts;
                    sender_stream->last_pkt_ts = p->ts.tv_sec;

                    SCLogDebug("timestamp considered valid anyway");
                } else {
                    goto invalid;
                }
            }
        }
    } else {
        /* Solaris stops using timestamps if a packet is received
           without a timestamp and timestamps were used on that stream. */
        /*if (receiver_stream->os_policy == OS_POLICY_SOLARIS)
            ssn->flags &= ~STREAMTCP_FLAG_TIMESTAMP;*/
    }

    return 1;

invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
    return 0;
}

static TcpSession *StreamTcpNewSession (Packet *p,int id)
{
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if(ssn == NULL) {
        p->flow->protoctx = PoolThreadGetById(ssn_pool, id);
        ssn = (TcpSession *)p->flow->protoctx;//convert void* to TcpSession *
        if(ssn == NULL){
            SCLogDebug("ssn_pool is empty");
            return NULL;
        }

        ssn->state = TCP_NONE;
        ssn->reassembly_depth = stream_config.reassembly_depth;
        ssn->tcp_packet_flags = p->tcph ? p->tcph->th_flags : 0;
        ssn->server.flags = stream_config.stream_init_flags;
        ssn->client.flags = stream_config.stream_init_flags;

        StreamingBuffer x = STREAMING_BUFFER_INITIALIZER(&stream_config.sbcnf);
        ssn->client.sb = x;
        ssn->server.sb = x;

        if (PKT_IS_TOSERVER(p)) {
            ssn->client.tcp_flags = p->tcph ? p->tcph->th_flags : 0;
            ssn->server.tcp_flags = 0;
        } else if (PKT_IS_TOCLIENT(p)) {
            ssn->server.tcp_flags = p->tcph ? p->tcph->th_flags : 0;
            ssn->client.tcp_flags = 0;
        }
    }

    return ssn;
}

static int StreamTcpPacketStateNone(ThreadVars *tv, Packet *p,
                                    StreamTcpThread *stt, TcpSession *ssn,
                                    PacketQueueNoLock *pq)
{
    //meet rst or fin packet when session state is None
    if (p->tcph->th_flags & TH_RST) {
        StreamTcpSetEvent(p, STREAM_RST_BUT_NO_SESSION);
        SCLogDebug("RST packet received, no session setup");
        return -1;

    } else if (p->tcph->th_flags & TH_FIN) {
        StreamTcpSetEvent(p, STREAM_FIN_BUT_NO_SESSION);
        SCLogDebug("FIN packet received, no session setup");
        return -1;
    /* SYN*/
    }else if (p->tcph->th_flags & TH_SYN) {
        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p,stt->ssn_pool_id);
            if (ssn == NULL) {
                return -1;
            }
            //StatsIncr(tv, stt->counter_tcp_sessions);
        }

        /* set the state */
        StreamTcpPacketSetState(p, ssn, TCP_SYN_SENT);
        SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_SENT", ssn);

        /* set the sequence numbers and window */
        ssn->client.isn = TCP_GET_SEQ(p);
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = ssn->client.isn + 1;

        /* Set the stream timestamp value, if packet has timestamp option
         * enabled. */
        if (TCP_HAS_TS(p)) {
            ssn->client.last_ts = TCP_GET_TSVAL(p);
            SCLogDebug("ssn %p: %02x", ssn, ssn->client.last_ts);

            if (ssn->client.last_ts == 0)
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;

            ssn->client.last_pkt_ts = p->ts.tv_sec;
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_TIMESTAMP;
        }

        ssn->server.window = TCP_GET_WINDOW(p);
        if (TCP_HAS_WSCALE(p)) {
            ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
            ssn->server.wscale = TCP_GET_WSCALE(p);
        }

        if (TCP_GET_SACKOK(p) == 1) {
            ssn->flags |= STREAMTCP_FLAG_CLIENT_SACKOK;
            SCLogDebug("ssn %p: SACK permitted on SYN packet", ssn);
        }

        if (TCP_HAS_TFO(p)) {
            ssn->flags |= STREAMTCP_FLAG_TCP_FAST_OPEN;
            if (p->payload_len) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
                SCLogDebug("ssn: %p (TFO) [len: %d] isn %u base_seq %u next_seq %u payload len %u",
                           ssn, p->tcpvars.tfo.len, ssn->client.isn, ssn->client.base_seq, ssn->client.next_seq, p->payload_len);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            }
        }
    }else if (p->tcph->th_flags & TH_ACK) {
        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
            if (ssn == NULL) {
                return -1;
            }
        }

        StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);

        ssn->flags = STREAMTCP_FLAG_MIDSTREAM;
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;

        ssn->client.wscale = TCP_WSCALE_MAX;
        ssn->server.wscale = TCP_WSCALE_MAX;

        /* set the sequence numbers and window */
        ssn->client.isn = TCP_GET_SEQ(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
        ssn->client.last_ack = TCP_GET_SEQ(p);
        ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

        ssn->server.isn = TCP_GET_ACK(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.last_ack = TCP_GET_ACK(p);
        ssn->server.next_win = ssn->server.last_ack;
    }else{
        //TODO: malformed packet received before session setup
    }

    return 0;
}

static inline int StreamTcpStateDispatch(ThreadVars *tv, Packet *p,
                                         StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq,
                                         const uint8_t state)
{
    SCLogDebug("ssn: %p", ssn);
    switch (state) {
        case TCP_SYN_SENT:
            if (StreamTcpPacketStateSynSent(p, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_SYN_RECV:
            if (StreamTcpPacketStateSynRecv(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_ESTABLISHED:
            if (StreamTcpPacketStateEstablished(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_FIN_WAIT1://comment by haolipeng
            /*SCLogDebug("packet received on TCP_FIN_WAIT1 state");
            if (StreamTcpPacketStateFinWait1(p, ssn, pq)) {
                return -1;
            }*/
            break;
        case TCP_FIN_WAIT2://comment by haolipeng
            SCLogDebug("packet received on TCP_FIN_WAIT2 state");
            /*if (StreamTcpPacketStateFinWait2(p, ssn, pq)) {
                return -1;
            }*/
            break;
        case TCP_CLOSING:
            SCLogDebug("packet received on TCP_CLOSING state");
            /*if (StreamTcpPacketStateClosing(p, ssn, pq)) {
                return -1;
            }*/
            break;
        case TCP_CLOSE_WAIT:
            SCLogDebug("packet received on TCP_CLOSE_WAIT state");
            /*if (StreamTcpPacketStateCloseWait(p, ssn, pq)) {
                return -1;
            }*/
            break;
        case TCP_LAST_ACK:
            SCLogDebug("packet received on TCP_LAST_ACK state");
            /*if (StreamTcpPacketStateLastAck(p, ssn, pq)) {
                return -1;
            }*/
            break;
        case TCP_TIME_WAIT:
            SCLogDebug("packet received on TCP_TIME_WAIT state");
            /*if (StreamTcpPacketStateTimeWait(p, ssn, pq)) {
                return -1;
            }*/
            break;
        case TCP_CLOSED:
            /* TCP session memory is not returned to pool until timeout. */
            SCLogDebug("packet received on closed state");

            /*if (StreamTcpPacketStateClosed(p, ssn, pq)) {
                return -1;
            }*/

            break;
        default:
            SCLogDebug("packet received on default state");
            break;
    }
    return 0;
}

static void StreamTcpPacketSetState(Packet *p, TcpSession *ssn,
                                    uint8_t state)
{
    if (state == ssn->state)
        return;

    ssn->pstate = ssn->state;
    ssn->state = state;

    /* update the flow state */
    switch(ssn->state) {
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_CLOSING:
        case TCP_CLOSE_WAIT:
            //FlowUpdateState(p->flow, FLOW_STATE_ESTABLISHED);
            break;
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
        case TCP_CLOSED:
            //FlowUpdateState(p->flow, FLOW_STATE_CLOSED);
            break;
    }
}

static inline void StreamTcpCloseSsnWithReset(Packet *p, TcpSession *ssn)
{
    ssn->flags |= STREAMTCP_FLAG_CLOSED_BY_RST;
    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
    /*SCLogDebug("ssn %p: (state: %s) Reset received and state changed to "
               "TCP_CLOSED", ssn, StreamTcpStateAsString(ssn->state));*/
}

/**
 *  \brief  Function to test the received ACK values against the stream window
 *          and previous ack value. ACK values should be higher than previous
 *          ACK value and less than the next_win value.
 *
 *  \param  ssn     TcpSession for state access
 *  \param  stream  TcpStream of which last_ack needs to be tested
 *  \param  p       Packet which is used to test the last_ack
 *
 *  \retval 0  ACK is valid, last_ack is updated if ACK was higher
 *  \retval -1 ACK is invalid
 */
static inline int StreamTcpValidateAck(TcpSession *ssn, TcpStream *stream, Packet *p)
{
    uint32_t ack = TCP_GET_ACK(p);

    /* fast track */
    if (SEQ_GT(ack, stream->last_ack) && SEQ_LEQ(ack, stream->next_win))
    {
        SCLogDebug("ACK in bounds");
        return 0;
    }
        /* fast track */
    else if (SEQ_EQ(ack, stream->last_ack)) {
        SCLogDebug("pkt ACK %"PRIu32" == stream last ACK %"PRIu32, TCP_GET_ACK(p), stream->last_ack);
        return 0;
    }

    /* exception handling */
    if (SEQ_LT(ack, stream->last_ack)) {
        SCLogDebug("pkt ACK %"PRIu32" < stream last ACK %"PRIu32, TCP_GET_ACK(p), stream->last_ack);

        /* This is an attempt to get a 'left edge' value that we can check against.
         * It doesn't work when the window is 0, need to think of a better way. */

        if (stream->window != 0 && SEQ_LT(ack, (stream->last_ack - stream->window))) {
            /*SCLogDebug("ACK %"PRIu32" is before last_ack %"PRIu32" - window "
                       "%"PRIu32" = %"PRIu32, ack, stream->last_ack,
                       stream->window, stream->last_ack - stream->window);*/
            goto invalid;
        }

        return 0;
    }

    /* no further checks possible for ASYNC */
    if ((ssn->flags & STREAMTCP_FLAG_ASYNC) != 0) {
        return 0;
    }

    if (ssn->state > TCP_SYN_SENT && SEQ_GT(ack, stream->next_win)) {
        SCLogDebug("ACK %"PRIu32" is after next_win %"PRIu32, ack, stream->next_win);
        goto invalid;
        /* a toclient RST as a reponse to SYN, next_win is 0, ack will be isn+1, just like
         * the syn ack */
    } else if (ssn->state == TCP_SYN_SENT && PKT_IS_TOCLIENT(p) &&
               p->tcph->th_flags & TH_RST &&
               SEQ_EQ(ack, stream->isn + 1)) {
        return 0;
    }

    /*SCLogDebug("default path leading to invalid: ACK %"PRIu32", last_ack %"PRIu32
               " next_win %"PRIu32, ack, stream->last_ack, stream->next_win);*/
invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_ACK);
    return -1;
}

/**
 *  \brief Function to check the validity of the received timestamp based on
 *         the target OS of the given stream.
 *
 *  It's passive except for:
 *  1. it sets the os policy on the stream if necessary
 *  2. it sets an event in the packet if necessary
 *
 *  \param ssn TCP session to which the given packet belongs
 *  \param p Packet which has to be checked for its validity
 *
 *  \retval 1 if the timestamp is valid
 *  \retval 0 if the timestamp is invalid
 */
static int StreamTcpValidateTimestamp (TcpSession *ssn, Packet *p)
{
    TcpStream *sender_stream;
    TcpStream *receiver_stream;
    uint8_t ret = 1;
    uint8_t check_ts = 1;

    if (PKT_IS_TOSERVER(p)) {
        sender_stream = &ssn->client;
        receiver_stream = &ssn->server;
    } else {
        sender_stream = &ssn->server;
        receiver_stream = &ssn->client;
    }

    /* Set up the os_policy to be used in validating the timestamps based on
       the target system */
    if (receiver_stream->os_policy == 0) {
        StreamTcpSetOSPolicy(receiver_stream, p);
    }

    if (TCP_HAS_TS(p)) {
        uint32_t ts = TCP_GET_TSVAL(p);
        uint32_t last_pkt_ts = sender_stream->last_pkt_ts;
        uint32_t last_ts = sender_stream->last_ts;

        if (sender_stream->flags & STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP) {
            /* The 3whs used the timestamp with 0 value. */
            switch (receiver_stream->os_policy) {
                case OS_POLICY_LINUX:
                case OS_POLICY_WINDOWS2K3:
                    /* Linux and windows 2003 does not allow the use of 0 as
                     * timestamp in the 3whs. */
                    check_ts = 0;
                    break;

                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_VISTA:
                    if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) {
                        last_ts = ts;
                        check_ts = 0; /*next packet will be checked for validity
                                        and stream TS has been updated with this
                                        one.*/
                    }
                    break;
            }
        }

        if (ts == 0) {
            switch (receiver_stream->os_policy) {
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_VISTA:
                    /* Old Linux and windows allowed packet with 0 timestamp. */
                    break;
                default:
                    /* other OS simply drop the pakcet with 0 timestamp, when
                     * 3whs has valid timestamp*/
                    goto invalid;
            }
        }

        if (check_ts) {
            int32_t result = 0;

            SCLogDebug("ts %"PRIu32", last_ts %"PRIu32"", ts, last_ts);

            if (receiver_stream->os_policy == OS_POLICY_LINUX) {
                /* Linux accepts TS which are off by one.*/
                result = (int32_t) ((ts - last_ts) + 1);
            } else {
                result = (int32_t) (ts - last_ts);
            }

            SCLogDebug("result %"PRIi32", p->ts.tv_sec %"PRIuMAX"", result, (uintmax_t)p->ts.tv_sec);

            if (last_pkt_ts == 0 &&
                (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
            {
                last_pkt_ts = p->ts.tv_sec;
            }

            if (result < 0) {
                /*SCLogDebug("timestamp is not valid last_ts "
                           "%" PRIu32 " p->tcpvars->ts %" PRIu32 " result "
                           "%" PRId32 "", last_ts, ts, result);*/
                /* candidate for rejection */
                ret = 0;
            } else if ((sender_stream->last_ts != 0) &&
                       (((uint32_t) p->ts.tv_sec) >
                        last_pkt_ts + PAWS_24DAYS))
            {
                /*SCLogDebug("packet is not valid last_pkt_ts "
                           "%" PRIu32 " p->ts.tv_sec %" PRIu32 "",
                           last_pkt_ts, (uint32_t) p->ts.tv_sec);*/
                /* candidate for rejection */
                ret = 0;
            }

            if (ret == 0) {
                /* if the timestamp of packet is not valid then, check if the
                 * current stream timestamp is not so old. if so then we need to
                 * accept the packet and update the stream->last_ts (RFC 1323)*/
                if ((SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) &&
                    (((uint32_t) p->ts.tv_sec > (last_pkt_ts + PAWS_24DAYS))))
                {
                    SCLogDebug("timestamp considered valid anyway");
                } else {
                    goto invalid;
                }
            }
        }
    }

    return 1;

invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
    return 0;
}

static void StreamTcpPacketCheckPostRst(TcpSession *ssn, Packet *p)
{
    if (p->flags & PKT_PSEUDO_STREAM_END) {
        return;
    }
    /* more RSTs are not unusual */
    if ((p->tcph->th_flags & (TH_RST)) != 0) {
        return;
    }

    TcpStream *ostream = NULL;
    if (PKT_IS_TOSERVER(p)) {
        ostream = &ssn->server;
    } else {
        ostream = &ssn->client;
    }

    if (ostream->flags & STREAMTCP_STREAM_FLAG_RST_RECV) {
        SCLogDebug("regular packet %"PRIu64" from same sender as "
                   "the previous RST. Looks like it injected!", p->pcap_cnt);
        ostream->flags &= ~STREAMTCP_STREAM_FLAG_RST_RECV;
        ssn->flags &= ~STREAMTCP_FLAG_CLOSED_BY_RST;
        StreamTcpSetEvent(p, STREAM_SUSPECTED_RST_INJECT);
        return;
    }
    return;
}

static int TcpSessionPacketIsStreamStarter(const Packet *p)
{
  if (p->tcph->th_flags == TH_SYN) {
    SCLogDebug("packet %"PRIu64" is a stream starter: %02x", p->pcap_cnt, p->tcph->th_flags);
    return 1;
  }

  if (stream_config.midstream == TRUE) {
    if (p->tcph->th_flags == (TH_SYN|TH_ACK)) {
      SCLogDebug("packet %"PRIu64" is a midstream stream starter: %02x", p->pcap_cnt, p->tcph->th_flags);
      return 1;
    }
  }
  return 0;
}

static int TcpSessionReuseDoneEnoughSyn(const Packet *p, const Flow *f, const TcpSession *ssn)
{
  if (FlowGetPacketDirection(f, p) == TOSERVER) {
    if (ssn == NULL) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p null. No reuse.", p->pcap_cnt, ssn);
      return 0;
    }
    if (SEQ_EQ(ssn->client.isn, TCP_GET_SEQ(p))) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p. Packet SEQ == Stream ISN. Retransmission. Don't reuse.", p->pcap_cnt, ssn);
      return 0;
    }
    if (ssn->state >= TCP_LAST_ACK) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
      return 1;
    }
    if (ssn->state == TCP_NONE) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
      return 1;
    }
    if (ssn->state < TCP_LAST_ACK) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
      return 0;
    }

  } else {
    if (ssn == NULL) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p null. Reuse.", p->pcap_cnt, ssn);
      return 1;
    }
    if (ssn->state >= TCP_LAST_ACK) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
      return 1;
    }
    if (ssn->state == TCP_NONE) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
      return 1;
    }
    if (ssn->state < TCP_LAST_ACK) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
      return 0;
    }
  }

  SCLogDebug("default: how did we get here?");
  return 0;
}

static int TcpSessionReuseDoneEnoughSynAck(const Packet *p, const Flow *f, const TcpSession *ssn)
{
  if (FlowGetPacketDirection(f, p) == TOCLIENT) {
    if (ssn == NULL) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p null. No reuse.", p->pcap_cnt, ssn);
      return 0;
    }
    if (SEQ_EQ(ssn->server.isn, TCP_GET_SEQ(p))) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p. Packet SEQ == Stream ISN. Retransmission. Don't reuse.", p->pcap_cnt, ssn);
      return 0;
    }
    if (ssn->state >= TCP_LAST_ACK) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
      return 1;
    }
    if (ssn->state == TCP_NONE) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
      return 1;
    }
    if (ssn->state < TCP_LAST_ACK) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
      return 0;
    }

  } else {
    if (ssn == NULL) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p null. Reuse.", p->pcap_cnt, ssn);
      return 1;
    }
    if (ssn->state >= TCP_LAST_ACK) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
      return 1;
    }
    if (ssn->state == TCP_NONE) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
      return 1;
    }
    if (ssn->state < TCP_LAST_ACK) {
      SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
      return 0;
    }
  }

  SCLogDebug("default: how did we get here?");
  return 0;
}

static int TcpSessionReuseDoneEnough(const Packet *p, const Flow *f, const TcpSession *ssn)
{
  if (p->tcph->th_flags == TH_SYN) {
    return TcpSessionReuseDoneEnoughSyn(p, f, ssn);
  }

  if (stream_config.midstream == TRUE ) {
    if (p->tcph->th_flags == (TH_SYN|TH_ACK)) {
      return TcpSessionReuseDoneEnoughSynAck(p, f, ssn);
    }
  }

  return 0;
}

int TcpSessionPacketSsnReuse(const Packet *p, const Flow *f, const void *tcp_ssn)
{
  if (p->proto == IPPROTO_TCP && p->tcph != NULL) {
    if (TcpSessionPacketIsStreamStarter(p) == 1) {
      if (TcpSessionReuseDoneEnough(p, f, tcp_ssn) == 1) {
        return 1;
      }
    }
  }
  return 0;
}

void StreamTcpInitConfig(char quiet)
{
    intmax_t value = 0;
    uint16_t rdrange = 10;

    SCLogDebug("Initializing Stream");

    memset(&stream_config,  0, sizeof(stream_config));

    SC_ATOMIC_INIT(stream_config.memcap);
    SC_ATOMIC_INIT(stream_config.reassembly_memcap);

    //最大会话数
    if ((ConfGetInt("stream.max-sessions", &value)) == 1) {
        SCLogWarning(SC_WARN_OPTION_OBSOLETE, "max-sessions is obsolete. "
                                              "Number of concurrent sessions is now only limited by Flow and "
                                              "TCP stream engine memcaps.");
    }

    if ((ConfGetInt("stream.prealloc-sessions", &value)) == 1) {
        stream_config.prealloc_sessions = (uint32_t)value;
    } else {
        stream_config.prealloc_sessions = STREAMTCP_DEFAULT_PREALLOC;
        if (ConfGetNode("stream.prealloc-sessions") != NULL) {
            WarnInvalidConfEntry("stream.prealloc_sessions",
                                 "%"PRIu32,
                                 stream_config.prealloc_sessions);
        }
    }
    if (!quiet) {
        SCLogConfig("stream \"prealloc-sessions\": %"PRIu32" (per thread)",
                    stream_config.prealloc_sessions);
    }

    const char *temp_stream_memcap_str;
    if (ConfGetValue("stream.memcap", &temp_stream_memcap_str) == 1) {
        uint64_t stream_memcap_copy;
        if (ParseSizeStringU64(temp_stream_memcap_str, &stream_memcap_copy) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing stream.memcap "
                                          "from conf file - %s.  Killing engine",
                       temp_stream_memcap_str);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(stream_config.memcap, stream_memcap_copy);
        }
    } else {
        SC_ATOMIC_SET(stream_config.memcap, STREAMTCP_DEFAULT_MEMCAP);
    }

    if (!quiet) {
        SCLogConfig("stream \"memcap\": %"PRIu64, SC_ATOMIC_GET(stream_config.memcap));
    }

    ConfGetBool("stream.midstream", &stream_config.midstream);

    if (!quiet) {
        SCLogConfig("stream \"midstream\" session pickups: %s", stream_config.midstream ? "enabled" : "disabled");
    }

    ConfGetBool("stream.async-oneside", &stream_config.async_oneside);

    if (!quiet) {
        SCLogConfig("stream \"async-oneside\": %s", stream_config.async_oneside ? "enabled" : "disabled");
    }

    int csum = 0;

    if ((ConfGetBool("stream.checksum-validation", &csum)) == 1) {
        if (csum == 1) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION;
        }
        /* Default is that we validate the checksum of all the packets */
    } else {
        stream_config.flags |= STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION;
    }

    if (!quiet) {
        SCLogConfig("stream \"checksum-validation\": %s",
                    stream_config.flags & STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION ?
                    "enabled" : "disabled");
    }

    const char *temp_stream_inline_str;
    if (ConfGetValue("stream.inline", &temp_stream_inline_str) == 1) {
        //TODO:modify by haolipeng
    } else {

    }
    stream_config.ssn_memcap_policy = ExceptionPolicyParse("stream.memcap-policy", true);
    stream_config.reassembly_memcap_policy =
            ExceptionPolicyParse("stream.reassembly.memcap-policy", true);
    SCLogConfig("memcap-policy: %u/%u", stream_config.ssn_memcap_policy,
                stream_config.reassembly_memcap_policy);
    stream_config.midstream_policy = ExceptionPolicyParse("stream.midstream-policy", true);
    if (stream_config.midstream && stream_config.midstream_policy != EXCEPTION_POLICY_IGNORE) {
        SCLogWarning(SC_WARN_COMPATIBILITY,
                     "stream.midstream_policy setting conflicting with stream.midstream enabled. "
                     "Ignoring stream.midstream_policy.");
        stream_config.midstream_policy = EXCEPTION_POLICY_IGNORE;
    }

    if (!quiet) {
        SCLogConfig("stream.\"inline\": %s",
                    stream_config.flags & STREAMTCP_INIT_FLAG_INLINE
                    ? "enabled" : "disabled");
    }

    int bypass = 0;
    if ((ConfGetBool("stream.bypass", &bypass)) == 1) {
        if (bypass == 1) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_BYPASS;
        }
    }

    if (!quiet) {
        SCLogConfig("stream \"bypass\": %s",
                    (stream_config.flags & STREAMTCP_INIT_FLAG_BYPASS)
                    ? "enabled" : "disabled");
    }

    int drop_invalid = 0;
    if ((ConfGetBool("stream.drop-invalid", &drop_invalid)) == 1) {
        if (drop_invalid == 1) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_DROP_INVALID;
        }
    } else {
        stream_config.flags |= STREAMTCP_INIT_FLAG_DROP_INVALID;
    }

    if ((ConfGetInt("stream.max-synack-queued", &value)) == 1) {
        if (value >= 0 && value <= 255) {
            stream_config.max_synack_queued = (uint8_t)value;
        } else {
            stream_config.max_synack_queued = (uint8_t)STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED;
        }
    } else {
        stream_config.max_synack_queued = (uint8_t)STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED;
    }
    if (!quiet) {
        SCLogConfig("stream \"max-synack-queued\": %"PRIu8, stream_config.max_synack_queued);
    }

    const char *temp_stream_reassembly_memcap_str;
    if (ConfGetValue("stream.reassembly.memcap", &temp_stream_reassembly_memcap_str) == 1) {
        uint64_t stream_reassembly_memcap_copy;
        if (ParseSizeStringU64(temp_stream_reassembly_memcap_str,
                               &stream_reassembly_memcap_copy) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                                          "stream.reassembly.memcap "
                                          "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_memcap_str);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(stream_config.reassembly_memcap, stream_reassembly_memcap_copy);
        }
    } else {
        SC_ATOMIC_SET(stream_config.reassembly_memcap , STREAMTCP_DEFAULT_REASSEMBLY_MEMCAP);
    }

    if (!quiet) {
        SCLogConfig("stream.reassembly \"memcap\": %"PRIu64"",
                    SC_ATOMIC_GET(stream_config.reassembly_memcap));
    }

    const char *temp_stream_reassembly_depth_str;
    if (ConfGetValue("stream.reassembly.depth", &temp_stream_reassembly_depth_str) == 1) {
        if (ParseSizeStringU32(temp_stream_reassembly_depth_str,&stream_config.reassembly_depth) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                                          "stream.reassembly.depth "
                                          "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_depth_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_depth = 0;
    }

    if (!quiet) {
        SCLogConfig("stream.reassembly \"depth\": %"PRIu32"", stream_config.reassembly_depth);
    }

    int randomize = 0;
    if ((ConfGetBool("stream.reassembly.randomize-chunk-size", &randomize)) == 0) {
        /* randomize by default if value not set
         * In ut mode we disable, to get predictible test results */
        //if (!(RunmodeIsUnittests()))
            randomize = 1;
    }

    if (randomize) {
        const char *temp_rdrange;
        if (ConfGetValue("stream.reassembly.randomize-chunk-range",
                         &temp_rdrange) == 1) {
            if (ParseSizeStringU16(temp_rdrange, &rdrange) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                                              "stream.reassembly.randomize-chunk-range "
                                              "from conf file - %s.  Killing engine",
                           temp_rdrange);
                exit(EXIT_FAILURE);
            } else if (rdrange >= 100) {
                FatalError(SC_ERR_FATAL,
                           "stream.reassembly.randomize-chunk-range "
                           "must be lower than 100");
            }
        }
    }

    const char *temp_stream_reassembly_toserver_chunk_size_str;
    if (ConfGetValue("stream.reassembly.toserver-chunk-size",
                     &temp_stream_reassembly_toserver_chunk_size_str) == 1) {
        if (ParseSizeStringU16(temp_stream_reassembly_toserver_chunk_size_str,
                               &stream_config.reassembly_toserver_chunk_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                                          "stream.reassembly.toserver-chunk-size "
                                          "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_toserver_chunk_size_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_toserver_chunk_size =
                STREAMTCP_DEFAULT_TOSERVER_CHUNK_SIZE;
    }

    if (randomize) {
        long int r = RandomGetWrap();
        stream_config.reassembly_toserver_chunk_size +=
                (int) (stream_config.reassembly_toserver_chunk_size *
                       (r * 1.0 / RAND_MAX - 0.5) * rdrange / 100);
    }
    const char *temp_stream_reassembly_toclient_chunk_size_str;
    if (ConfGetValue("stream.reassembly.toclient-chunk-size",
                     &temp_stream_reassembly_toclient_chunk_size_str) == 1) {
        if (ParseSizeStringU16(temp_stream_reassembly_toclient_chunk_size_str,
                               &stream_config.reassembly_toclient_chunk_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                                          "stream.reassembly.toclient-chunk-size "
                                          "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_toclient_chunk_size_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_toclient_chunk_size =
                STREAMTCP_DEFAULT_TOCLIENT_CHUNK_SIZE;
    }

    if (randomize) {
        long int r = RandomGetWrap();
        stream_config.reassembly_toclient_chunk_size +=
                (int) (stream_config.reassembly_toclient_chunk_size *
                       (r * 1.0 / RAND_MAX - 0.5) * rdrange / 100);
    }
    if (!quiet) {
        SCLogConfig("stream.reassembly \"toserver-chunk-size\": %"PRIu16,
                    stream_config.reassembly_toserver_chunk_size);
        SCLogConfig("stream.reassembly \"toclient-chunk-size\": %"PRIu16,
                    stream_config.reassembly_toclient_chunk_size);
    }

    int enable_raw = 1;
    if (ConfGetBool("stream.reassembly.raw", &enable_raw) == 1) {
        if (!enable_raw) {
            stream_config.stream_init_flags = STREAMTCP_STREAM_FLAG_DISABLE_RAW;
        }
    } else {
        enable_raw = 1;
    }
    if (!quiet)
        SCLogConfig("stream.reassembly.raw: %s", enable_raw ? "enabled" : "disabled");

    /* init the memcap/use tracking */
    StreamTcpInitMemuse();

    StreamTcpReassembleInit(quiet);

    /* set the default free function and flow state function
     * values. */
    FlowSetProtoFreeFunc(IPPROTO_TCP, StreamTcpSessionClear);
}

void StreamTcpSessionClear(void *ssnptr)
{
    TcpSession *ssn = (TcpSession *)ssnptr;
    if (ssn == NULL)
        return;

    StreamTcpSessionCleanup(ssn);

    /* HACK: don't loose track of thread id */
    PoolThreadReserved a = ssn->res;
    memset(ssn, 0, sizeof(TcpSession));
    ssn->res = a;

    PoolThreadReturn(ssn_pool, ssn);

    return ;
}

TmEcode StreamTcp (ThreadVars *tv, Packet *p, void *data, PacketQueueNoLock *pq){
    StreamTcpThread *stt = (StreamTcpThread *)data;

    if (!(PKT_IS_TCP(p))) {
        return TM_ECODE_OK;
    }

    if (p->flow->protoctx == NULL) {
        return TM_ECODE_OK;
    }

    /* only TCP packets with a flow from here */
    (void)StreamTcpPacket(tv, p, stt, pq);

    return TM_ECODE_OK;
}

/* flow is and stays locked */
int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt,
                    PacketQueueNoLock *pq)
{
    //find protoctx assign operation
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    /* track TCP flags */
    if (ssn != NULL) {
        ssn->tcp_packet_flags |= p->tcph->th_flags;
        if (PKT_IS_TOSERVER(p))
            ssn->client.tcp_flags |= p->tcph->th_flags;
        else if (PKT_IS_TOCLIENT(p))
            ssn->server.tcp_flags |= p->tcph->th_flags;
    }

    /* broken TCP*/
    if (!(p->tcph->th_flags & TH_ACK) && TCP_GET_ACK(p) != 0) {
        StreamTcpSetEvent(p, STREAM_PKT_BROKEN_ACK);
        if (!(p->tcph->th_flags & TH_SYN))
            goto error;
    }

    if (ssn == NULL || ssn->state == TCP_NONE) {
        if (StreamTcpPacketStateNone( tv, p, stt, ssn, &stt->pseudo_queue) == -1) {
            goto error;
        }
    } else {
        /* special case for PKT_PSEUDO_STREAM_END packets:
         * bypass the state handling and various packet checks,
         * we care about reassembly here. */
        if (p->flags & PKT_PSEUDO_STREAM_END) {
            if (PKT_IS_TOCLIENT(p)) {
                ssn->client.last_ack = TCP_GET_ACK(p);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
            } else {
                ssn->server.last_ack = TCP_GET_ACK(p);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            }
            /* straight to 'skip' as we already handled reassembly */
            goto skip;
        }

        if (p->flow->flags & FLOW_WRONG_THREAD) {
            /* Stream and/or session in known bad condition. Block events
             * from being set. */
            p->flags |= PKT_STREAM_NO_EVENTS;
        }

        //TODO:some keep alive function

        /* handle the per 'state' logic */
        if (StreamTcpStateDispatch( tv, p, stt, ssn, &stt->pseudo_queue, ssn->state) < 0)
            goto error;

    skip:
        StreamTcpPacketCheckPostRst(ssn, p);

        if (ssn->state >= TCP_ESTABLISHED) {
            p->flags |= PKT_STREAM_EST;
        }
    }

    /* deal with a pseudo packet that is created upon receiving a RST
     * segment. To be sure we process both sides of the connection, we
     * inject a fake packet into the system, forcing reassembly of the
     * opposing direction.
     * There should be only one, but to be sure we do a while loop. */
    if (ssn != NULL) {
        while (stt->pseudo_queue.len > 0) {
            SCLogDebug("processing pseudo packet / stream end");
            Packet *np = PacketDequeueNoLock(&stt->pseudo_queue);
            if (np != NULL) {
                /* process the opposing direction of the original packet */
                if (PKT_IS_TOSERVER(np)) {
                    SCLogDebug("pseudo packet is to server");
                    StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,&ssn->client, np, NULL);
                } else {
                    SCLogDebug("pseudo packet is to client");
                    StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,&ssn->server, np, NULL);
                }

                /* enqueue this packet so we inspect it in detect etc */
                PacketEnqueueNoLock(pq, np);
            }
            SCLogDebug("processing pseudo packet / stream end done");
        }

        /* encrypted packets */
        if ((PKT_IS_TOSERVER(p) && (ssn->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) ||
            (PKT_IS_TOCLIENT(p) && (ssn->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)))
        {
            p->flags |= PKT_STREAM_NOPCAPLOG;
        }
    }

    return 0;
error:
    /* make sure we don't leave packets in our pseudo queue */
    while (stt->pseudo_queue.len > 0) {
        Packet *np = PacketDequeueNoLock(&stt->pseudo_queue);
        if (np != NULL) {
            PacketEnqueueNoLock(pq, np);
        }
    }

    return -1;
}

static void *StreamTcpSessionPoolAlloc(void)
{
  void *ptr = NULL;

  ptr = malloc(sizeof(TcpSession));
  if (unlikely(ptr == NULL))
    return NULL;

  return ptr;
}

static int StreamTcpSessionPoolInit(void *data, void* initdata)
{
  memset(data, 0, sizeof(TcpSession));
  StreamTcpIncrMemuse((uint64_t)sizeof(TcpSession));

  return 1;
}

static void StreamTcpSessionPoolCleanup(void *s)
{
  if (s != NULL) {
    StreamTcpSessionCleanup(s);
    /** \todo not very clean, as the memory is not freed here */
    StreamTcpDecrMemuse((uint64_t)sizeof(TcpSession));
  }
}

TmEcode StreamTcpThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    StreamTcpThread *stt = malloc(sizeof(StreamTcpThread));
    if (unlikely(stt == NULL))
        return TM_ECODE_FAILED;
    memset(stt, 0, sizeof(StreamTcpThread));
    stt->ssn_pool_id = -1;

    *data = (void *)stt;

    /* init reassembly ctx */
    stt->ra_ctx = StreamTcpReassembleInitThreadCtx(tv);
    if (stt->ra_ctx == NULL)
      return TM_ECODE_FAILED;

    SCLogDebug("StreamTcp thread specific ctx online at %p, reassembly ctx %p",
               stt, stt->ra_ctx);

    SCMutexLock(&ssn_pool_mutex);
    if (ssn_pool == NULL) {
      ssn_pool = PoolThreadInit(1, /* thread */
                                0, /* unlimited */
                                stream_config.prealloc_sessions,
                                sizeof(TcpSession),
                                StreamTcpSessionPoolAlloc,
                                StreamTcpSessionPoolInit, NULL,
                                StreamTcpSessionPoolCleanup, NULL);
      stt->ssn_pool_id = 0;
      SCLogDebug("pool size %d, thread ssn_pool_id %d", PoolThreadSize(ssn_pool), stt->ssn_pool_id);
    } else {
      /* grow ssn_pool until we have a element for our thread id */
      stt->ssn_pool_id = PoolThreadExpand(ssn_pool);
      SCLogDebug("pool size %d, thread ssn_pool_id %d", PoolThreadSize(ssn_pool), stt->ssn_pool_id);
    }
    SCMutexUnlock(&ssn_pool_mutex);
    if (stt->ssn_pool_id < 0 || ssn_pool == NULL) {
      SCLogError(SC_ERR_MEM_ALLOC, "failed to setup/expand stream session pool. Expand stream.memcap?");
      return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

TmEcode StreamTcpThreadDeinit(ThreadVars *tv, void *data)
{
    StreamTcpThread *stt = (StreamTcpThread *)data;
    if (stt == NULL) {
      return TM_ECODE_OK;
    }

    /* free reassembly ctx */
    StreamTcpReassembleFreeThreadCtx(stt->ra_ctx);

    /* clear memory */
    memset(stt, 0, sizeof(StreamTcpThread));

    SCFree(stt);
    return TM_ECODE_OK;
}

static void StreamTcpPseudoPacketCreateDetectLogFlush(ThreadVars *tv,
                                                      StreamTcpThread *stt, Packet *parent,
                                                      TcpSession *ssn, PacketQueueNoLock *pq, int dir)
{
  Flow *f = parent->flow;

  if (parent->flags & PKT_PSEUDO_DETECTLOG_FLUSH) {
    return ;
  }

  Packet *np = PacketPoolGetPacket();
  if (np == NULL) {
    return;
  }
  PKT_SET_SRC(np, PKT_SRC_STREAM_TCP_DETECTLOG_FLUSH);

  np->datalink = DLT_RAW;
  np->proto = IPPROTO_TCP;
  FlowReference(&np->flow, f);
  np->flags |= PKT_STREAM_EST;
  np->flags |= PKT_HAS_FLOW;
  np->flags |= PKT_IGNORE_CHECKSUM;
  np->flags |= PKT_PSEUDO_DETECTLOG_FLUSH;
  np->vlan_id[0] = f->vlan_id[0];
  np->vlan_id[1] = f->vlan_id[1];
  np->vlan_idx = f->vlan_idx;
  np->livedev = (struct LiveDevice_ *)f->livedev;

  if (f->flags & FLOW_NOPACKET_INSPECTION) {
    DecodeSetNoPacketInspectionFlag(np);
  }
  if (f->flags & FLOW_NOPAYLOAD_INSPECTION) {
    DecodeSetNoPayloadInspectionFlag(np);
  }

  if (dir == 0) {
    SCLogDebug("pseudo is to_server");
    np->flowflags |= FLOW_PKT_TOSERVER;
  } else {
    SCLogDebug("pseudo is to_client");
    np->flowflags |= FLOW_PKT_TOCLIENT;
  }
  np->flowflags |= FLOW_PKT_ESTABLISHED;
  np->payload = NULL;
  np->payload_len = 0;

  if (FLOW_IS_IPV4(f)) {
    if (dir == 0) {
      FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, &np->src);
      FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, &np->dst);
      np->sp = f->sp;
      np->dp = f->dp;
    } else {
      FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, &np->dst);
      FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, &np->src);
      np->sp = f->dp;
      np->dp = f->sp;
    }

    /* Check if we have enough room in direct data. We need ipv4 hdr + tcp hdr.
         * Force an allocation if it is not the case.
     */
    if (GET_PKT_DIRECT_MAX_SIZE(np) <  40) {
      if (PacketCallocExtPkt(np, 40) == -1) {
        goto error;
      }
    }
    /* set the ip header */
    np->ip4h = (IPV4Hdr *)GET_PKT_DATA(np);
    /* version 4 and length 20 bytes for the tcp header */
    np->ip4h->ip_verhl = 0x45;
    np->ip4h->ip_tos = 0;
    np->ip4h->ip_len = htons(40);
    np->ip4h->ip_id = 0;
    np->ip4h->ip_off = 0;
    np->ip4h->ip_ttl = 64;
    np->ip4h->ip_proto = IPPROTO_TCP;
    if (dir == 0) {
      np->ip4h->s_ip_src.s_addr = f->src.addr_data32[0];
      np->ip4h->s_ip_dst.s_addr = f->dst.addr_data32[0];
    } else {
      np->ip4h->s_ip_src.s_addr = f->dst.addr_data32[0];
      np->ip4h->s_ip_dst.s_addr = f->src.addr_data32[0];
    }

    /* set the tcp header */
    np->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(np) + 20);

    SET_PKT_LEN(np, 40); /* ipv4 hdr + tcp hdr */

  } else if (FLOW_IS_IPV6(f)) {
    if (dir == 0) {
      FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, &np->src);
      FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, &np->dst);
      np->sp = f->sp;
      np->dp = f->dp;
    } else {
      FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, &np->dst);
      FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, &np->src);
      np->sp = f->dp;
      np->dp = f->sp;
    }

    /* Check if we have enough room in direct data. We need ipv6 hdr + tcp hdr.
         * Force an allocation if it is not the case.
     */
    if (GET_PKT_DIRECT_MAX_SIZE(np) <  60) {
      if (PacketCallocExtPkt(np, 60) == -1) {
        goto error;
      }
    }
    /* set the ip header */
    np->ip6h = (IPV6Hdr *)GET_PKT_DATA(np);
    /* version 6 */
    np->ip6h->s_ip6_vfc = 0x60;
    np->ip6h->s_ip6_flow = 0;
    np->ip6h->s_ip6_nxt = IPPROTO_TCP;
    np->ip6h->s_ip6_plen = htons(20);
    np->ip6h->s_ip6_hlim = 64;
    if (dir == 0) {
      np->ip6h->s_ip6_src[0] = f->src.addr_data32[0];
      np->ip6h->s_ip6_src[1] = f->src.addr_data32[1];
      np->ip6h->s_ip6_src[2] = f->src.addr_data32[2];
      np->ip6h->s_ip6_src[3] = f->src.addr_data32[3];
      np->ip6h->s_ip6_dst[0] = f->dst.addr_data32[0];
      np->ip6h->s_ip6_dst[1] = f->dst.addr_data32[1];
      np->ip6h->s_ip6_dst[2] = f->dst.addr_data32[2];
      np->ip6h->s_ip6_dst[3] = f->dst.addr_data32[3];
    } else {
      np->ip6h->s_ip6_src[0] = f->dst.addr_data32[0];
      np->ip6h->s_ip6_src[1] = f->dst.addr_data32[1];
      np->ip6h->s_ip6_src[2] = f->dst.addr_data32[2];
      np->ip6h->s_ip6_src[3] = f->dst.addr_data32[3];
      np->ip6h->s_ip6_dst[0] = f->src.addr_data32[0];
      np->ip6h->s_ip6_dst[1] = f->src.addr_data32[1];
      np->ip6h->s_ip6_dst[2] = f->src.addr_data32[2];
      np->ip6h->s_ip6_dst[3] = f->src.addr_data32[3];
    }

    /* set the tcp header */
    np->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(np) + 40);

    SET_PKT_LEN(np, 60); /* ipv6 hdr + tcp hdr */
  }

  np->tcph->th_offx2 = 0x50;
  np->tcph->th_flags |= TH_ACK;
  np->tcph->th_win = 10;
  np->tcph->th_urp = 0;

  /* to server */
  if (dir == 0) {
    np->tcph->th_sport = htons(f->sp);
    np->tcph->th_dport = htons(f->dp);

    np->tcph->th_seq = htonl(ssn->client.next_seq);
    np->tcph->th_ack = htonl(ssn->server.last_ack);

    /* to client */
  } else {
    np->tcph->th_sport = htons(f->dp);
    np->tcph->th_dport = htons(f->sp);

    np->tcph->th_seq = htonl(ssn->server.next_seq);
    np->tcph->th_ack = htonl(ssn->client.last_ack);
  }

  /* use parent time stamp */
  memcpy(&np->ts, &parent->ts, sizeof(struct timeval));

  SCLogDebug("np %p", np);
  PacketEnqueueNoLock(pq, np);

  return ;
error:
  FlowDeReference(&np->flow);
  return ;
}

void StreamTcpDetectLogFlush(ThreadVars *tv, StreamTcpThread *stt, Flow *f, Packet *p,
                             PacketQueueNoLock *pq)
{
  TcpSession *ssn = f->protoctx;
  ssn->client.flags |= STREAMTCP_STREAM_FLAG_TRIGGER_RAW;
  ssn->server.flags |= STREAMTCP_STREAM_FLAG_TRIGGER_RAW;
  bool ts = PKT_IS_TOSERVER(p) ? true : false;
  ts ^= false;
  StreamTcpPseudoPacketCreateDetectLogFlush(tv, stt, p, ssn, pq, ts^0);
  StreamTcpPseudoPacketCreateDetectLogFlush(tv, stt, p, ssn, pq, ts^1);
}
