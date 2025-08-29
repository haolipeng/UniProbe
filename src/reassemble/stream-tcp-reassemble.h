#ifndef NET_THREAT_DETECT_STREAM_TCP_REASSEMBLE_H
#define NET_THREAT_DETECT_STREAM_TCP_REASSEMBLE_H

#include "utils/packet-queue.h"
#include "decode/decode.h"
#include "stream-tcp-private.h"
#include "modules/threadvars.h"

enum
{
    OS_POLICY_NONE = 1,
    OS_POLICY_BSD,
    OS_POLICY_BSD_RIGHT,
    OS_POLICY_OLD_LINUX,
    OS_POLICY_LINUX,
    OS_POLICY_WINDOWS,
    OS_POLICY_VISTA,
    OS_POLICY_WINDOWS2K3,
    OS_POLICY_FIRST,
    OS_POLICY_LAST
};

enum StreamUpdateDir {
    UPDATE_DIR_PACKET,
    UPDATE_DIR_OPPOSING,
    UPDATE_DIR_BOTH,
};

typedef struct TcpReassemblyThreadCtx_ {
    void *app_tctx;

    int segment_thread_pool_id;

    /** TCP segments which are not being reassembled due to memcap was reached */
    uint16_t counter_tcp_segment_memcap;
    /** number of streams that stop reassembly because their depth is reached */
    uint16_t counter_tcp_stream_depth;
    /** count number of streams with a unrecoverable stream gap (missing pkts) */
    uint16_t counter_tcp_reass_gap;

    /** count packet data overlaps */
    uint16_t counter_tcp_reass_overlap;
    /** count overlaps with different data */
    uint16_t counter_tcp_reass_overlap_diff_data;

    uint16_t counter_tcp_reass_data_normal_fail;
    uint16_t counter_tcp_reass_data_overlap_fail;
    uint16_t counter_tcp_reass_list_fail;
} TcpReassemblyThreadCtx;

void StreamTcpReassembleInitMemuse(void);
int StreamTcpReassembleHandleSegment(ThreadVars *, TcpReassemblyThreadCtx *,TcpSession *, TcpStream *, Packet *, PacketQueueNoLock *);
int StreamTcpReassembleInit(char);
void StreamTcpReassembleFree(char);
TcpReassemblyThreadCtx *StreamTcpReassembleInitThreadCtx(ThreadVars *tv);
void StreamTcpReassembleFreeThreadCtx(TcpReassemblyThreadCtx *);
int StreamTcpReassembleAppLayer (ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,TcpSession *ssn, TcpStream *stream,
                                Packet *p, enum StreamUpdateDir dir);

void StreamTcpSetOSPolicy(TcpStream *, Packet *);

int StreamTcpReassembleHandleSegmentHandleData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,TcpSession *ssn, TcpStream *stream, Packet *p);
int StreamTcpReassembleInsertSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,TcpStream *, TcpSegment *, Packet *, uint32_t pkt_seq, uint8_t *pkt_data, uint16_t pkt_datalen);
TcpSegment *StreamTcpGetSegment(ThreadVars *, TcpReassemblyThreadCtx *);

void StreamTcpReturnStreamSegments(TcpStream *);
void StreamTcpSegmentReturntoPool(TcpSegment *);

void StreamTcpReassembleTriggerRawReassembly(TcpSession *, int direction);

void StreamTcpPruneSession(Flow *, uint8_t);
int StreamTcpReassembleDepthReached(Packet *p);

void StreamTcpReassembleIncrMemuse(uint64_t size);
void StreamTcpReassembleDecrMemuse(uint64_t size);
int StreamTcpReassembleSetMemcap(uint64_t size);
uint64_t StreamTcpReassembleGetMemcap(void);
int StreamTcpReassembleCheckMemcap(uint64_t size);
uint64_t StreamTcpReassembleMemuseGlobalCounter(void);

//TODO:disable app layer
void StreamTcpDisableAppLayer(Flow *f);
int StreamTcpAppLayerIsDisabled(Flow *f);

bool StreamReassembleRawHasDataReady(TcpSession *ssn, Packet *p);
void StreamTcpReassemblySetMinInspectDepth(TcpSession *ssn, int direction, uint32_t depth);

static inline bool STREAM_LASTACK_GT_BASESEQ(const TcpStream *stream)
{
  /* last ack not yet initialized */
  if (STREAM_BASE_OFFSET(stream) == 0 && (stream->tcp_flags & TH_ACK) == 0) {
    return false;
  }
  if (SEQ_GT(stream->last_ack, stream->base_seq))
    return true;
  return false;
}
#endif //NET_THREAT_DETECT_STREAM_TCP_REASSEMBLE_H
