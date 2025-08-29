#include "stream-tcp-reassemble.h"
#include "utils/util-pool-thread.h"
#include "stream-tcp-private.h"
#include "stream-tcp.h"
#include "stream.h"
#include "utils/conf.h"
#include "utils/util-byte.h"
#include <string.h>

#ifdef DEBUG
static SCMutex segment_pool_memuse_mutex;
static uint64_t segment_pool_memuse = 0;
static uint64_t segment_pool_memcnt = 0;
#endif

#ifdef DEBUG
thread_local uint64_t t_pcapcnt = UINT64_MAX;
#endif

static PoolThread *segment_thread_pool = NULL;
/* init only, protect initializing and growing pool */
static SCMutex segment_thread_pool_mutex = SCMUTEX_INITIALIZER;

/* Memory use counter */
SC_ATOMIC_DECLARE(uint64_t, ra_memuse);

/* prototypes */
TcpSegment *StreamTcpGetSegment(ThreadVars *tv, TcpReassemblyThreadCtx *);

void StreamTcpReassembleInitMemuse(void)
{
  SC_ATOMIC_INIT(ra_memuse);
}

/**
 *  \brief  Function to Increment the memory usage counter for the TCP reassembly
 *          segments
 *
 *  \param  size Size of the TCP segment and its payload length memory allocated
 */
void StreamTcpReassembleIncrMemuse(uint64_t size)
{
  (void) SC_ATOMIC_ADD(ra_memuse, size);
  SCLogDebug("REASSEMBLY %"PRIu64", incr %"PRIu64, StreamTcpReassembleMemuseGlobalCounter(), size);
  return;
}

/**
 *  \brief  Function to Decrease the memory usage counter for the TCP reassembly
 *          segments
 *
 *  \param  size Size of the TCP segment and its payload length memory allocated
 */
void StreamTcpReassembleDecrMemuse(uint64_t size)
{
  (void) SC_ATOMIC_SUB(ra_memuse, size);

  SCLogDebug("REASSEMBLY %"PRIu64", decr %"PRIu64, StreamTcpReassembleMemuseGlobalCounter(), size);
  return;
}

uint64_t StreamTcpReassembleMemuseGlobalCounter(void)
{
  uint64_t smemuse = SC_ATOMIC_GET(ra_memuse);
  return smemuse;
}

/**
 * \brief  Function to Check the reassembly memory usage counter against the
 *         allowed max memory usgae for TCP segments.
 *
 * \param  size Size of the TCP segment and its payload length memory allocated
 * \retval 1 if in bounds
 * \retval 0 if not in bounds
 */
int StreamTcpReassembleCheckMemcap(uint64_t size)
{
#ifdef DEBUG
  if (unlikely((g_eps_stream_reassembly_memcap != UINT64_MAX &&
                g_eps_stream_reassembly_memcap == t_pcapcnt))) {
    SCLogNotice("simulating memcap reached condition for packet %" PRIu64, t_pcapcnt);
    return 0;
  }
#endif
  uint64_t memcapcopy = SC_ATOMIC_GET(stream_config.reassembly_memcap);
  if (memcapcopy == 0 ||
      (uint64_t)((uint64_t)size + SC_ATOMIC_GET(ra_memuse)) <= memcapcopy)
    return 1;
  return 0;
}

/**
 *  \brief Update memcap value
 *
 *  \param size new memcap value
 */
int StreamTcpReassembleSetMemcap(uint64_t size)
{
  if (size == 0 || (uint64_t)SC_ATOMIC_GET(ra_memuse) < size) {
    SC_ATOMIC_SET(stream_config.reassembly_memcap, size);
    return 1;
  }

  return 0;
}

/**
 *  \brief Return memcap value
 *
 *  \return memcap memcap value
 */
uint64_t StreamTcpReassembleGetMemcap(void)
{
  uint64_t memcapcopy = SC_ATOMIC_GET(stream_config.reassembly_memcap);
  return memcapcopy;
}

/* memory functions for the streaming buffer API */

/*
    void *(*Malloc)(size_t size);
*/
static void *ReassembleMalloc(size_t size)
{
  if (StreamTcpReassembleCheckMemcap(size) == 0)
    return NULL;
  void *ptr = malloc(size);
  if (ptr == NULL)
    return NULL;
  StreamTcpReassembleIncrMemuse(size);
  return ptr;
}

/*
    void *(*Calloc)(size_t n, size_t size);
*/
static void *ReassembleCalloc(size_t n, size_t size)
{
  if (StreamTcpReassembleCheckMemcap(n * size) == 0)
    return NULL;
  void *ptr = calloc(n, size);
  if (ptr == NULL)
    return NULL;
  StreamTcpReassembleIncrMemuse(n * size);
  return ptr;
}

/*
    void *(*Realloc)(void *ptr, size_t orig_size, size_t size);
*/
static void *ReassembleRealloc(void *optr, size_t orig_size, size_t size)
{
  if (size > orig_size) {
    if (StreamTcpReassembleCheckMemcap(size - orig_size) == 0)
      return NULL;
  }
  void *nptr = realloc(optr, size);
  if (nptr == NULL)
    return NULL;

  if (size > orig_size) {
    StreamTcpReassembleIncrMemuse(size - orig_size);
  } else {
    StreamTcpReassembleDecrMemuse(orig_size - size);
  }
  return nptr;
}

/*
    void (*Free)(void *ptr, size_t size);
*/
static void ReassembleFree(void *ptr, size_t size)
{
  free(ptr);
  StreamTcpReassembleDecrMemuse(size);
}

/** \brief alloc a tcp segment pool entry */
static void *TcpSegmentPoolAlloc(void)
{
  if (StreamTcpReassembleCheckMemcap((uint32_t)sizeof(TcpSegment)) == 0) {
    return NULL;
  }

  TcpSegment *seg = NULL;

  seg = malloc(sizeof (TcpSegment));
  if (unlikely(seg == NULL))
    return NULL;
  return seg;
}

static int TcpSegmentPoolInit(void *data, void *initdata)
{
  TcpSegment *seg = (TcpSegment *) data;

  /* do this before the can bail, so TcpSegmentPoolCleanup
     * won't have uninitialized memory to consider. */
  memset(seg, 0, sizeof (TcpSegment));

  if (StreamTcpReassembleCheckMemcap((uint32_t)sizeof(TcpSegment)) == 0) {
    return 0;
  }

#ifdef DEBUG
  SCMutexLock(&segment_pool_memuse_mutex);
  segment_pool_memuse += sizeof(TcpSegment);
  segment_pool_memcnt++;
  SCLogDebug("segment_pool_memcnt %"PRIu64"", segment_pool_memcnt);
  SCMutexUnlock(&segment_pool_memuse_mutex);
#endif

  StreamTcpReassembleIncrMemuse((uint32_t)sizeof(TcpSegment));
  return 1;
}

/** \brief clean up a tcp segment pool entry */
static void TcpSegmentPoolCleanup(void *ptr)
{
  if (ptr == NULL)
    return;

  StreamTcpReassembleDecrMemuse((uint32_t)sizeof(TcpSegment));

#ifdef DEBUG
  SCMutexLock(&segment_pool_memuse_mutex);
  segment_pool_memuse -= sizeof(TcpSegment);
  segment_pool_memcnt--;
  SCLogDebug("segment_pool_memcnt %"PRIu64"", segment_pool_memcnt);
  SCMutexUnlock(&segment_pool_memuse_mutex);
#endif
}

/**
 *  \brief Function to return the segment back to the pool.
 *
 *  \param seg Segment which will be returned back to the pool.
 */
void StreamTcpSegmentReturntoPool(TcpSegment *seg)
{
  if (seg == NULL)
    return;

  PoolThreadReturn(segment_thread_pool, seg);
}

/**
 *  \brief return all segments in this stream into the pool(s)
 *
 *  \param stream the stream to cleanup
 */
void StreamTcpReturnStreamSegments (TcpStream *stream)
{
  TcpSegment *seg = NULL, *safe = NULL;
  RB_FOREACH_SAFE(seg, TCPSEG, &stream->seg_tree, safe)
  {
    RB_REMOVE(TCPSEG, &stream->seg_tree, seg);
    StreamTcpSegmentReturntoPool(seg);
  }
}

/** \param f locked flow */
/*void StreamTcpDisableAppLayer(Flow *f)
{
  if (f->protoctx == NULL)
    return;

  TcpSession *ssn = (TcpSession *)f->protoctx;
  StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->client);
  StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->server);
  StreamTcpDisableAppLayerReassembly(ssn);
  if (f->alparser) {
    AppLayerParserStateSetFlag(f->alparser,
                               (APP_LAYER_PARSER_EOF_TS|APP_LAYER_PARSER_EOF_TC));
  }
}*/

/** \param f locked flow */
int StreamTcpAppLayerIsDisabled(Flow *f)
{
  if (f->protoctx == NULL || f->proto != IPPROTO_TCP)
    return 0;

  TcpSession *ssn = (TcpSession *)f->protoctx;
  return (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
}

static int StreamTcpReassemblyConfig(char quiet)
{
    uint32_t segment_prealloc = 2048;
    ConfNode *seg = ConfGetNode("stream.reassembly.segment-prealloc");
    if (seg) {
        uint32_t prealloc = 0;
        if (StringParseUint32(&prealloc, 10, strlen(seg->val), seg->val) < 0)
        {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "segment-prealloc of %s is invalid", seg->val);
            return -1;
        }
        segment_prealloc = prealloc;
    }
    if (!quiet)
        SCLogConfig("stream.reassembly \"segment-prealloc\": %u", segment_prealloc);
    stream_config.prealloc_segments = segment_prealloc;

    int overlap_diff_data = 0;
    ConfGetBool("stream.reassembly.check-overlap-different-data", &overlap_diff_data);
    if (overlap_diff_data) {
        StreamTcpReassembleConfigEnableOverlapCheck();
    }

    stream_config.sbcnf.flags = STREAMING_BUFFER_NOFLAGS;
    stream_config.sbcnf.buf_size = 2048;
    stream_config.sbcnf.Malloc = ReassembleMalloc;
    stream_config.sbcnf.Calloc = ReassembleCalloc;
    stream_config.sbcnf.Realloc = ReassembleRealloc;
    stream_config.sbcnf.Free = ReassembleFree;

    return 0;
}

int StreamTcpReassembleInit(char quiet)
{
  /* init the memcap/use tracker */
  StreamTcpReassembleInitMemuse();

  if (StreamTcpReassemblyConfig(quiet) < 0)
    return -1;

  //TODO:modify by haolipeng
  //StatsRegisterGlobalCounter("tcp.reassembly_memuse",StreamTcpReassembleMemuseGlobalCounter);
  return 0;
}

void StreamTcpReassembleFree(char quiet)
{
  SCMutexLock(&segment_thread_pool_mutex);
  if (segment_thread_pool != NULL) {
    PoolThreadFree(segment_thread_pool);
    segment_thread_pool = NULL;
  }
  SCMutexUnlock(&segment_thread_pool_mutex);
  SCMutexDestroy(&segment_thread_pool_mutex);

#ifdef DEBUG
  if (segment_pool_memuse > 0)
    SCLogInfo("segment_pool_memuse %"PRIu64"", segment_pool_memuse);
  if (segment_pool_memcnt > 0)
    SCLogInfo("segment_pool_memcnt %"PRIu64"", segment_pool_memcnt);
  SCMutexDestroy(&segment_pool_memuse_mutex);
#endif
}

TcpReassemblyThreadCtx *StreamTcpReassembleInitThreadCtx(ThreadVars *tv)
{
  TcpReassemblyThreadCtx *ra_ctx = malloc(sizeof(TcpReassemblyThreadCtx));
  if (unlikely(ra_ctx == NULL))
    return NULL;

  memset(ra_ctx, 0x00, sizeof(TcpReassemblyThreadCtx));

  //ra_ctx->app_tctx = AppLayerGetCtxThread(tv);

  SCMutexLock(&segment_thread_pool_mutex);
  if (segment_thread_pool == NULL) {
    segment_thread_pool = PoolThreadInit(1, /* thread */
                                         0, /* unlimited */
                                         stream_config.prealloc_segments,
                                         sizeof(TcpSegment),
                                         TcpSegmentPoolAlloc,
                                         TcpSegmentPoolInit, NULL,
                                         TcpSegmentPoolCleanup, NULL);
    ra_ctx->segment_thread_pool_id = 0;
    SCLogDebug("pool size %d, thread segment_thread_pool_id %d",
               PoolThreadSize(segment_thread_pool),
               ra_ctx->segment_thread_pool_id);
  } else {
    /* grow segment_thread_pool until we have a element for our thread id */
    ra_ctx->segment_thread_pool_id = PoolThreadExpand(segment_thread_pool);
    SCLogDebug("pool size %d, thread segment_thread_pool_id %d",
               PoolThreadSize(segment_thread_pool),
               ra_ctx->segment_thread_pool_id);
  }
  SCMutexUnlock(&segment_thread_pool_mutex);
  if (ra_ctx->segment_thread_pool_id < 0 || segment_thread_pool == NULL) {
    SCLogError(SC_ERR_MEM_ALLOC, "failed to setup/expand stream segment pool. Expand stream.reassembly.memcap?");
    StreamTcpReassembleFreeThreadCtx(ra_ctx);
    return NULL;
  }

  return ra_ctx;
}

void StreamTcpReassembleFreeThreadCtx(TcpReassemblyThreadCtx *ra_ctx)
{
  if (ra_ctx) {
    //TODO:modify App Layer
    //AppLayerDestroyCtxThread(ra_ctx->app_tctx);
    free(ra_ctx);
  }
  return ;
}

/**
 *  \brief check if stream in pkt direction has depth reached
 *
 *  \param p packet with *LOCKED* flow
 *
 *  \retval 1 stream has depth reached
 *  \retval 0 stream does not have depth reached
 */
int StreamTcpReassembleDepthReached(Packet *p)
{
  if (p->flow != NULL && p->flow->protoctx != NULL) {
    TcpSession *ssn = p->flow->protoctx;
    TcpStream *stream;
    if (p->flowflags & FLOW_PKT_TOSERVER) {
      stream = &ssn->client;
    } else {
      stream = &ssn->server;
    }

    return (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) ? 1 : 0;
  }

  return 0;
}

/**
 *  \internal
 *  \brief Function to Check the reassembly depth valuer against the
 *        allowed max depth of the stream reassembly for TCP streams.
 *
 *  \param stream stream direction
 *  \param seq sequence number where "size" starts
 *  \param size size of the segment that is added
 *
 *  \retval size Part of the size that fits in the depth, 0 if none
 */
static uint32_t StreamTcpReassembleCheckDepth(TcpSession *ssn, TcpStream *stream,
                                              uint32_t seq, uint32_t size)
{
  /* if the configured depth value is 0, it means there is no limit on
     reassembly depth. Otherwise carry on my boy ;) */
  if (ssn->reassembly_depth == 0) {
    return size;
  }

  /* if the final flag is set, we're not accepting anymore */
  if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
    return 0;
  }

  uint64_t seg_depth;
  if (SEQ_GT(stream->base_seq, seq)) {
    if (SEQ_LEQ(seq+size, stream->base_seq)) {
      SCLogDebug("segment entirely before base_seq, weird: base %u, seq %u, re %u",
                 stream->base_seq, seq, seq+size);
      return 0;
    }

    seg_depth = STREAM_BASE_OFFSET(stream) + size - (stream->base_seq - seq);
  } else {
    seg_depth = STREAM_BASE_OFFSET(stream) + ((seq + size) - stream->base_seq);
  }

  /* if the base_seq has moved passed the depth window we stop
     * checking and just reject the rest of the packets including
     * retransmissions. Saves us the hassle of dealing with sequence
     * wraps as well */
  SCLogDebug("seq + size %u, base %u, seg_depth %"PRIu64" limit %u", (seq + size),
             stream->base_seq, seg_depth,
             ssn->reassembly_depth);

  if (seg_depth > (uint64_t)ssn->reassembly_depth) {
    SCLogDebug("STREAMTCP_STREAM_FLAG_DEPTH_REACHED");
    stream->flags |= STREAMTCP_STREAM_FLAG_DEPTH_REACHED;
    return 0;
  }
  SCLogDebug("NOT STREAMTCP_STREAM_FLAG_DEPTH_REACHED");
  SCLogDebug("%"PRIu64" <= %u", seg_depth, ssn->reassembly_depth);
#if 0
    SCLogDebug("full depth not yet reached: %"PRIu64" <= %"PRIu32,
            (stream->base_seq_offset + stream->base_seq + size),
            (stream->isn + ssn->reassembly_depth));
#endif
  if (SEQ_GEQ(seq, stream->isn) && SEQ_LT(seq, (stream->isn + ssn->reassembly_depth))) {
    /* packet (partly?) fits the depth window */

    if (SEQ_LEQ((seq + size),(stream->isn + 1 + ssn->reassembly_depth))) {
      /* complete fit */
      return size;
    } else {
      stream->flags |= STREAMTCP_STREAM_FLAG_DEPTH_REACHED;
      /* partial fit, return only what fits */
      uint32_t part = (stream->isn + 1 + ssn->reassembly_depth) - seq;
      DEBUG_VALIDATE_BUG_ON(part > size);
      if (part > size)
        part = size;
      return (part);
    }
  }

  return (0);
}

uint32_t StreamDataAvailableForProtoDetect(TcpStream *stream)
{
  if (RB_EMPTY(&stream->sb.sbb_tree)) {
    if (stream->sb.stream_offset != 0)
      return 0;

    return stream->sb.buf_offset;
  } else {
    DEBUG_VALIDATE_BUG_ON(stream->sb.head == NULL);
    DEBUG_VALIDATE_BUG_ON(stream->sb.sbb_size == 0);
    return stream->sb.sbb_size;
  }
}

/**
 *  \brief Insert a packets TCP data into the stream reassembly engine.
 *
 *  \retval 0 good segment, as far as we checked.
 *  \retval -1 badness, reason to drop in inline mode
 *
 *  If the retval is 0 the segment is inserted correctly, or overlap is handled,
 *  or it wasn't added because of reassembly depth.
 *
 */
int StreamTcpReassembleHandleSegmentHandleData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                               TcpSession *ssn, TcpStream *stream, Packet *p)
{
    if (ssn->data_first_seen_dir == 0) {
        if (PKT_IS_TOSERVER(p)) {
            ssn->data_first_seen_dir = STREAM_TOSERVER;
        } else {
            ssn->data_first_seen_dir = STREAM_TOCLIENT;
        }
    }

    /* If the OS policy is not set then set the OS policy for this stream */
    if (stream->os_policy == 0) {
        StreamTcpSetOSPolicy(stream, p);
    }

    if ((ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) &&
        (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED)) {
        SCLogDebug("ssn %p: both app and raw reassembly disabled, not reassembling", ssn);
        return (0);
    }

    /* If we have reached the defined depth for either of the stream, then stop
       reassembling the TCP session */
    uint32_t size = StreamTcpReassembleCheckDepth(ssn, stream, TCP_GET_SEQ(p), p->payload_len);
    SCLogDebug("ssn %p: check depth returned %"PRIu32, ssn, size);

    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
        /* increment stream depth counter */
        //StatsIncr(tv, ra_ctx->counter_tcp_stream_depth);
    }
    if (size == 0) {
        SCLogDebug("ssn %p: depth reached, not reassembling", ssn);
        return (0);
    }

    DEBUG_VALIDATE_BUG_ON(size > p->payload_len);
    if (size > p->payload_len)
        size = p->payload_len;

    TcpSegment *seg = StreamTcpGetSegment(tv, ra_ctx);
    if (seg == NULL) {
        SCLogDebug("segment_pool is empty");
        StreamTcpSetEvent(p, STREAM_REASSEMBLY_NO_SEGMENT);
        return (-1);
    }

    TCP_SEG_LEN(seg) = size;
    seg->seq = TCP_GET_SEQ(p);

    /* HACK: for TFO SYN packets the seq for data starts at + 1 */
    if (TCP_HAS_TFO(p) && p->payload_len && p->tcph->th_flags == TH_SYN)
        seg->seq += 1;

    /* proto detection skipped, but now we do get data. Set event. */
    if (RB_EMPTY(&stream->seg_tree) &&
        stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_SKIPPED) {
        //TODO:App Layer modify by haolipeng
        //AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,APPLAYER_PROTO_DETECTION_SKIPPED);
    }

    if (StreamTcpReassembleInsertSegment(tv, ra_ctx, stream, seg, p, TCP_GET_SEQ(p), p->payload, p->payload_len) != 0) {
        SCLogDebug("StreamTcpReassembleInsertSegment failed");
        return (-1);
    }
    return (0);
}

static uint8_t StreamGetAppLayerFlags(TcpSession *ssn, TcpStream *stream,
                                      Packet *p)
{
  uint8_t flag = 0;

  if (!(stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED)) {
    flag |= STREAM_START;
  }

  if (ssn->state == TCP_CLOSED) {
    flag |= STREAM_EOF;
  }

  if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
    flag |= STREAM_MIDSTREAM;
  }

  if (p->flags & PKT_PSEUDO_STREAM_END) {
    flag |= STREAM_EOF;
  }

  if (&ssn->client == stream) {
    flag |= STREAM_TOSERVER;
  } else {
    flag |= STREAM_TOCLIENT;
  }
  if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
    flag |= STREAM_DEPTH;
  }
  return flag;
}

/**
 *  \brief Check the minimum size limits for reassembly.
 *
 *  \retval 0 don't reassemble yet
 *  \retval 1 do reassemble
 */
static int StreamTcpReassembleRawCheckLimit(const TcpSession *ssn,
                                            const TcpStream *stream, const Packet *p)
{
  /* if any of these flags is set we always inspect immediately */
#define STREAMTCP_STREAM_FLAG_FLUSH_FLAGS       \
        (   STREAMTCP_STREAM_FLAG_DEPTH_REACHED \
        |   STREAMTCP_STREAM_FLAG_TRIGGER_RAW   \
        |   STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED)

  if (stream->flags & STREAMTCP_STREAM_FLAG_FLUSH_FLAGS) {
    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
      SCLogDebug("reassembling now as STREAMTCP_STREAM_FLAG_DEPTH_REACHED "
                 "is set, so not expecting any new data segments");
    }
    if (stream->flags & STREAMTCP_STREAM_FLAG_TRIGGER_RAW) {
      SCLogDebug("reassembling now as STREAMTCP_STREAM_FLAG_TRIGGER_RAW is set");
    }
    if (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED) {
      SCLogDebug("reassembling now as STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED is set, "
                 "so no new segments will be considered");
    }
    return (1);
  }
#undef STREAMTCP_STREAM_FLAG_FLUSH_FLAGS

  /* some states mean we reassemble no matter how much data we have */
  if (ssn->state > TCP_TIME_WAIT)
    return (1);

  if (p->flags & PKT_PSEUDO_STREAM_END)
    return (1);

  /* check if we have enough data to do raw reassembly */
  if (PKT_IS_TOSERVER(p)) {
    if (STREAM_LASTACK_GT_BASESEQ(stream)) {
      uint32_t delta = stream->last_ack - stream->base_seq;
      /* get max absolute offset */
      uint64_t max_offset = STREAM_BASE_OFFSET(stream) + delta;

      int64_t diff = max_offset - STREAM_RAW_PROGRESS(stream);
      if ((int64_t)stream_config.reassembly_toserver_chunk_size <= diff) {
        return (1);
      } else {
        SCLogDebug("toserver min chunk len not yet reached: "
                   "last_ack %"PRIu32", ra_raw_base_seq %"PRIu32", %"PRIu32" < "
                   "%"PRIu32"", stream->last_ack, stream->base_seq,
                   (stream->last_ack - stream->base_seq),
                   stream_config.reassembly_toserver_chunk_size);
        return (0);
      }
    }
  } else {
    if (STREAM_LASTACK_GT_BASESEQ(stream)) {
      uint32_t delta = stream->last_ack - stream->base_seq;
      /* get max absolute offset */
      uint64_t max_offset = STREAM_BASE_OFFSET(stream) + delta;

      int64_t diff = max_offset - STREAM_RAW_PROGRESS(stream);

      if ((int64_t)stream_config.reassembly_toclient_chunk_size <= diff) {
        return (1);
      } else {
        SCLogDebug("toclient min chunk len not yet reached: "
                   "last_ack %"PRIu32", base_seq %"PRIu32",  %"PRIu32" < "
                   "%"PRIu32"", stream->last_ack, stream->base_seq,
                   (stream->last_ack - stream->base_seq),
                   stream_config.reassembly_toclient_chunk_size);
        return (0);
      }
    }
  }

  return (0);
}

/**
 *  \brief see what if any work the TCP session still needs
 */
int StreamNeedsReassembly(const TcpSession *ssn, uint8_t direction)
{
  const TcpStream *stream = NULL;
#ifdef DEBUG
  const char *dirstr = NULL;
#endif
  if (direction == STREAM_TOSERVER) {
    stream = &ssn->client;
#ifdef DEBUG
    dirstr = "client";
#endif
  } else {
    stream = &ssn->server;
#ifdef DEBUG
    dirstr = "server";
#endif
  }

  int use_app = 1;
  int use_raw = 1;

  if (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) {
    // app is dead
    use_app = 0;
  }

  if (stream->flags & STREAMTCP_STREAM_FLAG_DISABLE_RAW) {
    // raw is dead
    use_raw = 0;
  }

  uint64_t right_edge = STREAM_BASE_OFFSET(stream) + stream->sb.buf_offset;

  SCLogDebug("%s: app %"PRIu64" (use: %s), raw %"PRIu64" (use: %s). Stream right edge: %"PRIu64,
             dirstr,
             STREAM_APP_PROGRESS(stream), use_app ? "yes" : "no",
             STREAM_RAW_PROGRESS(stream), use_raw ? "yes" : "no",
             right_edge);
  if (use_raw) {
    if (right_edge > STREAM_RAW_PROGRESS(stream)) {
      SCLogDebug("%s: STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION", dirstr);
      return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
    }
  }
  if (use_app) {
    if (right_edge > STREAM_APP_PROGRESS(stream)) {
      SCLogDebug("%s: STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION", dirstr);
      return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
    }
  }

  SCLogDebug("%s: STREAM_HAS_UNPROCESSED_SEGMENTS_NONE", dirstr);
  return STREAM_HAS_UNPROCESSED_SEGMENTS_NONE;
}

#ifdef DEBUG
static uint64_t GetStreamSize(TcpStream *stream)
{
  if (stream) {
    uint64_t size = 0;
    uint32_t cnt = 0;

    TcpSegment *seg;
    RB_FOREACH(seg, TCPSEG, &stream->seg_tree) {
      cnt++;
      size += (uint64_t)TCP_SEG_LEN(seg);
    }

    SCLogDebug("size %"PRIu64", cnt %"PRIu32, size, cnt);
    return size;
  }
  return (uint64_t)0;
}

static void GetSessionSize(TcpSession *ssn, Packet *p)
{
  uint64_t size = 0;
  if (ssn) {
    size = GetStreamSize(&ssn->client);
    size += GetStreamSize(&ssn->server);

    //if (size > 900000)
    //    SCLogInfo("size %"PRIu64", packet %"PRIu64, size, p->pcap_cnt);
    SCLogDebug("size %"PRIu64", packet %"PRIu64, size, p->pcap_cnt);
  }
}
#endif

static StreamingBufferBlock *GetBlock(StreamingBuffer *sb, const uint64_t offset)
{
  StreamingBufferBlock *blk = sb->head;
  if (blk == NULL)
    return NULL;

  for ( ; blk != NULL; blk = SBB_RB_NEXT(blk)) {
    if (blk->offset >= offset)
      return blk;
    else if ((blk->offset + blk->len) > offset) {
      return blk;
    }
  }
  return NULL;
}

static inline uint64_t GetAbsLastAck(const TcpStream *stream)
{
  if (STREAM_LASTACK_GT_BASESEQ(stream)) {
    return STREAM_BASE_OFFSET(stream) +
           (stream->last_ack - stream->base_seq);
  } else {
    return STREAM_BASE_OFFSET(stream);
  }
}

static inline bool GapAhead(TcpStream *stream, StreamingBufferBlock *cur_blk)
{
  StreamingBufferBlock *nblk = SBB_RB_NEXT(cur_blk);
  if (nblk && (cur_blk->offset + cur_blk->len < nblk->offset) &&
      GetAbsLastAck(stream) > (cur_blk->offset + cur_blk->len)) {
    return true;
  }
  return false;
}

/** \internal
 *
 *  Get buffer, or first part of the buffer if data gaps exist.
 *
 *  \brief get stream data from offset
 *  \param offset stream offset
 *  \param check_for_gap check if there is a gap ahead. Optional as it is only
 *                       needed for app-layer incomplete support.
 *  \retval bool pkt loss ahead */
static bool GetAppBuffer(TcpStream *stream, const uint8_t **data, uint32_t *data_len,
                         uint64_t offset, const bool check_for_gap)
{
  const uint8_t *mydata;
  uint32_t mydata_len;
  bool gap_ahead = false;

  if (RB_EMPTY(&stream->sb.sbb_tree)) {
    SCLogDebug("getting one blob");

    StreamingBufferGetDataAtOffset(&stream->sb, &mydata, &mydata_len, offset);

    *data = mydata;
    *data_len = mydata_len;
  } else {
    StreamingBufferBlock *blk = GetBlock(&stream->sb, offset);
    if (blk == NULL) {
      *data = NULL;
      *data_len = 0;
      return false;
    }

    /* block at expected offset */
    if (blk->offset == offset) {

      StreamingBufferSBBGetData(&stream->sb, blk, data, data_len);

      gap_ahead = check_for_gap && GapAhead(stream, blk);

      /* block past out offset */
    } else if (blk->offset > offset) {
      SCLogDebug("gap, want data at offset %"PRIu64", "
                 "got data at %"PRIu64". GAP of size %"PRIu64,
                 offset, blk->offset, blk->offset - offset);
      *data = NULL;
      *data_len = blk->offset - offset;

      /* block starts before offset, but ends after */
    } else if (offset > blk->offset && offset <= (blk->offset + blk->len)) {
      SCLogDebug("get data from offset %"PRIu64". SBB %"PRIu64"/%u",
                 offset, blk->offset, blk->len);
      StreamingBufferSBBGetDataAtOffset(&stream->sb, blk, data, data_len, offset);
      SCLogDebug("data %p, data_len %u", *data, *data_len);

      gap_ahead = check_for_gap && GapAhead(stream, blk);

    } else {
      *data = NULL;
      *data_len = 0;
    }
  }
  return gap_ahead;
}

/** \internal
 *  \brief check to see if we should declare a GAP
 *  Call this when the app layer didn't get data at the requested
 *  offset.
 */
static inline bool CheckGap(TcpSession *ssn, TcpStream *stream, Packet *p)
{
  const uint64_t app_progress = STREAM_APP_PROGRESS(stream);
  uint64_t last_ack_abs = STREAM_BASE_OFFSET(stream);

  if (STREAM_LASTACK_GT_BASESEQ(stream)) {
    /* get window of data that is acked */
    const uint32_t delta = stream->last_ack - stream->base_seq;
    /* get max absolute offset */
    last_ack_abs += delta;

    const int ackadded = (ssn->state >= TCP_FIN_WAIT1) ? 1 : 0;
    last_ack_abs -= ackadded;

    SCLogDebug("last_ack %u abs %"PRIu64, stream->last_ack, last_ack_abs);
    SCLogDebug("next_seq %u", stream->next_seq);

    /* if last_ack_abs is beyond the app_progress data that we haven't seen
         * has been ack'd. This looks like a GAP. */
    if (last_ack_abs > app_progress) {
      /* however, we can accept ACKs a bit too liberally. If last_ack
             * is beyond next_seq, we only consider it a gap now if we do
             * already have data beyond the gap. */
      if (SEQ_GT(stream->last_ack, stream->next_seq)) {
        if (RB_EMPTY(&stream->sb.sbb_tree)) {
          SCLogDebug("packet %"PRIu64": no GAP. "
                     "next_seq %u < last_ack %u, but no data in list",
                     p->pcap_cnt, stream->next_seq, stream->last_ack);
          return false;
        } else {
          const uint64_t next_seq_abs = STREAM_BASE_OFFSET(stream) + (stream->next_seq - stream->base_seq);
          const StreamingBufferBlock *blk = stream->sb.head;
          if (blk->offset > next_seq_abs && blk->offset < last_ack_abs) {
            /* ack'd data after the gap */
            SCLogDebug("packet %"PRIu64": GAP. "
                       "next_seq %u < last_ack %u, but ACK'd data beyond gap.",
                       p->pcap_cnt, stream->next_seq, stream->last_ack);
            return true;
          }
        }
      }

      SCLogDebug("packet %"PRIu64": GAP! "
                 "last_ack_abs %"PRIu64" > app_progress %"PRIu64", "
                 "but we have no data.",
                 p->pcap_cnt, last_ack_abs, app_progress);
      return true;
    }
  }
  SCLogDebug("packet %"PRIu64": no GAP. "
             "last_ack_abs %"PRIu64" <= app_progress %"PRIu64,
             p->pcap_cnt, last_ack_abs, app_progress);
  return false;
}

static inline uint32_t AdjustToAcked(const Packet *p,
                                     const TcpSession *ssn, const TcpStream *stream,
                                     const uint64_t app_progress, const uint32_t data_len)
{
  uint32_t adjusted = data_len;

  /* get window of data that is acked */
  if (1) {
    SCLogDebug("ssn->state %s", StreamTcpStateAsString(ssn->state));
    if (data_len == 0 || ((ssn->state < TCP_CLOSED ||
                           (ssn->state == TCP_CLOSED &&
                            (ssn->flags & STREAMTCP_FLAG_CLOSED_BY_RST) != 0)) &&
                          (p->flags & PKT_PSEUDO_STREAM_END))) {
      // fall through, we use all available data
    } else {
      uint64_t last_ack_abs = STREAM_BASE_OFFSET(stream);
      if (STREAM_LASTACK_GT_BASESEQ(stream)) {
        /* get window of data that is acked */
        uint32_t delta = stream->last_ack - stream->base_seq;
        /* get max absolute offset */
        last_ack_abs += delta;
      }
      DEBUG_VALIDATE_BUG_ON(app_progress > last_ack_abs);

      /* see if the buffer contains unack'd data as well */
      if (app_progress <= last_ack_abs && app_progress + data_len > last_ack_abs) {
        uint32_t check = data_len;
        adjusted = last_ack_abs - app_progress;
        BUG_ON(adjusted > check);
        SCLogDebug("data len adjusted to %u to make sure only ACK'd "
                   "data is considered", adjusted);
      }
    }
  }
  return adjusted;
}

/** \internal
 *  \brief get stream buffer and update the app-layer
 *  \param stream pointer to pointer as app-layer can switch flow dir
 *  \retval 0 success
 */
 //TODO:modify by haolipeng app layer
#if 0
static int ReassembleUpdateAppLayer (ThreadVars *tv,
                                    TcpReassemblyThreadCtx *ra_ctx,
                                    TcpSession *ssn, TcpStream **stream,
                                    Packet *p, enum StreamUpdateDir dir)
{
  uint64_t app_progress = STREAM_APP_PROGRESS(*stream);

  SCLogDebug("app progress %"PRIu64, app_progress);
  SCLogDebug("last_ack %u, base_seq %u", (*stream)->last_ack, (*stream)->base_seq);

  const uint8_t *mydata;
  uint32_t mydata_len;
  bool gap_ahead = false;
  bool last_was_gap = false;

  while (1) {
    const uint8_t flags = StreamGetAppLayerFlags(ssn, *stream, p);
    bool check_for_gap_ahead = ((*stream)->data_required > 0);
    gap_ahead = GetAppBuffer(*stream, &mydata, &mydata_len,
                             app_progress, check_for_gap_ahead);
    if (last_was_gap && mydata_len == 0) {
      break;
    }
    last_was_gap = false;

    /* make sure to only deal with ACK'd data */
    mydata_len = AdjustToAcked(p, ssn, *stream, app_progress, mydata_len);
    DEBUG_VALIDATE_BUG_ON(mydata_len > (uint32_t)INT_MAX);
    if (mydata == NULL && mydata_len > 0 && CheckGap(ssn, *stream, p)) {
      SCLogDebug("sending GAP to app-layer (size: %u)", mydata_len);

      int r = AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                                    NULL, mydata_len,
                                    StreamGetAppLayerFlags(ssn, *stream, p)|STREAM_GAP);
      AppLayerProfilingStore(ra_ctx->app_tctx, p);

      StreamTcpSetEvent(p, STREAM_REASSEMBLY_SEQ_GAP);
      StatsIncr(tv, ra_ctx->counter_tcp_reass_gap);

      /* AppLayerHandleTCPData has likely updated progress. */
      const bool no_progress_update = (app_progress == STREAM_APP_PROGRESS(*stream));
      app_progress = STREAM_APP_PROGRESS(*stream);

      /* a GAP also consumes 'data required'. TODO perhaps we can use
             * this to skip post GAP data until the start of a next record. */
      if ((*stream)->data_required > 0) {
        if ((*stream)->data_required > mydata_len) {
          (*stream)->data_required -= mydata_len;
        } else {
          (*stream)->data_required = 0;
        }
      }
      if (r < 0)
        return 0;
      if (no_progress_update)
        break;
      last_was_gap = true;
      continue;

    } else if (flags & STREAM_DEPTH) {
      // we're just called once with this flag, so make sure we pass it on
      if (mydata == NULL && mydata_len > 0) {
        mydata_len = 0;
      }
    } else if (mydata == NULL || (mydata_len == 0 && ((flags & STREAM_EOF) == 0))) {
      /* Possibly a gap, but no new data. */
      if ((p->flags & PKT_PSEUDO_STREAM_END) == 0 || ssn->state < TCP_CLOSED)
        return (0);

      mydata = NULL;
      mydata_len = 0;
      SCLogDebug("%"PRIu64" got %p/%u", p->pcap_cnt, mydata, mydata_len);
      break;
    }
    DEBUG_VALIDATE_BUG_ON(mydata == NULL && mydata_len > 0);

    SCLogDebug("stream %p data in buffer %p of len %u and offset %"PRIu64,
               *stream, &(*stream)->sb, mydata_len, app_progress);

    if ((p->flags & PKT_PSEUDO_STREAM_END) == 0 || ssn->state < TCP_CLOSED) {
      if (mydata_len < (*stream)->data_required) {
        if (gap_ahead) {
          SCLogDebug("GAP while expecting more data (expect %u, gap size %u)",
                     (*stream)->data_required, mydata_len);
          (*stream)->app_progress_rel += mydata_len;
          (*stream)->data_required -= mydata_len;
          // TODO send incomplete data to app-layer with special flag
          // indicating its all there is for this rec?
        } else {
          return (0);
        }
        app_progress = STREAM_APP_PROGRESS(*stream);
        continue;
      }
    }
    (*stream)->data_required = 0;

    /* update the app-layer */
    (void)AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, stream,
                                (uint8_t *)mydata, mydata_len, flags);
    AppLayerProfilingStore(ra_ctx->app_tctx, p);
    uint64_t new_app_progress = STREAM_APP_PROGRESS(*stream);
    if (new_app_progress == app_progress || FlowChangeProto(p->flow))
      break;
    app_progress = new_app_progress;
    if (flags & STREAM_DEPTH)
      break;
  }

  return (0);
}
#endif

/**
 *  \brief Update the stream reassembly upon receiving a packet.
 *
 *  For IDS mode, the stream is in the opposite direction of the packet,
 *  as the ACK-packet is ACK'ing the stream.
 *
 *  One of the utilities call by this function AppLayerHandleTCPData(),
 *  has a feature where it will call this very same function for the
 *  stream opposing the stream it is called with.  This shouldn't cause
 *  any issues, since processing of each stream is independent of the
 *  other stream.
 */
#if 1
int StreamTcpReassembleAppLayer (ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                TcpSession *ssn, TcpStream *stream,
                                Packet *p, enum StreamUpdateDir dir)
{
  //TODO:modify by haolipeng
  return 0;
}
#else
int StreamTcpReassembleAppLayer (ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                TcpSession *ssn, TcpStream *stream,
                                Packet *p, enum StreamUpdateDir dir)
{
  /* this function can be directly called by app layer protocol
     * detection. */
  if ((ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) ||
      (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
    SCLogDebug("stream no reassembly flag set or app-layer disabled.");
    return (0);
  }

#ifdef DEBUG
  SCLogDebug("stream->seg_tree RB_MIN %p", RB_MIN(TCPSEG, &stream->seg_tree));
  GetSessionSize(ssn, p);
#endif
  /* if no segments are in the list or all are already processed,
     * and state is beyond established, we send an empty msg */
  if (!STREAM_HAS_SEEN_DATA(stream) || STREAM_RIGHT_EDGE(stream) <= STREAM_APP_PROGRESS(stream))
  {
    /* send an empty EOF msg if we have no segments but TCP state
         * is beyond ESTABLISHED */
    if (ssn->state >= TCP_CLOSING || (p->flags & PKT_PSEUDO_STREAM_END)) {
      SCLogDebug("sending empty eof message");
      /* send EOF to app layer */
      AppLayerHandleTCPData(tv, ra_ctx, p, p->flow, ssn, &stream,
                            NULL, 0,
                            StreamGetAppLayerFlags(ssn, stream, p));
      AppLayerProfilingStore(ra_ctx->app_tctx, p);

      return (0);
    }
  }

  /* with all that out of the way, lets update the app-layer */
  return ReassembleUpdateAppLayer(tv, ra_ctx, ssn, &stream, p, dir);
}
#endif

/** \internal
 *  \brief get stream data from offset
 *  \param offset stream offset */
static int GetRawBuffer(TcpStream *stream, const uint8_t **data, uint32_t *data_len,
                        StreamingBufferBlock **iter, uint64_t offset, uint64_t *data_offset)
{
  const uint8_t *mydata;
  uint32_t mydata_len;
  if (RB_EMPTY(&stream->sb.sbb_tree)) {
    SCLogDebug("getting one blob for offset %"PRIu64, offset);

    uint64_t roffset = offset;
    if (offset)
      StreamingBufferGetDataAtOffset(&stream->sb, &mydata, &mydata_len, offset);
    else {
      StreamingBufferGetData(&stream->sb, &mydata, &mydata_len, &roffset);
    }

    *data = mydata;
    *data_len = mydata_len;
    *data_offset = roffset;
  } else {
    SCLogDebug("multiblob %s. Want offset %"PRIu64,
               *iter == NULL ? "starting" : "continuing", offset);
    if (*iter == NULL) {
      StreamingBufferBlock key = { .offset = offset, .len = 0 };
      *iter = SBB_RB_FIND_INCLUSIVE(&stream->sb.sbb_tree, &key);
      SCLogDebug("*iter %p", *iter);
    }
    if (*iter == NULL) {
      SCLogDebug("no data");
      *data = NULL;
      *data_len = 0;
      *data_offset = 0;
      return 0;
    }
    SCLogDebug("getting multiple blobs. Iter %p, %"PRIu64"/%u", *iter, (*iter)->offset, (*iter)->len);

    StreamingBufferSBBGetData(&stream->sb, (*iter), &mydata, &mydata_len);
    SCLogDebug("mydata %p", mydata);

    if ((*iter)->offset < offset) {
      uint64_t delta = offset - (*iter)->offset;
      if (delta < mydata_len) {
        *data = mydata + delta;
        *data_len = mydata_len - delta;
        *data_offset = offset;
      } else {
        SCLogDebug("no data (yet)");
        *data = NULL;
        *data_len = 0;
        *data_offset = 0;
      }

    } else {
      *data = mydata;
      *data_len = mydata_len;
      *data_offset = (*iter)->offset;
    }

    *iter = SBB_RB_NEXT(*iter);
    SCLogDebug("*iter %p", *iter);
  }
  return 0;
}

/** \brief does the stream engine have data to inspect?
 *
 *  Returns true if there is data to inspect. In IDS case this is
 *  about ACK'd data in the packet's direction.
 *
 *  In the IPS case this is about the packet itself.
 */
bool StreamReassembleRawHasDataReady(TcpSession *ssn, Packet *p)
{
  TcpStream *stream;
  if (PKT_IS_TOSERVER(p)) {
    stream = &ssn->client;
  } else {
    stream = &ssn->server;
  }

  if (RB_EMPTY(&stream->seg_tree)) {
    return false;
  }

  if (stream->flags & (STREAMTCP_STREAM_FLAG_NOREASSEMBLY|
                       STREAMTCP_STREAM_FLAG_DISABLE_RAW))
    return false;

  if ((STREAM_RAW_PROGRESS(stream) == STREAM_BASE_OFFSET(stream) + stream->sb.buf_offset)) {
    return false;
  }
  if (StreamTcpReassembleRawCheckLimit(ssn, stream, p) == 1) {
    return true;
  }
  return false;
}

/** \brief update stream engine after detection
 *
 *  Tasked with progressing the 'progress' for Raw reassembly.
 *  2 main scenario's:
 *   1. progress is != 0, so we use this
 *   2. progress is 0, meaning the detect engine didn't touch
 *      raw at all. In this case we need to look into progressing
 *      raw anyway.
 *
 *  Additionally, this function is tasked with disabling raw
 *  reassembly if the app-layer requested to disable it.
 */
void StreamReassembleRawUpdateProgress(TcpSession *ssn, Packet *p, uint64_t progress)
{
  TcpStream *stream;
  if (PKT_IS_TOSERVER(p)) {
    stream = &ssn->client;
  } else {
    stream = &ssn->server;
  }

  if (progress > STREAM_RAW_PROGRESS(stream)) {
    uint32_t slide = progress - STREAM_RAW_PROGRESS(stream);
    stream->raw_progress_rel += slide;
    stream->flags &= ~STREAMTCP_STREAM_FLAG_TRIGGER_RAW;

    /* if app is active and beyond raw, sync raw to app */
  } else if (progress == 0 && STREAM_APP_PROGRESS(stream) > STREAM_RAW_PROGRESS(stream) &&
             !(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED)) {
    /* if trigger raw is set we sync the 2 trackers */
    if (stream->flags & STREAMTCP_STREAM_FLAG_TRIGGER_RAW)
    {
      uint32_t slide = STREAM_APP_PROGRESS(stream) - STREAM_RAW_PROGRESS(stream);
      stream->raw_progress_rel += slide;
      stream->flags &= ~STREAMTCP_STREAM_FLAG_TRIGGER_RAW;

      /* otherwise mix in the tcp window */
    } else {
      uint64_t tcp_window = stream->window;
      if (tcp_window > 0 && STREAM_APP_PROGRESS(stream) > tcp_window) {
        uint64_t new_raw = STREAM_APP_PROGRESS(stream) - tcp_window;
        if (new_raw > STREAM_RAW_PROGRESS(stream)) {
          uint32_t slide = new_raw - STREAM_RAW_PROGRESS(stream);
          stream->raw_progress_rel += slide;
        }
      }
    }
    /* app is dead */
  } else if (progress == 0) {
    uint64_t tcp_window = stream->window;
    uint64_t stream_right_edge = STREAM_BASE_OFFSET(stream) + stream->sb.buf_offset;
    if (tcp_window < stream_right_edge) {
      uint64_t new_raw = stream_right_edge - tcp_window;
      if (new_raw > STREAM_RAW_PROGRESS(stream)) {
        uint32_t slide = new_raw - STREAM_RAW_PROGRESS(stream);
        stream->raw_progress_rel += slide;
      }
    }
    stream->flags &= ~STREAMTCP_STREAM_FLAG_TRIGGER_RAW;

  } else {
    SCLogDebug("p->pcap_cnt %"PRIu64": progress %"PRIu64" app %"PRIu64" raw %"PRIu64" tcp win %"PRIu32,
               p->pcap_cnt, progress, STREAM_APP_PROGRESS(stream),
               STREAM_RAW_PROGRESS(stream), stream->window);
  }

  /* if we were told to accept no more raw data, we can mark raw as
     * disabled now. */
  if (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED) {
    stream->flags |= STREAMTCP_STREAM_FLAG_DISABLE_RAW;
    SCLogDebug("ssn %p: STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED set, "
               "now that detect ran also set STREAMTCP_STREAM_FLAG_DISABLE_RAW", ssn);
  }

  SCLogDebug("stream raw progress now %"PRIu64, STREAM_RAW_PROGRESS(stream));
}

/** \internal
  * \brief get a buffer around the current packet and run the callback on it
  *
  * The inline/IPS scanning method takes the current payload and wraps it in
  * data from other segments.
  *
  * How much data is inspected is controlled by the available data, chunk_size
  * and the payload size of the packet.
  *
  * Large packets: if payload size is close to the chunk_size, where close is
  * defined as more than 67% of the chunk_size, a larger chunk_size will be
  * used: payload_len + 33% of the chunk_size.
  * If the payload size if equal to or bigger than the chunk_size, we use
  * payload len + 33% of the chunk size.
 */
static int StreamReassembleRawInline(TcpSession *ssn, const Packet *p,
                                     StreamReassembleRawFunc Callback, void *cb_data, uint64_t *progress_out)
{
  int r = 0;

  TcpStream *stream;
  if (PKT_IS_TOSERVER(p)) {
    stream = &ssn->client;
  } else {
    stream = &ssn->server;
  }

  if (p->payload_len == 0 || (p->flags & PKT_STREAM_ADD) == 0 ||
      (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY))
  {
    *progress_out = STREAM_RAW_PROGRESS(stream);
    return 0;
  }

  uint32_t chunk_size = PKT_IS_TOSERVER(p) ?
                                           stream_config.reassembly_toserver_chunk_size :
                                           stream_config.reassembly_toclient_chunk_size;
  if (chunk_size <= p->payload_len) {
    chunk_size = p->payload_len + (chunk_size / 3);
    SCLogDebug("packet payload len %u, so chunk_size adjusted to %u",
               p->payload_len, chunk_size);
  } else if (((chunk_size / 3 ) * 2) < p->payload_len) {
    chunk_size = p->payload_len + ((chunk_size / 3));
    SCLogDebug("packet payload len %u, so chunk_size adjusted to %u",
               p->payload_len, chunk_size);
  }

  uint64_t packet_leftedge_abs = STREAM_BASE_OFFSET(stream) + (TCP_GET_SEQ(p) - stream->base_seq);
  uint64_t packet_rightedge_abs = packet_leftedge_abs + p->payload_len;
  SCLogDebug("packet_leftedge_abs %"PRIu64", rightedge %"PRIu64,
             packet_leftedge_abs, packet_rightedge_abs);

  const uint8_t *mydata = NULL;
  uint32_t mydata_len = 0;
  uint64_t mydata_offset = 0;
  /* simply return progress from the block we inspected. */
  bool return_progress = false;

  if (RB_EMPTY(&stream->sb.sbb_tree)) {
    /* continues block */
    StreamingBufferGetData(&stream->sb, &mydata, &mydata_len, &mydata_offset);
    return_progress = true;

  } else {
    SCLogDebug("finding our SBB from offset %"PRIu64, packet_leftedge_abs);
    /* find our block */
    StreamingBufferBlock key = { .offset = packet_leftedge_abs, .len = p->payload_len };
    StreamingBufferBlock *sbb = SBB_RB_FIND_INCLUSIVE(&stream->sb.sbb_tree, &key);
    if (sbb) {
      SCLogDebug("found %p offset %"PRIu64" len %u", sbb, sbb->offset, sbb->len);
      StreamingBufferSBBGetData(&stream->sb, sbb, &mydata, &mydata_len);
      mydata_offset = sbb->offset;
    }
  }

  /* this can only happen if the segment insert of our current 'p' failed */
  uint64_t mydata_rightedge_abs = mydata_offset + mydata_len;
  if ((mydata == NULL || mydata_len == 0) || /* no data */
      (mydata_offset >= packet_rightedge_abs || /* data all to the right */
       packet_leftedge_abs >= mydata_rightedge_abs) || /* data all to the left */
      (packet_leftedge_abs < mydata_offset || /* data missing at the start */
       packet_rightedge_abs > mydata_rightedge_abs)) /* data missing at the end */
  {
    /* no data, or data is incomplete or wrong: use packet data */
    mydata = p->payload;
    mydata_len = p->payload_len;
    mydata_offset = packet_leftedge_abs;
    //mydata_rightedge_abs = packet_rightedge_abs;
  } else {
    /* adjust buffer to match chunk_size */
    SCLogDebug("chunk_size %u mydata_len %u", chunk_size, mydata_len);
    if (mydata_len > chunk_size) {
      uint32_t excess = mydata_len - chunk_size;
      SCLogDebug("chunk_size %u mydata_len %u excess %u", chunk_size, mydata_len, excess);

      if (mydata_rightedge_abs == packet_rightedge_abs) {
        mydata += excess;
        mydata_len -= excess;
        mydata_offset += excess;
        SCLogDebug("cutting front of the buffer with %u", excess);
      } else if (mydata_offset == packet_leftedge_abs) {
        mydata_len -= excess;
        SCLogDebug("cutting tail of the buffer with %u", excess);
      } else {
        uint32_t before = (uint32_t)(packet_leftedge_abs - mydata_offset);
        uint32_t after = (uint32_t)(mydata_rightedge_abs - packet_rightedge_abs);
        SCLogDebug("before %u after %u", before, after);

        if (after >= (chunk_size - p->payload_len) / 2) {
          // more trailing data than we need

          if (before >= (chunk_size - p->payload_len) / 2) {
            // also more heading data, divide evenly
            before = after = (chunk_size - p->payload_len) / 2;
          } else {
            // heading data is less than requested, give the
            // rest to the trailing data
            after = (chunk_size - p->payload_len) - before;
          }
        } else {
          // less trailing data than requested

          if (before >= (chunk_size - p->payload_len) / 2) {
            before = (chunk_size - p->payload_len) - after;
          } else {
            // both smaller than their requested size
          }
        }

        /* adjust the buffer */
        uint32_t skip = (uint32_t)(packet_leftedge_abs - mydata_offset) - before;
        uint32_t cut = (uint32_t)(mydata_rightedge_abs - packet_rightedge_abs) - after;
        DEBUG_VALIDATE_BUG_ON(skip > mydata_len);
        DEBUG_VALIDATE_BUG_ON(cut > mydata_len);
        DEBUG_VALIDATE_BUG_ON(skip + cut > mydata_len);
        mydata += skip;
        mydata_len -= (skip + cut);
        mydata_offset += skip;
      }
    }
  }

  /* run the callback */
  r = Callback(cb_data, mydata, mydata_len);
  BUG_ON(r < 0);

  if (return_progress) {
    *progress_out = (mydata_offset + mydata_len);
  } else {
    /* several blocks of data, so we need to be a bit more careful:
         * - if last_ack is beyond last progress, move progress forward to last_ack
         * - if our block matches or starts before last ack, return right edge of
         *   our block.
     */
    uint64_t last_ack_abs = STREAM_BASE_OFFSET(stream);
    if (STREAM_LASTACK_GT_BASESEQ(stream)) {
      uint32_t delta = stream->last_ack - stream->base_seq;
      /* get max absolute offset */
      last_ack_abs += delta;
    }
    SCLogDebug("last_ack_abs %"PRIu64, last_ack_abs);

    if (STREAM_RAW_PROGRESS(stream) < last_ack_abs) {
      if (mydata_offset > last_ack_abs) {
        /* gap between us and last ack, set progress to last ack */
        *progress_out = last_ack_abs;
      } else {
        *progress_out = (mydata_offset + mydata_len);
      }
    } else {
      *progress_out = STREAM_RAW_PROGRESS(stream);
    }
  }
  return r;
}

/** \brief access 'raw' reassembly data.
 *
 *  Access data as tracked by 'raw' tracker. Data is made available to
 *  callback that is passed to this function.
 *
 *  In the case of IDS the callback may be run multiple times if data
 *  contains gaps. It will then be run for each block of data that is
 *  continuous.
 *
 *  The callback should give on of 2 return values:
 *  - 0 ok
 *  - 1 done
 *  The value 1 will break the loop if there is a block list that is
 *  inspected.
 *
 *  This function will return the 'progress' value that has been
 *  consumed until now.
 *
 *  \param ssn tcp session
 *  \param stream tcp stream
 *  \param Callback the function pointer to the callback function
 *  \param cb_data callback data
 *  \param[in] progress_in progress to work from
 *  \param[out] progress_out absolute progress value of the data this
 *                           call handled.
 *  \param eof we're wrapping up so inspect all data we have, incl unACKd
 *  \param respect_inspect_depth use Stream::min_inspect_depth if set
 *
 *  `respect_inspect_depth` is used to avoid useless inspection of too
 *  much data.
 */
static int StreamReassembleRawDo(TcpSession *ssn, TcpStream *stream,
                                 StreamReassembleRawFunc Callback, void *cb_data,
                                 const uint64_t progress_in,
                                 uint64_t *progress_out, bool eof,
                                 bool respect_inspect_depth)
{
  int r = 0;

  StreamingBufferBlock *iter = NULL;
  uint64_t progress = progress_in;
  uint64_t last_ack_abs = STREAM_BASE_OFFSET(stream); /* absolute right edge of ack'd data */

  /* if the app layer triggered a flush, and we're supposed to
     * use a minimal inspect depth, we actually take the app progress
     * as that is the right edge of the data. Then we take the window
     * of 'min_inspect_depth' before that. */

  SCLogDebug("respect_inspect_depth %s STREAMTCP_STREAM_FLAG_TRIGGER_RAW %s stream->min_inspect_depth %u",
             respect_inspect_depth ? "true" : "false",
             (stream->flags & STREAMTCP_STREAM_FLAG_TRIGGER_RAW) ? "true" : "false",
             stream->min_inspect_depth);

  if (respect_inspect_depth &&
      (stream->flags & STREAMTCP_STREAM_FLAG_TRIGGER_RAW)
      && stream->min_inspect_depth)
  {
    progress = STREAM_APP_PROGRESS(stream);
    if (stream->min_inspect_depth >= progress) {
      progress = 0;
    } else {
      progress -= stream->min_inspect_depth;
    }

    SCLogDebug("stream app %"PRIu64", raw %"PRIu64, STREAM_APP_PROGRESS(stream), STREAM_RAW_PROGRESS(stream));

    progress = MIN(progress, STREAM_RAW_PROGRESS(stream));
    SCLogDebug("applied min inspect depth due to STREAMTCP_STREAM_FLAG_TRIGGER_RAW: progress %"PRIu64, progress);
  }

  SCLogDebug("progress %"PRIu64", min inspect depth %u %s", progress, stream->min_inspect_depth, stream->flags & STREAMTCP_STREAM_FLAG_TRIGGER_RAW ? "STREAMTCP_STREAM_FLAG_TRIGGER_RAW":"(no trigger)");

  /* get window of data that is acked */
  if (STREAM_LASTACK_GT_BASESEQ(stream)) {
    SCLogDebug("last_ack %u, base_seq %u", stream->last_ack, stream->base_seq);
    uint32_t delta = stream->last_ack - stream->base_seq;
    /* get max absolute offset */
    last_ack_abs += delta;
    SCLogDebug("last_ack_abs %"PRIu64, last_ack_abs);
  }

  /* loop through available buffers. On no packet loss we'll have a single
     * iteration. On missing data we'll walk the blocks */
  while (1) {
    const uint8_t *mydata;
    uint32_t mydata_len;
    uint64_t mydata_offset = 0;

    GetRawBuffer(stream, &mydata, &mydata_len, &iter, progress, &mydata_offset);
    if (mydata_len == 0) {
      SCLogDebug("no data");
      break;
    }
    //PrintRawDataFp(stdout, mydata, mydata_len);

    SCLogDebug("raw progress %"PRIu64, progress);
    SCLogDebug("stream %p data in buffer %p of len %u and offset %"PRIu64,
               stream, &stream->sb, mydata_len, progress);

    if (eof) {
      // inspect all remaining data, ack'd or not
    } else {
      if (last_ack_abs < progress) {
        SCLogDebug("nothing to do");
        goto end;
      }

      SCLogDebug("last_ack_abs %"PRIu64", raw_progress %"PRIu64, last_ack_abs, progress);
      SCLogDebug("raw_progress + mydata_len %"PRIu64", last_ack_abs %"PRIu64, progress + mydata_len, last_ack_abs);

      /* see if the buffer contains unack'd data as well */
      if (progress + mydata_len > last_ack_abs) {
        uint32_t check = mydata_len;
        mydata_len = last_ack_abs - progress;
        BUG_ON(check < mydata_len);
        SCLogDebug("data len adjusted to %u to make sure only ACK'd "
                   "data is considered", mydata_len);
      }

    }
    if (mydata_len == 0)
      break;

    SCLogDebug("data %p len %u", mydata, mydata_len);

    /* we have data. */
    r = Callback(cb_data, mydata, mydata_len);
    BUG_ON(r < 0);

    if (mydata_offset == progress) {
      SCLogDebug("progress %"PRIu64" increasing with data len %u to %"PRIu64,
                 progress, mydata_len, progress_in + mydata_len);

      progress += mydata_len;
      SCLogDebug("raw progress now %"PRIu64, progress);

      /* data is beyond the progress we'd like, and before last ack. Gap. */
    } else if (mydata_offset > progress && mydata_offset < last_ack_abs) {
      SCLogDebug("GAP: data is missing from %"PRIu64" (%u bytes), setting to first data we have: %"PRIu64, progress, (uint32_t)(mydata_offset - progress), mydata_offset);
      SCLogDebug("last_ack_abs %"PRIu64, last_ack_abs);
      progress = mydata_offset;
      SCLogDebug("raw progress now %"PRIu64, progress);

    } else {
      SCLogDebug("not increasing progress, data gap => mydata_offset "
                 "%"PRIu64" != progress %"PRIu64, mydata_offset, progress);
    }

    if (iter == NULL || r == 1)
      break;
  }
end:
  *progress_out = progress;
  return r;
}

int StreamReassembleRaw(TcpSession *ssn, const Packet *p,
                        StreamReassembleRawFunc Callback, void *cb_data,
                        uint64_t *progress_out, bool respect_inspect_depth)
{
  TcpStream *stream;
  if (PKT_IS_TOSERVER(p)) {
    stream = &ssn->client;
  } else {
    stream = &ssn->server;
  }

  if ((stream->flags & (STREAMTCP_STREAM_FLAG_NOREASSEMBLY|STREAMTCP_STREAM_FLAG_DISABLE_RAW)) ||
      StreamTcpReassembleRawCheckLimit(ssn, stream, p) == 0)
  {
    *progress_out = STREAM_RAW_PROGRESS(stream);
    return 0;
  }

  return StreamReassembleRawDo(ssn, stream, Callback, cb_data,
                               STREAM_RAW_PROGRESS(stream), progress_out,
                               (p->flags & PKT_PSEUDO_STREAM_END), respect_inspect_depth);
}

int StreamReassembleLog(TcpSession *ssn, TcpStream *stream,
                        StreamReassembleRawFunc Callback, void *cb_data,
                        uint64_t progress_in,
                        uint64_t *progress_out, bool eof)
{
  if (stream->flags & (STREAMTCP_STREAM_FLAG_NOREASSEMBLY))
    return 0;

  return StreamReassembleRawDo(ssn, stream, Callback, cb_data,
                               progress_in, progress_out, eof, false);
}

/** \internal
 *  \brief update app layer based on received ACK
 *
 *  \retval r 0 on success, -1 on error
 */
static int StreamTcpReassembleHandleSegmentUpdateACK (ThreadVars *tv,
                                                     TcpReassemblyThreadCtx *ra_ctx, TcpSession *ssn, TcpStream *stream, Packet *p)
{
  if (StreamTcpReassembleAppLayer(tv, ra_ctx, ssn, stream, p, UPDATE_DIR_OPPOSING) < 0)
    return (-1);

  return (0);
}

int StreamTcpReassembleHandleSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                     TcpSession *ssn, TcpStream *stream,
                                     Packet *p, PacketQueueNoLock *pq)
{
  DEBUG_VALIDATE_BUG_ON(p->tcph == NULL);

  SCLogDebug("ssn %p, stream %p, p %p, p->payload_len %"PRIu16"",
             ssn, stream, p, p->payload_len);

  /* default IDS: update opposing side (triggered by ACK) */
  enum StreamUpdateDir dir = UPDATE_DIR_OPPOSING;
  /* inline and stream end and flow timeout packets trigger same dir handling */
  if (p->flags & PKT_PSEUDO_STREAM_END) {
    dir = UPDATE_DIR_PACKET;
  } else if (p->tcph->th_flags & TH_RST) { // accepted rst
    dir = UPDATE_DIR_PACKET;
  } else if ((p->tcph->th_flags & TH_FIN) && ssn->state > TCP_TIME_WAIT) {
    if (p->tcph->th_flags & TH_ACK) {
      dir = UPDATE_DIR_BOTH;
    } else {
      dir = UPDATE_DIR_PACKET;
    }
  } else if (ssn->state == TCP_CLOSED) {
    dir = UPDATE_DIR_BOTH;
  }

  /* handle ack received */
  if ((dir == UPDATE_DIR_OPPOSING || dir == UPDATE_DIR_BOTH)) {
    /* we need to update the opposing stream in
         * StreamTcpReassembleHandleSegmentUpdateACK */
    TcpStream *opposing_stream = NULL;
    if (stream == &ssn->client) {
      opposing_stream = &ssn->server;
    } else {
      opposing_stream = &ssn->client;
    }

    const bool reversed_before_ack_handling = (p->flow->flags & FLOW_DIR_REVERSED) != 0;

    if (StreamTcpReassembleHandleSegmentUpdateACK(tv, ra_ctx, ssn, opposing_stream, p) != 0) {
      SCLogDebug("StreamTcpReassembleHandleSegmentUpdateACK error");
      return (-1);
    }

    /* StreamTcpReassembleHandleSegmentUpdateACK
         * may swap content of ssn->server and ssn->client structures.
         * We have to continue with initial content of the stream in such case */
    const bool reversed_after_ack_handling = (p->flow->flags & FLOW_DIR_REVERSED) != 0;
    if (reversed_before_ack_handling != reversed_after_ack_handling) {
      SCLogDebug("TCP streams were swapped");
      stream = opposing_stream;
    }
  }
  /* if this segment contains data, insert it */
  if (p->payload_len > 0 && !(stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
    SCLogDebug("calling StreamTcpReassembleHandleSegmentHandleData");

    if (StreamTcpReassembleHandleSegmentHandleData(tv, ra_ctx, ssn, stream, p) != 0) {
      SCLogDebug("StreamTcpReassembleHandleSegmentHandleData error");
      /* failure can only be because of memcap hit, so see if this should lead to a drop */
      //TODO:modify by haolipeng
      //ExceptionPolicyApply(p, stream_config.reassembly_memcap_policy, PKT_DROP_REASON_STREAM_MEMCAP);
      return (-1);
    }

    SCLogDebug("packet %"PRIu64" set PKT_STREAM_ADD", p->pcap_cnt);
    p->flags |= PKT_STREAM_ADD;
  } else {
    SCLogDebug("ssn %p / stream %p: not calling StreamTcpReassembleHandleSegmentHandleData:"
               " p->payload_len %u, STREAMTCP_STREAM_FLAG_NOREASSEMBLY %s",
               ssn, stream, p->payload_len,
               (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ? "true" : "false");

  }

  /* if the STREAMTCP_STREAM_FLAG_DEPTH_REACHED is set, but not the
     * STREAMTCP_STREAM_FLAG_NOREASSEMBLY flag, it means the DEPTH flag
     * was *just* set. In this case we trigger the AppLayer Truncate
     * logic, to inform the applayer no more data in this direction is
     * to be expected. */
  if ((stream->flags & (STREAMTCP_STREAM_FLAG_DEPTH_REACHED|STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) == STREAMTCP_STREAM_FLAG_DEPTH_REACHED)
  {
    SCLogDebug("STREAMTCP_STREAM_FLAG_DEPTH_REACHED, truncate applayer");
    if (dir != UPDATE_DIR_PACKET) {
      SCLogDebug("override: direction now UPDATE_DIR_PACKET so we "
                 "can trigger Truncate");
      dir = UPDATE_DIR_PACKET;
    }
  }

  /* in stream inline mode even if we have no data we call the reassembly
     * functions to handle EOF */
  //在stream inline模式下，即使即使没有数据
  if (dir == UPDATE_DIR_PACKET || dir == UPDATE_DIR_BOTH) {
    SCLogDebug("inline (%s) or PKT_PSEUDO_STREAM_END (%s)",
               "false",
               (p->flags & PKT_PSEUDO_STREAM_END) ?"true":"false");
    if (StreamTcpReassembleAppLayer(tv, ra_ctx, ssn, stream, p, dir) < 0) {
      return (-1);
    }
  }

  return (0);
}

/**
 *  \brief get a segment from the pool
 *
 *  \retval seg Segment from the pool or NULL
 */
TcpSegment *StreamTcpGetSegment(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx)
{
  TcpSegment *seg = (TcpSegment *) PoolThreadGetById(segment_thread_pool, ra_ctx->segment_thread_pool_id);
  SCLogDebug("seg we return is %p", seg);
  if (seg == NULL) {
    /* Increment the counter to show that we are not able to serve the
       segment request due to memcap limit */
    //StatsIncr(tv, ra_ctx->counter_tcp_segment_memcap);
  } else {
    memset(&seg->sbseg, 0, sizeof(seg->sbseg));
  }

  return seg;
}

void StreamTcpReassembleTriggerRawReassembly(TcpSession *ssn, int direction)
{
#ifdef DEBUG
  BUG_ON(ssn == NULL);
#endif

  if (ssn != NULL) {
    if (direction == STREAM_TOSERVER) {
      ssn->client.flags |= STREAMTCP_STREAM_FLAG_TRIGGER_RAW;
    } else {
      ssn->server.flags |= STREAMTCP_STREAM_FLAG_TRIGGER_RAW;
    }

    SCLogDebug("flagged ssn %p for immediate raw reassembly", ssn);
  }
}

void StreamTcpReassemblySetMinInspectDepth(TcpSession *ssn, int direction, uint32_t depth)
{
#ifdef DEBUG
  BUG_ON(ssn == NULL);
#endif

  if (ssn != NULL) {
    if (direction == STREAM_TOSERVER) {
      ssn->client.min_inspect_depth = depth;
      SCLogDebug("ssn %p: set client.min_inspect_depth to %u", ssn, depth);
    } else {
      ssn->server.min_inspect_depth = depth;
      SCLogDebug("ssn %p: set server.min_inspect_depth to %u", ssn, depth);
    }
  }
}
