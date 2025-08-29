#ifndef NET_THREAT_DETECT_STREAM_TCP_H
#define NET_THREAT_DETECT_STREAM_TCP_H

#include "utils/packet-queue.h"
#include "decode/decode.h"
#include "stream-tcp-reassemble.h"
#include "modules/tm-threads-common.h"
#include "utils/util-exception-policy.h"

#define STREAM_VERBOSE    FALSE
/* Flag to indicate that the checksum validation for the stream engine
   has been enabled */
#define STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION    BIT_U8(0)
#define STREAMTCP_INIT_FLAG_DROP_INVALID           BIT_U8(1)
#define STREAMTCP_INIT_FLAG_BYPASS                 BIT_U8(2)
#define STREAMTCP_INIT_FLAG_INLINE                 BIT_U8(3)

/*global flow data*/
typedef struct TcpStreamCnf_ {
  /** stream tracking
     *
     * max stream mem usage
   */
  SC_ATOMIC_DECLARE(uint64_t, memcap);
  SC_ATOMIC_DECLARE(uint64_t, reassembly_memcap); /**< max memory usage for stream reassembly */

  uint16_t stream_init_flags; /**< new stream flags will be initialized to this */

  /* coccinelle: TcpStreamCnf:flags:STREAMTCP_INIT_ */
  uint8_t flags;
  uint8_t max_synack_queued;

  uint32_t prealloc_sessions; /**< ssns to prealloc per stream thread */
  uint32_t prealloc_segments; /**< segments to prealloc per stream thread */
  int midstream;
  int async_oneside;
  uint32_t reassembly_depth;  /**< Depth until when we reassemble the stream */

  uint16_t reassembly_toserver_chunk_size;
  uint16_t reassembly_toclient_chunk_size;

  bool streaming_log_api;

  enum ExceptionPolicy ssn_memcap_policy;
  enum ExceptionPolicy reassembly_memcap_policy;
  enum ExceptionPolicy midstream_policy;

  StreamingBufferConfig sbcnf;
} TcpStreamCnf;

typedef struct StreamTcpThread_ {
  int ssn_pool_id;

  /** queue for pseudo packet(s) that were created in the stream
     *  process and need further handling. Currently only used when
     *  receiving (valid) RST packets */
  PacketQueueNoLock pseudo_queue;

  uint16_t counter_tcp_sessions;
  /** sessions not picked up because memcap was reached */
  uint16_t counter_tcp_ssn_memcap;
  /** pseudo packets processed */
  uint16_t counter_tcp_pseudo;
  /** pseudo packets failed to setup */
  uint16_t counter_tcp_pseudo_failed;
  /** packets rejected because their csum is invalid */
  uint16_t counter_tcp_invalid_checksum;
  /** TCP packets with no associated flow */
  uint16_t counter_tcp_no_flow;
  /** sessions reused */
  uint16_t counter_tcp_reused_ssn;
  /** syn pkts */
  uint16_t counter_tcp_syn;
  /** syn/ack pkts */
  uint16_t counter_tcp_synack;
  /** rst pkts */
  uint16_t counter_tcp_rst;
  /** midstream pickups */
  uint16_t counter_tcp_midstream_pickups;
  /** wrong thread */
  uint16_t counter_tcp_wrong_thread;

  /** tcp reassembly thread data */
  TcpReassemblyThreadCtx *ra_ctx;
} StreamTcpThread;

extern TcpStreamCnf stream_config;
void StreamTcpInitConfig (char);
void StreamTcpFreeConfig(char);
void StreamTcpRegisterTests (void);

void StreamTcpSessionPktFree (Packet *);

void StreamTcpInitMemuse(void);
void StreamTcpIncrMemuse(uint64_t);
void StreamTcpDecrMemuse(uint64_t);
int StreamTcpSetMemcap(uint64_t);
uint64_t StreamTcpGetMemcap(void);
int StreamTcpCheckMemcap(uint64_t);
uint64_t StreamTcpMemuseCounter(void);
uint64_t StreamTcpReassembleMemuseGlobalCounter(void);

Packet *StreamTcpPseudoSetup(Packet *, uint8_t *, uint32_t);

void StreamTcpReassembleConfigEnableOverlapCheck(void);
void TcpSessionSetReassemblyDepth(TcpSession *ssn, uint32_t size);

typedef int (*StreamReassembleRawFunc)(void *data, const uint8_t *input, const uint32_t input_len);

int StreamReassembleLog(TcpSession *ssn, TcpStream *stream,StreamReassembleRawFunc Callback, void *cb_data,
                        uint64_t progress_in,uint64_t *progress_out, bool eof);
int StreamReassembleRaw(TcpSession *ssn, const Packet *p,
                        StreamReassembleRawFunc Callback, void *cb_data,
                        uint64_t *progress_out, bool respect_inspect_depth);
void StreamReassembleRawUpdateProgress(TcpSession *ssn, Packet *p, uint64_t progress);

void StreamTcpDetectLogFlush(ThreadVars *tv, StreamTcpThread *stt, Flow *f, Packet *p, PacketQueueNoLock *pq);

const char *StreamTcpStateAsString(const enum TcpState);
const char *StreamTcpSsnStateAsString(const TcpSession *ssn);

/** ------- Inline functions: ------ */
enum {
  /* stream has no segments for forced reassembly, nor for detection */
  STREAM_HAS_UNPROCESSED_SEGMENTS_NONE = 0,
  /* stream has no segments for forced reassembly, but only segments that
     * have been sent for detection, but are stuck in the detection queues */
  STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION = 1,
};

TmEcode StreamTcp (ThreadVars *, Packet *, void *, PacketQueueNoLock *);
int StreamNeedsReassembly(const TcpSession *ssn, uint8_t direction);
TmEcode StreamTcpThreadInit(ThreadVars *, void *, void **);
TmEcode StreamTcpThreadDeinit(ThreadVars *tv, void *data);

int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt,PacketQueueNoLock *pq);
/* clear ssn and return to pool */
void StreamTcpSessionClear(void *ssnptr);
/* cleanup ssn, but don't free ssn */
void StreamTcpSessionCleanup(TcpSession *ssn);
/* cleanup stream, but don't free the stream */
void StreamTcpStreamCleanup(TcpStream *stream);
/* check if bypass is enabled */
int StreamTcpBypassEnabled(void);

int TcpSessionPacketSsnReuse(const Packet *p, const Flow *f, const void *tcp_ssn);

void StreamTcpUpdateAppLayerProgress(TcpSession *ssn, char direction,
                                     const uint32_t progress);

#endif //NET_THREAT_DETECT_STREAM_TCP_H
