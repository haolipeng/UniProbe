#ifndef NET_THREAT_DETECT_PACKET_QUEUE_H
#define NET_THREAT_DETECT_PACKET_QUEUE_H
#include "decode/decode.h"
#include <stdint.h>

typedef struct PacketQueueNoLock_ {
    Packet *top;
    Packet *bot;
    uint32_t len;
} PacketQueueNoLock;

typedef struct PacketQueue_ {
    Packet *top;
    Packet *bot;
    uint32_t len;
    pthread_mutex_t mutex_q;
    pthread_cond_t cond_q;
} PacketQueue;

PacketQueue *PacketQueueAlloc(void);
void PacketEnqueueNoLock(PacketQueueNoLock *qnl, struct Packet_ *p);
//void PacketEnqueue (PacketQueue *, struct Packet_ *);

struct Packet_ *PacketDequeueNoLock (PacketQueueNoLock *qnl);
struct Packet_ *PacketDequeue (PacketQueue *);

#endif //NET_THREAT_DETECT_PACKET_QUEUE_H
