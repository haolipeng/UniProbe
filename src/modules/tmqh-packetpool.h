#ifndef __TMQH_PACKETPOOL_H__
#define __TMQH_PACKETPOOL_H__

#include "decode/decode.h"
#include "utils/util-atomic.h"
#include "utils/threads.h"
#include "utils/packet-queue.h"

/* Return stack, onto which other threads free packets. */
typedef struct PktPoolLockedStack_{
    /* linked list of free packets. */
    SCMutex mutex;
    SCCondT cond;
    SC_ATOMIC_DECLARE(int, sync_now);
    Packet *head;
} __attribute__((aligned(64))) PktPoolLockedStack;

typedef struct PktPool_ {
    /* link listed of free packets local to this thread.
     * No mutex is needed.
     */
    Packet *head;
    /* Packets waiting (pending) to be returned to the given Packet
     * Pool. Accumulate packets for the same pool until a theshold is
     * reached, then return them all at once.  Keep the head and tail
     * to fast insertion of the entire list onto a return stack.
     */
    struct PktPool_ *pending_pool;
    Packet *pending_head;
    Packet *pending_tail;
    uint32_t pending_count;

    /* All members above this point are accessed locally by only one thread, so
     * these should live on their own cache line.
     */

    /* Return stack, where other threads put packets that they free that belong
     * to this thread.
     */
    PktPoolLockedStack return_stack;
} PktPool;

Packet *TmqhInputPacketpool(ThreadVars *);
void TmqhOutputPacketpool(ThreadVars *, Packet *);
void TmqhReleasePacketsToPacketPool(PacketQueue *pq);

void TmqhPacketpoolRegister(void);
Packet *PacketPoolGetPacket(void);
void PacketPoolWait(void);
void PacketPoolWaitForN(int n);
void PacketPoolReturnPacket(Packet *p);
void PacketPoolInit(void);
void PacketPoolInitEmpty(void);
void PacketPoolDestroy(void);
void PacketPoolPostRunmodes(void);

#endif /* __TMQH_PACKETPOOL_H__ */
