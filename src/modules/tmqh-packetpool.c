#include "utils/packet-queue.h"
#include "reassemble/stream-tcp-reassemble.h"
#include "tmqh-packetpool.h"
#include "utils/util-optimize.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"

/* Number of freed packet to save for one pool before freeing them. */
#define MAX_PENDING_RETURN_PACKETS 32
static uint32_t max_pending_return_packets = MAX_PENDING_RETURN_PACKETS;

thread_local PktPool thread_pkt_pool;
extern intmax_t max_pending_packets;

static inline PktPool *GetThreadPacketPool(void)
{
    return &thread_pkt_pool;
}

void TmqhPacketpoolRegister (void)
{
    tmqh_table[TMQH_PACKETPOOL].name = "packetpool";
    tmqh_table[TMQH_PACKETPOOL].InHandler = TmqhInputPacketpool;
    tmqh_table[TMQH_PACKETPOOL].OutHandler = TmqhOutputPacketpool;
}

static int PacketPoolIsEmpty(PktPool *pool)
{
    /* Check local stack first. */
    if (pool->head || pool->return_stack.head)
        return 0;

    return 1;
}

void PacketPoolWait(void)
{
    PktPool *my_pool = GetThreadPacketPool();

    if (PacketPoolIsEmpty(my_pool)) {
        SCMutexLock(&my_pool->return_stack.mutex);
        SC_ATOMIC_ADD(my_pool->return_stack.sync_now, 1);
        SCCondWait(&my_pool->return_stack.cond, &my_pool->return_stack.mutex);
        SCMutexUnlock(&my_pool->return_stack.mutex);
    }

    while(PacketPoolIsEmpty(my_pool))
        cc_barrier();
}

void PacketPoolWaitForN(int n)
{
    PktPool *my_pool = GetThreadPacketPool();
    Packet *p, *pp;

    while (1) {
        PacketPoolWait();

        /* count packets in our stack */
        int i = 0;
        pp = p = my_pool->head;
        while (p != NULL) {
            if (++i == n)
                return;

            pp = p;
            p = p->next;
        }

        /* check return stack, return to our pool and retry counting */
        if (my_pool->return_stack.head != NULL) {
            SCMutexLock(&my_pool->return_stack.mutex);
            /* Move all the packets from the locked return stack to the local stack. */
            if (pp) {
                pp->next = my_pool->return_stack.head;
            } else {
                my_pool->head = my_pool->return_stack.head;
            }
            my_pool->return_stack.head = NULL;
            SC_ATOMIC_RESET(my_pool->return_stack.sync_now);
            SCMutexUnlock(&my_pool->return_stack.mutex);

        /* or signal that we need packets and wait */
        } else {
            SCMutexLock(&my_pool->return_stack.mutex);
            SC_ATOMIC_ADD(my_pool->return_stack.sync_now, 1);
            SCCondWait(&my_pool->return_stack.cond, &my_pool->return_stack.mutex);
            SCMutexUnlock(&my_pool->return_stack.mutex);
        }
    }
}

/** \brief a initialized packet
 *
 *  \warning Use *only* at init, not at packet runtime
 */
static void PacketPoolStorePacket(Packet *p)
{
    /* Clear the PKT_ALLOC flag, since that indicates to push back
     * onto the ring buffer. */
    p->flags &= ~PKT_ALLOC;
    p->pool = GetThreadPacketPool();
    p->ReleasePacket = PacketPoolReturnPacket;
    PacketPoolReturnPacket(p);
}

static void PacketPoolGetReturnedPackets(PktPool *pool)
{
    SCMutexLock(&pool->return_stack.mutex);
    /* Move all the packets from the locked return stack to the local stack. */
    pool->head = pool->return_stack.head;
    pool->return_stack.head = NULL;
    SCMutexUnlock(&pool->return_stack.mutex);
}

/** \brief Get a new packet from the packet pool
 *
 * Only allocates from the thread's local stack, or mallocs new packets.
 * If the local stack is empty, first move all the return stack packets to
 * the local stack.
 *  \retval Packet pointer, or NULL on failure.
 */
Packet *PacketPoolGetPacket(void)
{
    PktPool *pool = GetThreadPacketPool();
#ifdef DEBUG_VALIDATION
    BUG_ON(pool->initialized == 0);
    BUG_ON(pool->destroyed == 1);
#endif /* DEBUG_VALIDATION */
    if (pool->head) {
        /* Stack is not empty. */
        Packet *p = pool->head;
        pool->head = p->next;
        p->pool = pool;
        PACKET_REINIT(p);
        return p;
    }

    /* Local Stack is empty, so check the return stack, which requires
     * locking. */
    PacketPoolGetReturnedPackets(pool);

    /* Try to allocate again. Need to check for not empty again, since the
     * return stack might have been empty too.
     */
    if (pool->head) {
        /* Stack is not empty. */
        Packet *p = pool->head;
        pool->head = p->next;
        p->pool = pool;
        PACKET_REINIT(p);
        return p;
    }

    /* Failed to allocate a packet, so return NULL. */
    /* Optionally, could allocate a new packet here. */
    return NULL;
}

/** \brief Return packet to Packet pool
 *
 */
void PacketPoolReturnPacket(Packet *p)
{
    PktPool *my_pool = GetThreadPacketPool();
    PktPool *pool = p->pool;
    if (pool == NULL) {
        PacketFree(p);
        return;
    }

    PACKET_RELEASE_REFS(p);

#ifdef DEBUG_VALIDATION
    BUG_ON(pool->initialized == 0);
    BUG_ON(pool->destroyed == 1);
    BUG_ON(my_pool->initialized == 0);
    BUG_ON(my_pool->destroyed == 1);
#endif /* DEBUG_VALIDATION */

    if (pool == my_pool) {
        /* Push back onto this thread's own stack, so no locking. */
        p->next = my_pool->head;
        my_pool->head = p;
    } else {
        PktPool *pending_pool = my_pool->pending_pool;
        if (pending_pool == NULL) {
            /* No pending packet, so store the current packet. */
            p->next = NULL;
            my_pool->pending_pool = pool;
            my_pool->pending_head = p;
            my_pool->pending_tail = p;
            my_pool->pending_count = 1;
        } else if (pending_pool == pool) {
            /* Another packet for the pending pool list. */
            p->next = my_pool->pending_head;
            my_pool->pending_head = p;
            my_pool->pending_count++;
            if (SC_ATOMIC_GET(pool->return_stack.sync_now) || my_pool->pending_count > max_pending_return_packets) {
                /* Return the entire list of pending packets. */
                SCMutexLock(&pool->return_stack.mutex);
                my_pool->pending_tail->next = pool->return_stack.head;
                pool->return_stack.head = my_pool->pending_head;
                SC_ATOMIC_RESET(pool->return_stack.sync_now);
                SCMutexUnlock(&pool->return_stack.mutex);
                SCCondSignal(&pool->return_stack.cond);
                /* Clear the list of pending packets to return. */
                my_pool->pending_pool = NULL;
                my_pool->pending_head = NULL;
                my_pool->pending_tail = NULL;
                my_pool->pending_count = 0;
            }
        } else {
            /* Push onto return stack for this pool */
            SCMutexLock(&pool->return_stack.mutex);
            p->next = pool->return_stack.head;
            pool->return_stack.head = p;
            SC_ATOMIC_RESET(pool->return_stack.sync_now);
            SCMutexUnlock(&pool->return_stack.mutex);
            SCCondSignal(&pool->return_stack.cond);
        }
    }
}

void PacketPoolInitEmpty(void)
{
    PktPool *my_pool = GetThreadPacketPool();

#ifdef DEBUG_VALIDATION
    BUG_ON(my_pool->initialized);
    my_pool->initialized = 1;
    my_pool->destroyed = 0;
#endif /* DEBUG_VALIDATION */

    SCMutexInit(&my_pool->return_stack.mutex, NULL);
    SCCondInit(&my_pool->return_stack.cond, NULL);
    SC_ATOMIC_INIT(my_pool->return_stack.sync_now);
}

void PacketPoolInit(void)
{
    extern intmax_t max_pending_packets;
    PktPool *my_pool = GetThreadPacketPool();

#ifdef DEBUG_VALIDATION
    BUG_ON(my_pool->initialized);
    my_pool->initialized = 1;
    my_pool->destroyed = 0;
#endif /* DEBUG_VALIDATION */

    SCMutexInit(&my_pool->return_stack.mutex, NULL);
    SCCondInit(&my_pool->return_stack.cond, NULL);
    SC_ATOMIC_INIT(my_pool->return_stack.sync_now);

    /* pre allocate packets */
    SCLogDebug("preallocating packets... packet size %" PRIuMAX "",
               (uintmax_t)SIZE_OF_PACKET);
    int i = 0;
    for (i = 0; i < max_pending_packets; i++) {
        Packet *p = PacketGetFromAlloc();
        if (unlikely(p == NULL)) {
            FatalError(SC_ERR_FATAL,
                       "Fatal error encountered while allocating a packet. Exiting...");
        }
        PacketPoolStorePacket(p);
    }

    SCLogInfo("preallocated %"PRIiMAX" packets. Total memory %"PRIuMAX"",
            max_pending_packets, (uintmax_t)(max_pending_packets*SIZE_OF_PACKET));
}

void PacketPoolDestroy(void)
{
    Packet *p = NULL;
    PktPool *my_pool = GetThreadPacketPool();

#ifdef DEBUG_VALIDATION
    BUG_ON(my_pool->destroyed);
#endif /* DEBUG_VALIDATION */

    if (my_pool && my_pool->pending_pool != NULL) {
        p = my_pool->pending_head;
        while (p) {
            Packet *next_p = p->next;
            PacketFree(p);
            p = next_p;
            my_pool->pending_count--;
        }
#ifdef DEBUG_VALIDATION
        BUG_ON(my_pool->pending_count);
#endif /* DEBUG_VALIDATION */
        my_pool->pending_pool = NULL;
        my_pool->pending_head = NULL;
        my_pool->pending_tail = NULL;
    }

    while ((p = PacketPoolGetPacket()) != NULL) {
        PacketFree(p);
    }

#ifdef DEBUG_VALIDATION
    my_pool->initialized = 0;
    my_pool->destroyed = 1;
#endif /* DEBUG_VALIDATION */
}

Packet *TmqhInputPacketpool(ThreadVars *tv)
{
    return PacketPoolGetPacket();
}

void TmqhOutputPacketpool(ThreadVars *t, Packet *p)
{
    PACKET_RELEASE_REFS(p);
    p->ReleasePacket(p);

    return;
}

/**
 *  \brief Release all the packets in the queue back to the packetpool.  Mainly
 *         used by threads that have failed, and wants to return the packets back
 *         to the packetpool.
 *
 *  \param pq Pointer to the packetqueue from which the packets have to be
 *            returned back to the packetpool
 *
 *  \warning this function assumes that the pq does not use locking
 */
void TmqhReleasePacketsToPacketPool(PacketQueue *pq)
{
    Packet *p = NULL;

    if (pq == NULL)
        return;

    while ( (p = PacketDequeue(pq)) != NULL)
        TmqhOutputPacketpool(NULL, p);

    return;
}

/** number of packets to keep reserved when calculating the the pending
 *  return packets count. This assumes we need at max 10 packets in one
 *  PacketPoolWaitForN call. The actual number is 9 now, so this has a
 *  bit of margin. */
#define RESERVED_PACKETS 10

/**
 *  \brief Set the max_pending_return_packets value
 *
 *  Set it to the max pending packets value, devided by the number
 *  of lister threads. Normally, in autofp these are the stream/detect/log
 *  worker threads.
 *
 *  The max_pending_return_packets value needs to stay below the packet
 *  pool size of the 'producers' (normally pkt capture threads but also
 *  flow timeout injection ) to avoid a deadlock where all the 'workers'
 *  keep packets in their return pools, while the capture thread can't
 *  continue because its pool is empty.
 */
void PacketPoolPostRunmodes(void)
{
    extern intmax_t max_pending_packets;
    intmax_t pending_packets = max_pending_packets;
    if (pending_packets < RESERVED_PACKETS) {
        FatalError(SC_ERR_INVALID_ARGUMENT, "'max-pending-packets' setting "
                "must be at least %d", RESERVED_PACKETS);
    }

    uint32_t threads = TmThreadCountThreadsByTmmFlags(TM_FLAG_DETECT_TM);
    if (threads == 0)
        return;

    uint32_t packets = (pending_packets / threads) - 1;
    if (packets < max_pending_return_packets)
        max_pending_return_packets = packets;

    /* make sure to have a margin in the return logic */
    if (max_pending_return_packets >= RESERVED_PACKETS)
        max_pending_return_packets -= RESERVED_PACKETS;

    SCLogDebug("detect threads %u, max packets %u, max_pending_return_packets %u",
            threads, packets, max_pending_return_packets);
}
