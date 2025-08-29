#include <stdlib.h>
#include <pthread.h>
#include "packet-queue.h"

static inline void PacketEnqueueDo(PacketQueue *q, Packet *p)
{
    //PacketQueueValidateDebug(q);

    if (p == NULL)
        return;

    /* more packets in queue */
    if (q->top != NULL) {
        p->prev = NULL;
        p->next = q->top;
        q->top->prev = p;
        q->top = p;
        /* only packet */
    } else {
        p->prev = NULL;
        p->next = NULL;
        q->top = p;
        q->bot = p;
    }
    q->len++;
    //PacketQueueValidateDebug(q);
}

void PacketEnqueueNoLock(PacketQueueNoLock *qnl, Packet *p)
{
    PacketQueue *q = (PacketQueue *)qnl;
    PacketEnqueueDo(q, p);
}

void PacketEnqueue (PacketQueue *q, Packet *p)
{
    PacketEnqueueDo(q, p);
}

static inline Packet *PacketDequeueDo (PacketQueue *q)
{
    //PacketQueueValidateDebug(q);
    /* if the queue is empty there are no packets left. */
    if (q->len == 0) {
        return NULL;
    }
    q->len--;

    /* pull the bottom packet from the queue */
    Packet *p = q->bot;

    /* more packets in queue */
    if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;
        /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

    //PacketQueueValidateDebug(q);
    p->next = NULL;
    p->prev = NULL;
    return p;
}

Packet *PacketDequeueNoLock (PacketQueueNoLock *qnl)
{
    PacketQueue *q = (PacketQueue *)qnl;
    return PacketDequeueDo(q);
}

Packet *PacketDequeue (PacketQueue *q)
{
    return PacketDequeueDo(q);
}

PacketQueue *PacketQueueAlloc(void)
{
    PacketQueue *pq = calloc(1, sizeof(*pq));
    if (pq == NULL)
        return NULL;
    pthread_mutex_init(&pq->mutex_q, NULL);
    pthread_cond_init(&pq->cond_q, NULL);
    return pq;
}

void PacketQueueFree(PacketQueue *pq)
{
    pthread_cond_destroy(&pq->cond_q);
    pthread_mutex_destroy(&pq->mutex_q);
    free(pq);
}
