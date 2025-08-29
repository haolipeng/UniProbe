#include "tm-queues.h"

static TAILQ_HEAD(TmqList_, Tmq_) tmq_list = TAILQ_HEAD_INITIALIZER(tmq_list);

static uint16_t tmq_id = 0;

Tmq *TmqCreateQueue(const char *name)
{
  Tmq *q = calloc(1, sizeof(*q));
  if (q == NULL)
    FatalError(SC_ERR_MEM_ALLOC, "SCCalloc failed");

  q->name = strdup(name);
  if (q->name == NULL)
    FatalError(SC_ERR_MEM_ALLOC, "SCStrdup failed");

  q->id = tmq_id++;
  q->is_packet_pool = (strcmp(q->name, "packetpool") == 0);
  if (!q->is_packet_pool) {
    q->pq = PacketQueueAlloc();
    if (q->pq == NULL)
      FatalError(SC_ERR_MEM_ALLOC, "PacketQueueAlloc failed");
  }

  TAILQ_INSERT_HEAD(&tmq_list, q, next);

  SCLogDebug("created queue \'%s\', %p", name, q);
  return q;
}

Tmq *TmqGetQueueByName(const char *name)
{
  Tmq *tmq = NULL;
  TAILQ_FOREACH(tmq, &tmq_list, next) {
    if (strcmp(tmq->name, name) == 0)
      return tmq;
  }
  return NULL;
}