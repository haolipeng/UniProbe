#ifndef __TM_QUEUES_H__
#define __TM_QUEUES_H__

#include "utils/queue.h"
#include "utils/packet-queue.h"

typedef struct Tmq_ {
  char *name;
  bool is_packet_pool;
  uint16_t id;
  uint16_t reader_cnt;
  uint16_t writer_cnt;
  PacketQueue *pq;
  TAILQ_ENTRY(Tmq_) next;
} Tmq;

Tmq* TmqCreateQueue(const char *name);
Tmq* TmqGetQueueByName(const char *name);

#endif /* __TM_QUEUES_H__ */

