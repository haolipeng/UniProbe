#include "tm-queuehandlers.h"
#include "tmqh-packetpool.h"

Tmqh tmqh_table[TMQH_SIZE];

void TmqhSetup (void)
{
  memset(&tmqh_table, 0, sizeof(tmqh_table));

  //TmqhSimpleRegister();
  TmqhPacketpoolRegister();
  //TmqhFlowRegister();
}

/** \brief Clean up registration time allocs */
void TmqhCleanup(void)
{
}

int TmqhNameToID(const char *name)
{
  for (int i = 0; i < TMQH_SIZE; i++) {
    if (tmqh_table[i].name != NULL) {
      if (strcmp(name, tmqh_table[i].name) == 0)
        return i;
    }
  }

  return -1;
}

Tmqh *TmqhGetQueueHandlerByName(const char *name)
{
  for (int i = 0; i < TMQH_SIZE; i++) {
    if (tmqh_table[i].name != NULL) {
      if (strcmp(name, tmqh_table[i].name) == 0)
        return &tmqh_table[i];
    }
  }

  return NULL;
}

Tmqh *TmqhGetQueueHandlerByID(const int id)
{
  if (id <= 0 || id >= TMQH_SIZE)
    return NULL;

  return &tmqh_table[id];
}