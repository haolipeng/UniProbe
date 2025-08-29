#ifndef NET_THREAT_DETECT_TM_THREADS_H
#define NET_THREAT_DETECT_TM_THREADS_H

#include "utils/util-atomic.h"
#include "threadvars.h"
#include "tm-threads-common.h"

#define TM_QUEUE_NAME_MAX 16
#define TM_THREAD_NAME_MAX 16

typedef TmEcode (*TmSlotFunc)(ThreadVars *, Packet *, void *);

typedef struct TmSlot_ {
    /* function pointers */
    union {
        TmSlotFunc SlotFunc;
        TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *);
        TmEcode (*Management)(ThreadVars *, void *);
    };
    /** linked list of slots, used when a pipeline has multiple slots
     *  in a single thread. */
    struct TmSlot_ *slot_next;

    SC_ATOMIC_DECLARE(void *, slot_data);

    TmEcode (*SlotThreadInit)(ThreadVars *, const void *, void **);
    TmEcode (*SlotThreadDeinit)(ThreadVars *, void *);

    /* data storage */
    const void *slot_initdata;
    /* store the thread module id */
    int tm_id;

} TmSlot;

enum {
  TVT_PPT,
  TVT_MGMT,
  TVT_CMD,
  TVT_MAX,
};

extern ThreadVars *tv_root[TVT_MAX];
extern SCMutex tv_root_lock;

int TmThreadsCheckFlag(ThreadVars *, uint32_t);
void TmThreadsSetFlag(ThreadVars *tv, uint32_t flag);
void TmThreadTestThreadUnPaused(ThreadVars *tv);
void TmThreadsUnsetFlag(ThreadVars *, uint32_t);
void TmThreadWaitForFlag(ThreadVars *, uint32_t);
void TmThreadContinue(ThreadVars *tv);
void TmThreadContinueThreads(void);
void TmThreadCheckThreadState(void);
static int TmThreadTimeoutLoop(ThreadVars *tv, TmSlot *s);
uint32_t TmThreadCountThreadsByTmmFlags(uint8_t flags);
bool TmThreadsTimeSubsysIsReady(void);

void TmThreadsInitThreadsTimestamp(const struct timeval *ts);
void TmThreadsSetThreadTimestamp(const int id, const struct timeval *ts);
int TmThreadsRegisterThread(ThreadVars *tv, const int type);
ThreadVars *TmThreadCreate(const char *name, const char *inq_name, const char *inqh_name,
                           const char *outq_name, const char *outqh_name, const char *slots,
                           void * (*fn_p)(void *), int mucond);
ThreadVars *TmThreadCreatePacketHandler(const char *, const char *, const char *, const char *, const char *,
                                        const char *);
ThreadVars *TmThreadCreateMgmtThreadByName(const char *name, const char *module,
                                           int mucond);

void TmThreadAppend(ThreadVars *tv, int type);

typedef struct TmModule_ TmModule;
void TmSlotSetFuncAppend(ThreadVars *tv, TmModule *tm, const void *data);
TmEcode TmThreadSpawn(ThreadVars *tv);
TmEcode TmThreadsSlotVarRun (ThreadVars *tv, Packet *p, TmSlot *slot);
TmEcode TmThreadsSlotProcessPkt(ThreadVars *tv, TmSlot *s, Packet *p);
TmEcode TmThreadWaitOnThreadInit(void);


#endif // NET_THREAT_DETECT_TM_THREADS_H
