#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>

#include "tm-threads.h"
#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "utils/conf.h"
#include "tm-modules.h"
#include "tmqh-packetpool.h"
#include "dpi/main.h"
#include "utils/util-mem.h"


/* root of the threadvars list */
ThreadVars *tv_root[TVT_MAX] = { NULL };

/* lock to protect tv_root */
SCMutex tv_root_lock = SCMUTEX_INITIALIZER;

typedef struct Thread_ {
    ThreadVars *tv;     /**< threadvars structure */
    const char *name;
    int type;
    int in_use;         /**< bool to indicate this is in use */

    struct timeval pktts;   /**< current packet time of this thread
                             *   (offline mode) */
    uint32_t sys_sec_stamp; /**< timestamp in seconds of the real system
                             *   time when the pktts was last updated. */
} Thread;

typedef struct Threads_ {
    Thread *threads;
    size_t threads_size;
    int threads_cnt;
} Threads;

static Threads thread_store = { NULL, 0, 0 };
static SCMutex thread_store_lock = SCMUTEX_INITIALIZER;

int TmThreadsCheckFlag(ThreadVars *tv, uint32_t flag)
{
  return (SC_ATOMIC_GET(tv->flags) & flag) ? 1 : 0;
}

void TmThreadsSetFlag(ThreadVars *tv, uint32_t flag)
{
  SC_ATOMIC_OR(tv->flags, flag);
}

void TmThreadsUnsetFlag(ThreadVars *tv, uint32_t flag)
{
  SC_ATOMIC_AND(tv->flags, ~flag);
}

void TmThreadWaitForFlag(ThreadVars *tv, uint32_t flags)
{
    while (!TmThreadsCheckFlag(tv, flags)) {
        usleep(100);
    }

    return;
}

void TmThreadContinue(ThreadVars *tv)
{
    TmThreadsUnsetFlag(tv, THV_PAUSE);

    return;
}

/**
 * \brief Unpauses all threads present in tv_root
 */
void TmThreadContinueThreads(void)
{
    SCMutexLock(&tv_root_lock);
    for (int i = 0; i < TVT_MAX; i++) {
        ThreadVars *tv = tv_root[i];
        while (tv != NULL) {
            TmThreadContinue(tv);
            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);
    return;
}

void TmThreadTestThreadUnPaused(ThreadVars *tv)
{
  while (TmThreadsCheckFlag(tv, THV_PAUSE)) {
    usleep(100);

    if (TmThreadsCheckFlag(tv, THV_KILL))
      break;
  }

  return;
}

static void *TmThreadsManagement(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = (TmSlot *)tv->tm_slots;
    TmEcode r = TM_ECODE_OK;

    BUG_ON(s == NULL);

    /* Set the thread name */
    if (SCSetThreadName(tv->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

    SCLogDebug("%s starting", tv->name);

    if (s->SlotThreadInit != NULL) {
        void *slot_data = NULL;
        r = s->SlotThreadInit(tv, s->slot_initdata, &slot_data);
        if (r != TM_ECODE_OK) {
            TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
            pthread_exit((void *) -1);
            return NULL;
        }
        (void)SC_ATOMIC_SET(s->slot_data, slot_data);
    }

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    r = s->Management(tv, SC_ATOMIC_GET(s->slot_data));
    /* handle error */
    if (r == TM_ECODE_FAILED) {
        TmThreadsSetFlag(tv, THV_FAILED);
    }


    TmThreadsSetFlag(tv, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv, THV_DEINIT);

    if (s->SlotThreadDeinit != NULL) {
        r = s->SlotThreadDeinit(tv, SC_ATOMIC_GET(s->slot_data));
        if (r != TM_ECODE_OK) {
            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
            return NULL;
        }
    }

    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
    return NULL;
}

static void *TmThreadsSlotPktAcqLoop(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = tv->tm_slots;
    char run = 1;
    TmEcode r = TM_ECODE_OK;
    TmSlot *slot = NULL;

    /* Set the thread name */
    if (SCSetThreadName(tv->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

    PacketPoolInit();

    /* check if we are setup properly */
    if (s == NULL || s->PktAcqLoop == NULL || tv->tmqh_in == NULL || tv->tmqh_out == NULL) {
        SCLogError(SC_ERR_FATAL, "TmSlot or ThreadVars badly setup: s=%p,"
                                 " PktAcqLoop=%p, tmqh_in=%p,"
                                 " tmqh_out=%p",
                   s, s ? s->PktAcqLoop : NULL, tv->tmqh_in, tv->tmqh_out);
        TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
        pthread_exit((void *) -1);
        return NULL;
    }

    for (slot = s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadInit != NULL) {
            void *slot_data = NULL;
            r = slot->SlotThreadInit(tv, slot->slot_initdata, &slot_data);
            if (r != TM_ECODE_OK) {
                if (r == TM_ECODE_DONE) {
                    EngineDone();
                    TmThreadsSetFlag(tv, THV_CLOSED | THV_INIT_DONE | THV_RUNNING_DONE);
                    goto error;
                } else {
                    TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
                    goto error;
                }
            }
            (void)SC_ATOMIC_SET(slot->slot_data, slot_data);
        }

        /* if the flowworker module is the first, get the threads input queue */
        if (slot == (TmSlot *)tv->tm_slots && (slot->tm_id == TMM_FLOWWORKER)) {
            tv->stream_pq = tv->inq->pq;
            tv->tm_flowworker = slot;
            SCLogDebug("pre-stream packetqueue %p (inq)", tv->stream_pq);
            tv->flow_queue = FlowQueueNew();
            if (tv->flow_queue == NULL) {
                TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
                pthread_exit((void *) -1);
                return NULL;
            }
            /* setup a queue */
        } else if (slot->tm_id == TMM_FLOWWORKER) {
            tv->stream_pq_local = calloc(1, sizeof(PacketQueue));
            if (tv->stream_pq_local == NULL)
                FatalError(SC_ERR_MEM_ALLOC, "failed to alloc PacketQueue");
            SCMutexInit(&tv->stream_pq_local->mutex_q, NULL);
            tv->stream_pq = tv->stream_pq_local;
            tv->tm_flowworker = slot;
            SCLogDebug("pre-stream packetqueue %p (local)", tv->stream_pq);
            tv->flow_queue = FlowQueueNew();
            if (tv->flow_queue == NULL) {
                TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
                pthread_exit((void *) -1);
                return NULL;
            }
        }
    }

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    while(run) {
        if (TmThreadsCheckFlag(tv, THV_PAUSE)) {
            TmThreadsSetFlag(tv, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv);
            TmThreadsUnsetFlag(tv, THV_PAUSED);
        }

        r = s->PktAcqLoop(tv, SC_ATOMIC_GET(s->slot_data), s);

        if (r == TM_ECODE_FAILED) {
            TmThreadsSetFlag(tv, THV_FAILED);
            run = 0;
        }
        if (TmThreadsCheckFlag(tv, THV_KILL_PKTACQ) || suricata_ctl_flags) {
            run = 0;
        }
        if (r == TM_ECODE_DONE) {
            run = 0;
        }
    }

    TmThreadsSetFlag(tv, THV_FLOW_LOOP);

    /* process all pseudo packets the flow timeout may throw at us */
    TmThreadTimeoutLoop(tv, s);

    TmThreadsSetFlag(tv, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv, THV_DEINIT);

    PacketPoolDestroy();

    for (slot = s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadDeinit != NULL) {
            r = slot->SlotThreadDeinit(tv, SC_ATOMIC_GET(slot->slot_data));
            if (r != TM_ECODE_OK) {
                TmThreadsSetFlag(tv, THV_CLOSED);
                goto error;
            }
        }
    }

    tv->stream_pq = NULL;
    SCLogDebug("%s ending", tv->name);
    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
    return NULL;

error:
    tv->stream_pq = NULL;
    pthread_exit((void *) -1);
    return NULL;
}

static int TmThreadTimeoutLoop(ThreadVars *tv, TmSlot *s)
{
    TmSlot *fw_slot = tv->tm_flowworker;
    int r = TM_ECODE_OK;

    if (tv->stream_pq == NULL || fw_slot == NULL) {
        SCLogDebug("not running TmThreadTimeoutLoop %p/%p", tv->stream_pq, fw_slot);
        return r;
    }

    SCLogDebug("flow end loop starting");
    while (1) {
        SCMutexLock(&tv->stream_pq->mutex_q);
        uint32_t len = tv->stream_pq->len;
        SCMutexUnlock(&tv->stream_pq->mutex_q);
        if (len > 0) {
            while (len--) {
                SCMutexLock(&tv->stream_pq->mutex_q);
                Packet *p = PacketDequeue(tv->stream_pq);
                SCMutexUnlock(&tv->stream_pq->mutex_q);
                if (likely(p)) {
                    if ((r = TmThreadsSlotProcessPkt(tv, fw_slot, p) != TM_ECODE_OK)) {
                        if (r == TM_ECODE_FAILED)
                            break;
                    }
                }
            }
        } else {
            if (TmThreadsCheckFlag(tv, THV_KILL)) {
                break;
            }
            usleep(1);
        }
    }
    SCLogDebug("flow end loop complete");


    return r;
}

static TmEcode TmThreadSetSlots(ThreadVars *tv, const char *name, void *(*fn_p)(void *))
{
    if (name == NULL) {
        if (fn_p == NULL) {
            printf("Both slot name and function pointer can't be NULL inside "
                   "TmThreadSetSlots\n");
            goto error;
        } else {
            name = "custom";
        }
    }

    if (strcmp(name, "varslot") == 0) {
        //tv->tm_func = TmThreadsSlotVar;
    } else if (strcmp(name, "pktacqloop") == 0) {
        tv->tm_func = TmThreadsSlotPktAcqLoop;
    } else if (strcmp(name, "management") == 0) {
        tv->tm_func = TmThreadsManagement;
    } else if (strcmp(name, "command") == 0) {
        tv->tm_func = TmThreadsManagement;
    } else if (strcmp(name, "custom") == 0) {
        if (fn_p == NULL)
            goto error;
        tv->tm_func = fn_p;
    } else {
        printf("Error: Slot \"%s\" not supported\n", name);
        goto error;
    }

    return TM_ECODE_OK;

error:
    return TM_ECODE_FAILED;
}

ThreadVars *TmThreadCreate(const char *name, const char *inq_name, const char *inqh_name,
                           const char *outq_name, const char *outqh_name, const char *slots,
                           void * (*fn_p)(void *), int mucond)
{
    ThreadVars *tv = NULL;
    Tmq *tmq = NULL;
    Tmqh *tmqh = NULL;

    SCLogDebug("creating thread \"%s\"...", name);

    /* XXX create separate function for this: allocate a thread container */
    tv = malloc(sizeof(ThreadVars));
    if (unlikely(tv == NULL))
        goto error;
    memset(tv, 0, sizeof(ThreadVars));

    SC_ATOMIC_INIT(tv->flags);

    strlcpy(tv->name, name, sizeof(tv->name));

    /* default state for every newly created thread */
    TmThreadsSetFlag(tv, THV_PAUSE);
    TmThreadsSetFlag(tv, THV_USE);

    /* set the incoming queue */
    if (inq_name != NULL && strcmp(inq_name, "packetpool") != 0) {
        SCLogDebug("inq_name \"%s\"", inq_name);

        tmq = TmqGetQueueByName(inq_name);
        if (tmq == NULL) {
            tmq = TmqCreateQueue(inq_name);
            if (tmq == NULL)
                goto error;
        }
        SCLogDebug("tmq %p", tmq);

        tv->inq = tmq;
        tv->inq->reader_cnt++;
        SCLogDebug("tv->inq %p", tv->inq);
    }
    if (inqh_name != NULL) {
        SCLogDebug("inqh_name \"%s\"", inqh_name);

        int id = TmqhNameToID(inqh_name);
        if (id <= 0) {
            goto error;
        }
        tmqh = TmqhGetQueueHandlerByName(inqh_name);
        if (tmqh == NULL)
            goto error;

        tv->tmqh_in = tmqh->InHandler;
        tv->inq_id = (uint8_t)id;
        SCLogDebug("tv->tmqh_in %p", tv->tmqh_in);
    }

    /* set the outgoing queue */
    if (outqh_name != NULL) {
        SCLogDebug("outqh_name \"%s\"", outqh_name);

        int id = TmqhNameToID(outqh_name);
        if (id <= 0) {
            goto error;
        }

        tmqh = TmqhGetQueueHandlerByName(outqh_name);
        if (tmqh == NULL)
            goto error;

        tv->tmqh_out = tmqh->OutHandler;
        tv->outq_id = (uint8_t)id;

        if (outq_name != NULL && strcmp(outq_name, "packetpool") != 0) {
            SCLogDebug("outq_name \"%s\"", outq_name);

            if (tmqh->OutHandlerCtxSetup != NULL) {
                tv->outctx = tmqh->OutHandlerCtxSetup(outq_name);
                if (tv->outctx == NULL)
                    goto error;
                tv->outq = NULL;
            } else {
                tmq = TmqGetQueueByName(outq_name);
                if (tmq == NULL) {
                    tmq = TmqCreateQueue(outq_name);
                    if (tmq == NULL)
                        goto error;
                }
                SCLogDebug("tmq %p", tmq);

                tv->outq = tmq;
                tv->outctx = NULL;
                tv->outq->writer_cnt++;
            }
        }
    }

    if (TmThreadSetSlots(tv, slots, fn_p) != TM_ECODE_OK) {
        goto error;
    }

    return tv;

error:
    SCLogError(SC_ERR_THREAD_CREATE, "failed to setup a thread");

    if (tv != NULL)
        free(tv);
    return NULL;
}

ThreadVars *TmThreadCreatePacketHandler(const char *name, const char *inq_name,
                                        const char *inqh_name, const char *outq_name,
                                        const char *outqh_name, const char *slots)
{
  ThreadVars *tv = NULL;

  tv = TmThreadCreate(name, inq_name, inqh_name, outq_name, outqh_name,
                      slots, NULL, 0);

  if (tv != NULL) {
    tv->type = TVT_PPT;
    tv->id = TmThreadsRegisterThread(tv, tv->type);//not need
  }


  return tv;
}

ThreadVars *TmThreadCreateMgmtThreadByName(const char *name, const char *module,
                                           int mucond)
{
    ThreadVars *tv = NULL;

    tv = TmThreadCreate(name, NULL, NULL, NULL, NULL, "management", NULL, mucond);

    if (tv != NULL) {
        tv->type = TVT_MGMT;
        tv->id = TmThreadsRegisterThread(tv, tv->type);
        //TmThreadSetCPU(tv, MANAGEMENT_CPU_SET);

        TmModule *m = TmModuleGetByName(module);
        if (m) {
            TmSlotSetFuncAppend(tv, m, NULL);
        }
    }

    return tv;
}

void TmSlotSetFuncAppend(ThreadVars *tv, TmModule *tm, const void *data)
{
    TmSlot *slot = malloc(sizeof(TmSlot));
    if (unlikely(slot == NULL))
        return;
    memset(slot, 0, sizeof(TmSlot));
    SC_ATOMIC_INITPTR(slot->slot_data);
    slot->SlotThreadInit = tm->ThreadInit;
    slot->slot_initdata = data;
    if (tm->Func) {
        slot->SlotFunc = tm->Func;
    } else if (tm->PktAcqLoop) {
        slot->PktAcqLoop = tm->PktAcqLoop;
        if (tm->PktAcqBreakLoop) {
            tv->break_loop = true;
        }
    } else if (tm->Management) {
        slot->Management = tm->Management;
    }
    slot->SlotThreadDeinit = tm->ThreadDeinit;
    /* we don't have to check for the return value "-1".  We wouldn't have
     * received a TM as arg, if it didn't exist */
    slot->tm_id = TmModuleGetIDForTM(tm);

    tv->tmm_flags |= tm->flags;

    if (tv->tm_slots == NULL) {
        tv->tm_slots = slot;
    } else {
        TmSlot *a = (TmSlot *)tv->tm_slots, *b = NULL;

        /* get the last slot */
        for ( ; a != NULL; a = a->slot_next) {
            b = a;
        }
        /* append the new slot */
        if (b != NULL) {
            b->slot_next = slot;
        }
    }
    return;
}

void TmThreadAppend(ThreadVars *tv, int type)
{
    SCMutexLock(&tv_root_lock);

    if (tv_root[type] == NULL) {
        tv_root[type] = tv;
        tv->next = NULL;

        SCMutexUnlock(&tv_root_lock);

        return;
    }

    ThreadVars *t = tv_root[type];

    while (t) {
        if (t->next == NULL) {
            t->next = tv;
            tv->next = NULL;
            break;
        }

        t = t->next;
    }

    SCMutexUnlock(&tv_root_lock);

    return;
}

TmEcode TmThreadSpawn(ThreadVars *tv)
{
    pthread_attr_t attr;
    if (tv->tm_func == NULL) {
        FatalError(SC_ERR_TM_THREADS_ERROR, "No thread function set");
    }

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int rc = pthread_create(&tv->t, &attr, tv->tm_func, (void *)tv);
    if (rc) {
        FatalError(SC_ERR_THREAD_CREATE,
                   "Unable to create thread with pthread_create() is %" PRId32, rc);
    }

    TmThreadWaitForFlag(tv, THV_INIT_DONE | THV_RUNNING_DONE);
    TmThreadAppend(tv, tv->type);
    return TM_ECODE_OK;
}

TmEcode TmThreadsSlotVarRun(ThreadVars *tv, Packet *p, TmSlot *slot)
{
  for (TmSlot *s = slot; s != NULL; s = s->slot_next) {
    TmEcode r = s->SlotFunc(tv, p, SC_ATOMIC_GET(s->slot_data));

    /* handle error */
    if (unlikely(r == TM_ECODE_FAILED)) {
      /* Encountered error.  Return packets to packetpool and return */
      //TODO:modify by haolipeng
      //TmThreadsSlotProcessPktFail(tv, s, NULL);
      return TM_ECODE_FAILED;
    }

    /* handle new packets */
    /*while (tv->decode_pq.top != NULL) {
      Packet *extra_p = PacketDequeueNoLock(&tv->decode_pq);
      if (unlikely(extra_p == NULL))
        continue;

      *//* see if we need to process the packet *//*
      if (s->slot_next != NULL) {
        r = TmThreadsSlotVarRun(tv, extra_p, s->slot_next);
        if (unlikely(r == TM_ECODE_FAILED)) {
          TmThreadsSlotProcessPktFail(tv, s, extra_p);
          return TM_ECODE_FAILED;
        }
      }
      tv->tmqh_out(tv, extra_p);
    }*/
  }

  return TM_ECODE_OK;
}

TmEcode TmThreadsSlotProcessPkt(ThreadVars *tv, TmSlot *s, Packet *p)
{
  if (s == NULL) {
    tv->tmqh_out(tv, p);
    return TM_ECODE_OK;
  }

  TmEcode r = TmThreadsSlotVarRun(tv, p, s);
  if (unlikely(r == TM_ECODE_FAILED)) {
    //TmThreadsSlotProcessPktFail(tv, s, p);
    return TM_ECODE_FAILED;
  }

  tv->tmqh_out(tv, p);

  //TmThreadsHandleInjectedPackets(tv);

  return TM_ECODE_OK;
}

void TmThreadCheckThreadState(void)
{
    SCMutexLock(&tv_root_lock);
    for (int i = 0; i < TVT_MAX; i++) {
        ThreadVars *tv = tv_root[i];
        while (tv) {
            if (TmThreadsCheckFlag(tv, THV_FAILED)) {
                FatalError(SC_ERR_FATAL, "thread %s failed", tv->name);
            }
            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);
    return;
}

TmEcode TmThreadWaitOnThreadInit(void)
{
    uint16_t mgt_num = 0;
    uint16_t ppt_num = 0;

    struct timeval start_ts;
    struct timeval cur_ts;
    gettimeofday(&start_ts, NULL);

    again:
    SCMutexLock(&tv_root_lock);
    for (int i = 0; i < TVT_MAX; i++) {
        ThreadVars *tv = tv_root[i];
        while (tv != NULL) {
            if (TmThreadsCheckFlag(tv, (THV_CLOSED|THV_DEAD))) {
                SCMutexUnlock(&tv_root_lock);

                SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" failed to "
                                               "initialize: flags %04x", tv->name,
                           SC_ATOMIC_GET(tv->flags));
                return TM_ECODE_FAILED;
            }

            if (!(TmThreadsCheckFlag(tv, THV_INIT_DONE))) {
                SCMutexUnlock(&tv_root_lock);

                gettimeofday(&cur_ts, NULL);
                if ((cur_ts.tv_sec - start_ts.tv_sec) > 120) {
                    SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" failed to "
                                                   "initialize in time: flags %04x", tv->name,
                               SC_ATOMIC_GET(tv->flags));
                    return TM_ECODE_FAILED;
                }

                /* sleep a little to give the thread some
                 * time to finish initialization */
                usleep(100);
                goto again;
            }

            if (TmThreadsCheckFlag(tv, THV_FAILED)) {
                SCMutexUnlock(&tv_root_lock);
                SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" failed to "
                                               "initialize.", tv->name);
                return TM_ECODE_FAILED;
            }
            if (TmThreadsCheckFlag(tv, THV_CLOSED)) {
                SCMutexUnlock(&tv_root_lock);
                SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" closed on "
                                               "initialization.", tv->name);
                return TM_ECODE_FAILED;
            }

            if (i == TVT_MGMT)
                mgt_num++;
            else if (i == TVT_PPT)
                ppt_num++;

            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);

    SCLogNotice("all %"PRIu16" packet processing threads, %"PRIu16" management "
                                                                  "threads initialized, engine started.", ppt_num, mgt_num);

    return TM_ECODE_OK;
}

static inline void TmThreadsCleanDecodePQ(PacketQueueNoLock *pq)
{
    while (1) {
        Packet *p = PacketDequeueNoLock(pq);
        if (unlikely(p == NULL))
            break;
        TmqhOutputPacketpool(NULL, p);
    }
}

static inline void TmThreadsSlotProcessPktFail(ThreadVars *tv, TmSlot *s, Packet *p)
{
    if (p != NULL) {
        TmqhOutputPacketpool(tv, p);
    }
    TmThreadsCleanDecodePQ(&tv->decode_pq);
    if (tv->stream_pq_local) {
        SCMutexLock(&tv->stream_pq_local->mutex_q);
        TmqhReleasePacketsToPacketPool(tv->stream_pq_local);
        SCMutexUnlock(&tv->stream_pq_local->mutex_q);
    }
    TmThreadsSetFlag(tv, THV_FAILED);
}

static inline bool TmThreadsHandleInjectedPackets(ThreadVars *tv)
{
    PacketQueue *pq = tv->stream_pq_local;
    if (pq && pq->len > 0) {
        while (1) {
            SCMutexLock(&pq->mutex_q);
            Packet *extra_p = PacketDequeue(pq);
            SCMutexUnlock(&pq->mutex_q);
            if (extra_p == NULL)
                break;
            TmEcode r = TmThreadsSlotVarRun(tv, extra_p, tv->tm_flowworker);
            if (r == TM_ECODE_FAILED) {
                TmThreadsSlotProcessPktFail(tv, tv->tm_flowworker, extra_p);
                break;
            }
            tv->tmqh_out(tv, extra_p);
        }
        return true;
    } else {
        return false;
    }
}

static inline void TmThreadsCaptureInjectPacket(ThreadVars *tv, Packet *p)
{
    TmThreadsUnsetFlag(tv, THV_CAPTURE_INJECT_PKT);
    if (p == NULL)
        p = PacketGetFromQueueOrAlloc();
    if (p != NULL) {
        p->flags |= PKT_PSEUDO_STREAM_END;
        PKT_SET_SRC(p, PKT_SRC_CAPTURE_TIMEOUT);
        if (TmThreadsSlotProcessPkt(tv, tv->tm_flowworker, p) != TM_ECODE_OK) {
            TmqhOutputPacketpool(tv, p);
        }
    }
}

static inline void TmThreadsCaptureHandleTimeout(ThreadVars *tv, Packet *p)
{
    if (TmThreadsCheckFlag(tv, THV_CAPTURE_INJECT_PKT)) {
        TmThreadsCaptureInjectPacket(tv, p); /* consumes 'p' */
        return;

    } else {
        if (TmThreadsHandleInjectedPackets(tv) == false) {
            /* see if we have to do some house keeping */
            if (tv->flow_queue && SC_ATOMIC_GET(tv->flow_queue->non_empty) == true) {
                TmThreadsCaptureInjectPacket(tv, p); /* consumes 'p' */
                return;
            }
        }
    }

    /* packet could have been passed to us that we won't use
     * return it to the pool. */
    if (p != NULL)
        tv->tmqh_out(tv, p);
}

void TmThreadsSetThreadTimestamp(const int id, const struct timeval *ts)
{
    SCMutexLock(&thread_store_lock);
    if (unlikely(id <= 0 || id > (int)thread_store.threads_size)) {
        SCMutexUnlock(&thread_store_lock);
        return;
    }

    int idx = id - 1;
    Thread *t = &thread_store.threads[idx];
    t->pktts = *ts;
    struct timeval systs;
    gettimeofday(&systs, NULL);
    t->sys_sec_stamp = (uint32_t)systs.tv_sec;
    SCMutexUnlock(&thread_store_lock);
}

void TmThreadsInitThreadsTimestamp(const struct timeval *ts)
{
    struct timeval systs;
    gettimeofday(&systs, NULL);
    SCMutexLock(&thread_store_lock);
    for (size_t s = 0; s < thread_store.threads_size; s++) {
        Thread *t = &thread_store.threads[s];
        if (!t->in_use)
            break;
        t->pktts = *ts;
        t->sys_sec_stamp = (uint32_t)systs.tv_sec;
    }
    SCMutexUnlock(&thread_store_lock);
}

#define STEP 32
/**
 *  \retval id thread id, or 0 if not found
 */
int TmThreadsRegisterThread(ThreadVars *tv, const int type)
{
    SCMutexLock(&thread_store_lock);
    if (thread_store.threads == NULL) {
        thread_store.threads = SCCalloc(STEP, sizeof(Thread));
        BUG_ON(thread_store.threads == NULL);
        thread_store.threads_size = STEP;
    }

    size_t s;
    for (s = 0; s < thread_store.threads_size; s++) {
        if (thread_store.threads[s].in_use == 0) {
            Thread *t = &thread_store.threads[s];
            t->name = tv->name;
            t->type = type;
            t->tv = tv;
            t->in_use = 1;

            SCMutexUnlock(&thread_store_lock);
            return (int)(s+1);
        }
    }

    /* if we get here the array is completely filled */
    void *newmem = SCRealloc(thread_store.threads, ((thread_store.threads_size + STEP) * sizeof(Thread)));
    BUG_ON(newmem == NULL);
    thread_store.threads = newmem;
    memset((uint8_t *)thread_store.threads + (thread_store.threads_size * sizeof(Thread)), 0x00, STEP * sizeof(Thread));

    Thread *t = &thread_store.threads[thread_store.threads_size];
    t->name = tv->name;
    t->type = type;
    t->tv = tv;
    t->in_use = 1;

    s = thread_store.threads_size;
    thread_store.threads_size += STEP;

    SCMutexUnlock(&thread_store_lock);
    return (int)(s+1);
}
#undef STEP

uint32_t TmThreadCountThreadsByTmmFlags(uint8_t flags)
{
    uint32_t cnt = 0;
    SCMutexLock(&tv_root_lock);
    for (int i = 0; i < TVT_MAX; i++) {
        ThreadVars *tv = tv_root[i];
        while (tv != NULL) {
            if ((tv->tmm_flags & flags) == flags)
                cnt++;

            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);
    return cnt;
}

bool TmThreadsTimeSubsysIsReady(void)
{
    bool ready = true;
    SCMutexLock(&thread_store_lock);
    for (size_t s = 0; s < thread_store.threads_size; s++) {
        Thread *t = &thread_store.threads[s];
        if (!t->in_use)
            break;
        if (t->sys_sec_stamp == 0) {
            ready = false;
            break;
        }
    }
    SCMutexUnlock(&thread_store_lock);
    return ready;
}