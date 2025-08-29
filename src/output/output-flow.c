#include "output-flow.h"
#include "utils/util-mem.h"


typedef struct OutputLoggerThreadStore_ {
    void *thread_data;
    struct OutputLoggerThreadStore_ *next;
} OutputLoggerThreadStore;

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputLoggerThreadData_ {
    OutputLoggerThreadStore *store;
} OutputLoggerThreadData;

typedef struct OutputFlowLogger_ {
    FlowLogger LogFunc;
    OutputCtx *output_ctx;
    struct OutputFlowLogger_ *next;
    const char *name;
    TmEcode (*ThreadInit)(ThreadVars *, const void *, void **);
    TmEcode (*ThreadDeinit)(ThreadVars *, void *);
    void (*ThreadExitPrintStats)(ThreadVars *, void *);
} OutputFlowLogger;

static OutputFlowLogger *list = NULL;

int OutputRegisterFlowLogger(const char *name, FlowLogger LogFunc,
                             OutputCtx *output_ctx, ThreadInitFunc ThreadInit,
                             ThreadDeinitFunc ThreadDeinit,
                             ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputFlowLogger *op = malloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->LogFunc = LogFunc;
    op->output_ctx = output_ctx;
    op->name = name;
    op->ThreadInit = ThreadInit;
    op->ThreadDeinit = ThreadDeinit;
    op->ThreadExitPrintStats = ThreadExitPrintStats;

    if (list == NULL)
        list = op;
    else {
        OutputFlowLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    SCLogDebug("OutputRegisterFlowLogger happy");
    return 0;
}

TmEcode OutputFlowLog(ThreadVars *tv, void *thread_data, Flow *f)
{
    DEBUG_VALIDATE_BUG_ON(thread_data == NULL);

    if (list == NULL)
        return TM_ECODE_OK;

    FlowSetEndFlags(f);

    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputFlowLogger *logger = list;
    OutputLoggerThreadStore *store = op_thread_data->store;

    DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
    DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    DEBUG_VALIDATE_BUG_ON(logger == NULL && store == NULL);

    logger = list;
    store = op_thread_data->store;
    while (logger && store) {
        DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);

        SCLogDebug("logger %p", logger);
        logger->LogFunc(tv, store->thread_data, f);

        logger = logger->next;
        store = store->next;

        DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
        DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    }

    return TM_ECODE_OK;
}

TmEcode OutputFlowLogThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    OutputLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

    SCLogDebug("OutputFlowLogThreadInit happy (*data %p)", *data);

    OutputFlowLogger *logger = list;
    while (logger) {
        if (logger->ThreadInit) {
            void *retptr = NULL;
            if (logger->ThreadInit(tv, (void *)logger->output_ctx, &retptr) == TM_ECODE_OK) {
                OutputLoggerThreadStore *ts = SCMalloc(sizeof(*ts));
/* todo */      BUG_ON(ts == NULL);
                memset(ts, 0x00, sizeof(*ts));

                /* store thread handle */
                ts->thread_data = retptr;

                if (td->store == NULL) {
                    td->store = ts;
                } else {
                    OutputLoggerThreadStore *tmp = td->store;
                    while (tmp->next != NULL)
                        tmp = tmp->next;
                    tmp->next = ts;
                }

                SCLogDebug("%s is now set up", logger->name);
            }
        }

        logger = logger->next;
    }

    return TM_ECODE_OK;
}

TmEcode OutputFlowLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    if (op_thread_data == NULL)
        return TM_ECODE_OK;

    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputFlowLogger *logger = list;

    while (logger && store) {
        if (logger->ThreadDeinit) {
            logger->ThreadDeinit(tv, store->thread_data);
        }

        OutputLoggerThreadStore *next_store = store->next;
        SCFree(store);
        store = next_store;
        logger = logger->next;
    }

    SCFree(op_thread_data);
    return TM_ECODE_OK;
}
