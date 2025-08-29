#ifndef NET_THREAT_DETECT_OUTPUT_FLOW_H
#define NET_THREAT_DETECT_OUTPUT_FLOW_H

#include "modules/threadvars.h"
#include "modules/tm-modules.h"

/** flow logger function pointer type */
typedef int (*FlowLogger)(ThreadVars *, void *thread_data, Flow *f);

int OutputRegisterFlowLogger(const char *name, FlowLogger LogFunc,
                             OutputCtx *output_ctx, ThreadInitFunc ThreadInit,
                             ThreadDeinitFunc ThreadDeinit,
                             ThreadExitPrintStatsFunc ThreadExitPrintStats);

//Output flow log
TmEcode OutputFlowLog(ThreadVars *tv, void *thread_data, Flow *f);
TmEcode OutputFlowLogThreadInit(ThreadVars *tv, void *initdata, void **data);
TmEcode OutputFlowLogThreadDeinit(ThreadVars *tv, void *thread_data);
#endif //NET_THREAT_DETECT_OUTPUT_FLOW_H
