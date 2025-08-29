#ifndef NET_THREAT_DETECT_OUTPUT_H
#define NET_THREAT_DETECT_OUTPUT_H

#include "modules/tm-modules.h"
#include "utils/conf.h"
#include "output-flow.h"

#define DEFAULT_LOG_MODE_APPEND     "yes"
#define DEFAULT_LOG_FILETYPE        "regular"

typedef struct OutputInitResult_ {
    OutputCtx *ctx;
    bool ok;
} OutputInitResult;

typedef OutputInitResult (*OutputInitFunc)(ConfNode *);
typedef OutputInitResult (*OutputInitSubFunc)(ConfNode *, OutputCtx *);
typedef TmEcode (*OutputLogFunc)(ThreadVars *, Packet *, void *);
typedef uint32_t (*OutputGetActiveCountFunc)(void);

typedef struct OutputModule_ {
    LoggerId logger_id;
    const char *name;
    const char *conf_name;
    const char *parent_name;
    OutputInitFunc InitFunc;
    OutputInitSubFunc InitSubFunc;

    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
    ThreadExitPrintStatsFunc ThreadExitPrintStats;

    FlowLogger FlowLogFunc;

    TAILQ_ENTRY(OutputModule_) entries;
} OutputModule;

typedef TAILQ_HEAD(OutputModuleList_, OutputModule_) OutputModuleList;
extern OutputModuleList output_modules;

TmEcode OutputLoggerThreadDeinit(ThreadVars *, void *);

void OutputSetupActiveLoggers(void);

void TmModuleLoggerRegister(void);

void OutputRegisterModule(const char *name, const char *conf_name, OutputInitFunc InitFunc);
void OutputRegisterFlowSubModule(LoggerId id, const char *parent_name,
                                 const char *name, const char *conf_name, OutputInitSubFunc InitFunc,
                                 FlowLogger FlowLogFunc, ThreadInitFunc ThreadInit,
                                 ThreadDeinitFunc ThreadDeinit,
                                 ThreadExitPrintStatsFunc ThreadExitPrintStats);

void OutputRegisterFileRotationFlag(int *flag);
void OutputUnregisterFileRotationFlag(int *flag);
#endif //NET_THREAT_DETECT_OUTPUT_H
