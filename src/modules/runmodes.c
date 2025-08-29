#include <stdio.h>
#include "runmodes.h"
#include "base.h"
#include "utils/util-debug.h"
#include "runmode-af-packet.h"
#include "utils/conf.h"
#include "flow/flow-manager.h"
#include "runmode-pcap-file.h"
#include "utils/util-mem.h"
#include "common/common.h"
#include "app-layer/app-layer-protos.h"
#include "output/output.h"

typedef struct RunMode_ {
    /* the runmode type */
    enum RunModes runmode;
    const char *name;
    const char *description;
    /* runmode function */
    int (*RunModeFunc)(void);
} RunMode;

typedef struct RunModes_ {
    int cnt;
    RunMode *runmodes;
} RunModes;

static RunModes runmodes[RUNMODE_USER_MAX];
static char *active_runmode;

static LoggerId logger_bits[ALPROTO_MAX];

/* free list for our outputs */
typedef struct OutputFreeList_ {
    OutputModule *output_module;
    OutputCtx *output_ctx;

    TAILQ_ENTRY(OutputFreeList_) entries;
} OutputFreeList;
static TAILQ_HEAD(, OutputFreeList_) output_free_list =
        TAILQ_HEAD_INITIALIZER(output_free_list);

void RunModeRegisterNewRunMode(enum RunModes runmode,
                               const char *name,
                               const char *description,
                               int (*RunModeFunc)(void))
{
    void *ptmp = realloc(runmodes[runmode].runmodes,
                           (runmodes[runmode].cnt + 1) * sizeof(RunMode));
    if (ptmp == NULL) {
        free(runmodes[runmode].runmodes);
        runmodes[runmode].runmodes = NULL;
        exit(EXIT_FAILURE);
    }
    runmodes[runmode].runmodes = ptmp;

    RunMode *mode = &runmodes[runmode].runmodes[runmodes[runmode].cnt];
    runmodes[runmode].cnt++;
    memset(mode, 0x00, sizeof(*mode));

    mode->runmode = runmode;
    mode->name = strdup(name);
    if (unlikely(mode->name == NULL)) {
        FatalError(SC_ERR_MEM_ALLOC, "Failed to allocate string");
    }
    mode->description = strdup(description);
    if (unlikely(mode->description == NULL)) {
        FatalError(SC_ERR_MEM_ALLOC, "Failed to allocate string");
    }
    mode->RunModeFunc = RunModeFunc;

    return;
}

void RunModeRegisterRunModes(void)
{
    memset(runmodes, 0, sizeof(runmodes));

    RunModeFilePcapRegister();
    RunModeIdsAFPRegister();
    return;
}

char *RunmodeGetActive(void)
{
    return active_runmode;
}

static RunMode *RunModeGetCustomMode(enum RunModes runmode, const char *custom_mode)
{
    if (runmode < RUNMODE_USER_MAX) {
        for (int i = 0; i < runmodes[runmode].cnt; i++) {
            if (strcmp(runmodes[runmode].runmodes[i].name, custom_mode) == 0)
                return &runmodes[runmode].runmodes[i];
        }
    }
    return NULL;
}

static const char *RunModeTranslateModeToName(int runmode)
{
    switch (runmode) {
        case RUNMODE_PCAP_DEV:
            return "PCAP_DEV";
        case RUNMODE_PCAP_FILE:
            return "PCAP_FILE";
        case RUNMODE_AFP_DEV:
            return "AF_PACKET_DEV";
        default:
            FatalError(SC_ERR_UNKNOWN_RUN_MODE, "Unknown runtime mode. Aborting");
    }
}

void RunModeDispatch(int runmode, const char *custom_mode)
{
    char *local_custom_mode = NULL;

    if (custom_mode == NULL) {
        const char *val = NULL;
        if (ConfGet("runmode", &val) != 1) {
            custom_mode = NULL;
        } else {
            custom_mode = val;
        }
    }

    if (custom_mode == NULL || strcmp(custom_mode, "auto") == 0) {
        switch (runmode) {
            case RUNMODE_PCAP_FILE:
                custom_mode = RunModeFilePcapGetDefaultMode();
                break;
            case RUNMODE_AFP_DEV:
                custom_mode = RunModeAFPGetDefaultMode();
                break;
            default:
                FatalError(SC_ERR_FATAL, "Unknown runtime mode. Aborting");
        }
    } else { /* if (custom_mode == NULL) */
        /* Add compability with old 'worker' name */
        if (!strcmp("worker", custom_mode)) {
            SCLogWarning(SC_ERR_RUNMODE, "'worker' mode have been renamed "
                                         "to 'workers', please modify your setup.");
            local_custom_mode = SCStrdup("workers");
            if (unlikely(local_custom_mode == NULL)) {
                FatalError(SC_ERR_FATAL, "Unable to dup custom mode");
            }
            custom_mode = local_custom_mode;
        }
    }

    RunMode *mode = RunModeGetCustomMode(runmode, custom_mode);
    if (mode == NULL) {
        SCLogError(SC_ERR_RUNMODE, "The custom type \"%s\" doesn't exist "
                                   "for this runmode type \"%s\".  Please use --list-runmodes to "
                                   "see available custom types for this runmode",
                   custom_mode, RunModeTranslateModeToName(runmode));
        exit(EXIT_FAILURE);
    }

    /* Export the custom mode */
    if (active_runmode) {
        SCFree(active_runmode);
    }
    active_runmode = SCStrdup(custom_mode);
    if (unlikely(active_runmode == NULL)) {
        FatalError(SC_ERR_FATAL, "Unable to dup active mode");
    }

    /*if (strcasecmp(active_runmode, "autofp") == 0) {
        TmqhFlowPrintAutofpHandler();
    }*/

    mode->RunModeFunc();

    if (local_custom_mode != NULL)
        SCFree(local_custom_mode);

    /* Check if the alloted queues have at least 1 reader and writer */
    //TmValidateQueueState();

    if (runmode != RUNMODE_UNIX_SOCKET) {
        /* spawn management threads */
        FlowManagerThreadSpawn();
        FlowRecyclerThreadSpawn();
    }
}

static void AddOutputToFreeList(OutputModule *module, OutputCtx *output_ctx)
{
    OutputFreeList *fl_output = SCCalloc(1, sizeof(OutputFreeList));
    if (unlikely(fl_output == NULL))
        return;
    fl_output->output_module = module;
    fl_output->output_ctx = output_ctx;
    TAILQ_INSERT_TAIL(&output_free_list, fl_output, entries);
}

static void SetupOutput(const char *name, OutputModule *module, OutputCtx *output_ctx)
{
    /* flow logger doesn't run in the packet path */
    if (module->FlowLogFunc) {
        OutputRegisterFlowLogger(module->name, module->FlowLogFunc,
                                 output_ctx, module->ThreadInit, module->ThreadDeinit,
                                 module->ThreadExitPrintStats);
        return;
    }
}

static void RunModeInitializeEveOutput(ConfNode *conf, OutputCtx *parent_ctx)
{
    ConfNode *types = ConfNodeLookupChild(conf, "types");
    SCLogDebug("types %p", types);
    if (types == NULL) {
        return;
    }

    ConfNode *type = NULL;
    TAILQ_FOREACH(type, &types->head, next) {
        SCLogConfig("enabling 'eve-log' module '%s'", type->val);

        int sub_count = 0;
        char subname[256];
        snprintf(subname, sizeof(subname), "eve-log.%s", type->val);

        ConfNode *sub_output_config = ConfNodeLookupChild(type, type->val);
        if (sub_output_config != NULL) {
            const char *enabled = ConfNodeLookupChildValue(
                    sub_output_config, "enabled");
            if (enabled != NULL && !ConfValIsTrue(enabled)) {
                continue;
            }
        }

        /* Now setup all registers logger of this name. */
        OutputModule *sub_module;
        TAILQ_FOREACH(sub_module, &output_modules, entries) {
            if (strcmp(subname, sub_module->conf_name) == 0) {
                sub_count++;

                if (sub_module->parent_name == NULL ||
                    strcmp(sub_module->parent_name, "eve-log") != 0) {
                    FatalError(SC_ERR_INVALID_ARGUMENT,
                               "bad parent for %s", subname);
                }
                if (sub_module->InitSubFunc == NULL) {
                    FatalError(SC_ERR_INVALID_ARGUMENT,
                               "bad sub-module for %s", subname);
                }

                /* pass on parent output_ctx */
                OutputInitResult result =
                        sub_module->InitSubFunc(sub_output_config, parent_ctx);
                if (!result.ok || result.ctx == NULL) {
                    continue;
                }

                AddOutputToFreeList(sub_module, result.ctx);
                SetupOutput(sub_module->name, sub_module,result.ctx);
            }
        }

        /* Error is no registered loggers with this name
         * were found .*/
        if (!sub_count) {
            FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                             "No output module named %s", subname);
            continue;
        }
    }
}

void RunModeInitializeOutputs(void)
{
    ConfNode *outputs = ConfGetNode("outputs");
    if (outputs == NULL) {
        /* No "outputs" section in the configuration. */
        return;
    }

    ConfNode *output, *output_config;
    const char *enabled;

    memset(&logger_bits, 0, sizeof(logger_bits));

    TAILQ_FOREACH(output, &outputs->head, next) {

        output_config = ConfNodeLookupChild(output, output->val);
        if (output_config == NULL) {
            /* Shouldn't happen. */
            FatalError(SC_ERR_INVALID_ARGUMENT,
                       "Failed to lookup configuration child node: %s", output->val);
        }

        enabled = ConfNodeLookupChildValue(output_config, "enabled");
        if (enabled == NULL || !ConfValIsTrue(enabled)) {
            continue;
        }

        if (strcmp(output->val, "dns-log") == 0) {
            SCLogWarning(SC_ERR_NOT_SUPPORTED,
                         "dns-log is not longer available as of Suricata 5.0");
            continue;
        }

        OutputModule *module;
        int count = 0;
        TAILQ_FOREACH(module, &output_modules, entries) {
            if (strcmp(module->conf_name, output->val) != 0) {
                continue;
            }

            count++;

            OutputCtx *output_ctx = NULL;
            if (module->InitFunc != NULL) {
                OutputInitResult r = module->InitFunc(output_config);
                if (!r.ok) {
                    FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                                     "output module \"%s\": setup failed", output->val);
                    continue;
                } else if (r.ctx == NULL) {
                    continue;
                }
                output_ctx = r.ctx;
            } else if (module->InitSubFunc != NULL) {
                SCLogInfo("skipping submodule");
                continue;
            }

            // TODO if module == parent, find it's children
            if (strcmp(output->val, "eve-log") == 0) {
                RunModeInitializeEveOutput(output_config, output_ctx);

                /* add 'eve-log' to free list as it's the owner of the
                 * main output ctx from which the sub-modules share the
                 * LogFileCtx */
                AddOutputToFreeList(module, output_ctx);
            } else {
                AddOutputToFreeList(module, output_ctx);
                SetupOutput(module->name, module, output_ctx);
            }
        }
        if (count == 0) {
            FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                             "No output module named %s", output->val);
            continue;
        }
    }

    //TODO:not register to the app-layer
    /* register the logger bits to the app-layer */

    OutputSetupActiveLoggers();
}