#include <jansson.h>
#include "output-json.h"
#include "output.h"
#include "utils/util-mem.h"

#define DEFAULT_LOG_FILENAME "eve.json"
#define MODULE_NAME "OutputJSON"

static void OutputJsonDeInitCtx(OutputCtx *);

OutputInitResult OutputJsonInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };

    OutputJsonCtx *json_ctx = SCCalloc(1, sizeof(OutputJsonCtx));
    if (unlikely(json_ctx == NULL)) {
        SCLogDebug("could not create new OutputJsonCtx");
        return result;
    }

    json_ctx->file_ctx = LogFileNewCtx();
    if (unlikely(json_ctx->file_ctx == NULL)) {
        SCLogDebug("AlertJsonInitCtx: Could not create new LogFileCtx");
        SCFree(json_ctx);
        return result;
    }

    //TODO: sensor name is NULL
    json_ctx->file_ctx->sensor_name = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(json_ctx->file_ctx);
        SCFree(json_ctx);
        return result;
    }

    output_ctx->data = json_ctx;
    output_ctx->DeInit = OutputJsonDeInitCtx;

    if (conf) {
        const char *output_s = ConfNodeLookupChildValue(conf, "filetype");

        if (output_s != NULL) {
            if (strcmp(output_s, "file") == 0 ||
                strcmp(output_s, "regular") == 0) {
                json_ctx->json_out = LOGFILE_TYPE_FILE;
            } else {
                FatalError(SC_ERR_INVALID_ARGUMENT,
                        "Invalid JSON output option: %s", output_s);
            }
        }

        if (json_ctx->json_out == LOGFILE_TYPE_FILE)
        {
            if (json_ctx->json_out == LOGFILE_TYPE_FILE) {
                /* Threaded file output */
                const ConfNode *threaded = ConfNodeLookupChild(conf, "threaded");
                if (threaded && threaded->val && ConfValIsTrue(threaded->val)) {
                    SCLogConfig("Enabling threaded eve logging.");
                    json_ctx->file_ctx->threaded = true;
                } else {
                    json_ctx->file_ctx->threaded = false;
                }
            }

            if (SCConfLogOpenGeneric(conf, json_ctx->file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
                LogFileFreeCtx(json_ctx->file_ctx);
                SCFree(json_ctx);
                SCFree(output_ctx);
                return result;
            }
            OutputRegisterFileRotationFlag(&json_ctx->file_ctx->rotation_flag);
        }

        /* Check if top-level metadata should be logged. */
        const ConfNode *metadata = ConfNodeLookupChild(conf, "metadata");
        if (metadata && metadata->val && ConfValIsFalse(metadata->val)) {
            SCLogConfig("Disabling eve metadata logging.");
            json_ctx->cfg.include_metadata = false;
        } else {
            json_ctx->cfg.include_metadata = true;
        }

        /* Check if ethernet information should be logged. */
        const ConfNode *ethernet = ConfNodeLookupChild(conf, "ethernet");
        if (ethernet && ethernet->val && ConfValIsTrue(ethernet->val)) {
            SCLogConfig("Enabling Ethernet MAC address logging.");
            json_ctx->cfg.include_ethernet = true;
        } else {
            json_ctx->cfg.include_ethernet = false;
        }

        json_ctx->file_ctx->type = json_ctx->json_out;
    }

    SCLogDebug("returning output_ctx %p", output_ctx);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void OutputJsonDeInitCtx(OutputCtx *output_ctx)
{
    OutputJsonCtx *json_ctx = (OutputJsonCtx *)output_ctx->data;
    LogFileCtx *logfile_ctx = json_ctx->file_ctx;
    if (logfile_ctx->dropped) {
        SCLogWarning(SC_WARN_EVENT_DROPPED,
                     "%"PRIu64" events were dropped due to slow or "
                              "disconnected socket", logfile_ctx->dropped);
    }

    LogFileFreeCtx(logfile_ctx);
    SCFree(json_ctx);
    SCFree(output_ctx);
}

void CreateEveFlowId(json_t *js, const Flow *f)
{
    if (f == NULL) {
        return;
    }
    int64_t flow_id = FlowGetId(f);
    json_object_set_new(js, "flow_id", json_integer(flow_id));
    /*if (f->parent_id) {
        jb_set_uint(js, "parent_id", f->parent_id);
    }*/
}

void OutputJsonRegister (void)
{
    OutputRegisterModule(MODULE_NAME, "eve-log", OutputJsonInitCtx);
}
