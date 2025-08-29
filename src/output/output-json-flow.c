#include <jansson.h>

#include "output-json-flow.h"
#include "common/common.h"
#include "modules/tm-threads-common.h"
#include "modules/threadvars.h"
#include "output.h"
#include "output-json.h"
#include "utils/util-mem.h"
#include "utils/util-buffer.h"
#include "utils/util-time.h"
#include "utils/util-print.h"
#include "reassemble/stream-tcp-private.h"

typedef struct JsonBuilder JsonBuilder;

typedef struct LogJsonFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
    OutputJsonCommonSettings cfg;
} LogJsonFileCtx;

typedef struct JsonFlowLogThread_ {
    LogJsonFileCtx *flowlog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx *file_ctx;
    MemBuffer *buffer;
} JsonFlowLogThread;

static void OutputFlowLogDeinitSub(OutputCtx *output_ctx)
{
    LogJsonFileCtx *flow_ctx = output_ctx->data;
    SCFree(flow_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputFlowLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    LogJsonFileCtx *flow_ctx = SCMalloc(sizeof(LogJsonFileCtx));
    if (unlikely(flow_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(flow_ctx);
        return result;
    }

    flow_ctx->file_ctx = ojc->file_ctx;
    flow_ctx->cfg = ojc->cfg;

    output_ctx->data = flow_ctx;
    output_ctx->DeInit = OutputFlowLogDeinitSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonFlowLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonFlowLogThread *aft = SCCalloc(1, sizeof(JsonFlowLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogFlow.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /* Use the Outptut Context (file pointer and mutex) */
    aft->flowlog_ctx = ((OutputCtx *)initdata)->data; //TODO

    aft->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        goto error_exit;
    }

    aft->file_ctx = LogFileEnsureExists(aft->flowlog_ctx->file_ctx, t->id);
    if (!aft->file_ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

    error_exit:
    if (aft->buffer != NULL) {
        MemBufferFree(aft->buffer);
    }
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonFlowLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonFlowLogThread *aft = (JsonFlowLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(JsonFlowLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static json_t *CreateJSONHeaderFromFlow(const Flow *f)
{
    char timebuf[64];
    char srcip[46] = {0}, dstip[46] = {0};
    Port sp, dp;

    json_t *js = json_object();
    if (unlikely(js == NULL)) {
        return NULL;
    }

    struct timeval tv;
    memset(&tv, 0x00, sizeof(tv));
    TimeGet(&tv);

    CreateIsoTimeString(&tv, timebuf, sizeof(timebuf));

    if ((f->flags & FLOW_DIR_REVERSED) == 0) {
        if (FLOW_IS_IPV4(f)) {
            PrintInet(AF_INET, (const void *)&(f->src.addr_data32[0]), srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)&(f->dst.addr_data32[0]), dstip, sizeof(dstip));
        } else if (FLOW_IS_IPV6(f)) {
            PrintInet(AF_INET6, (const void *)&(f->src.address), srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)&(f->dst.address), dstip, sizeof(dstip));
        }
        sp = f->sp;
        dp = f->dp;
    } else {
        if (FLOW_IS_IPV4(f)) {
            PrintInet(AF_INET, (const void *)&(f->dst.addr_data32[0]), srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)&(f->src.addr_data32[0]), dstip, sizeof(dstip));
        } else if (FLOW_IS_IPV6(f)) {
            PrintInet(AF_INET6, (const void *)&(f->dst.address), srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)&(f->src.address), dstip, sizeof(dstip));
        }
        sp = f->dp;
        dp = f->sp;
    }

    /* time */
    json_object_set_new(js,"timestamp", json_string(timebuf));

    CreateEveFlowId(js, (const Flow *)f);

    /* input interface */
    if (f->livedev) {
        //json_object_set_new(js, "in_iface", f->livedev->dev);
    }

    json_object_set_new(js, "event_type", json_string("flow"));

    //TODO: not deal vlan json content
    /* vlan */
    /*if (f->vlan_idx > 0) {
        jb_open_array(jb, "vlan");
        jb_append_uint(jb, f->vlan_id[0]);
        if (f->vlan_idx > 1) {
            jb_append_uint(jb, f->vlan_id[1]);
        }
        jb_close(jb);
    }*/

    /* tuple */
    json_object_set_new(js, "src_ip", json_string(srcip));
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            json_object_set_new(js, "src_port", json_integer(sp));
            break;
    }
    json_object_set_new(js, "dest_ip", json_string(dstip));
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            json_object_set_new(js, "dest_port", json_integer(dp));
            break;
    }

    char proto[4];
    snprintf(proto, sizeof(proto), "%"PRIu8"", f->proto);
    json_object_set_new(js, "proto", json_string(proto));

    /*if (SCProtoNameValid(f->proto)) {
        json_object_set_new(js, "proto", known_proto[f->proto]);
    } else {
        char proto[4];
        snprintf(proto, sizeof(proto), "%"PRIu8"", f->proto);
        json_object_set_new(js, "proto", json_string(proto));
    }*/

    //TODO: not deal icmp protocol
    /*switch (f->proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            jb_set_uint(jb, "icmp_type", f->icmp_s.type);
            jb_set_uint(jb, "icmp_code", f->icmp_s.code);
            if (f->tosrcpktcnt) {
                jb_set_uint(jb, "response_icmp_type", f->icmp_d.type);
                jb_set_uint(jb, "response_icmp_code", f->icmp_d.code);
            }
            break;
    }*/
    return js;
}

static int JsonFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    JsonFlowLogThread *jhl = (JsonFlowLogThread *)thread_data;

    /* reset */
    MemBufferReset(jhl->buffer);

    json_t *js = CreateJSONHeaderFromFlow(f);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }



    return TM_ECODE_OK;
}

void JsonFlowLogRegister (void)
{
    /* register as child of eve-log */
    OutputRegisterFlowSubModule(LOGGER_JSON_FLOW, "eve-log", "JsonFlowLog",
                                "eve-log.flow", OutputFlowLogInitSub, JsonFlowLogger,
                                JsonFlowLogThreadInit, JsonFlowLogThreadDeinit, NULL);
}
