#ifndef NET_THREAT_DETECT_OUTPUT_JSON_H
#define NET_THREAT_DETECT_OUTPUT_JSON_H
#include <stdbool.h>
#include <stdint.h>
#include <jansson.h>

#include "utils/util-logopenfile.h"
#include "flow/flow.h"

/* Suggested output buffer size */
#define JSON_OUTPUT_BUFFER_SIZE 65535

typedef struct OutputJsonCommonSettings_ {
    bool include_metadata;
    bool include_ethernet;
} OutputJsonCommonSettings;

typedef struct OutputJsonCtx_ {
    LogFileCtx *file_ctx;
    enum LogFileType json_out;
    OutputJsonCommonSettings cfg;
} OutputJsonCtx;

void OutputJsonRegister (void);
void CreateEveFlowId(json_t *js, const Flow *f);
#endif //NET_THREAT_DETECT_OUTPUT_JSON_H
