#ifndef NET_THREAT_DETECT_APP_LAYER_PARSER_H
#define NET_THREAT_DETECT_APP_LAYER_PARSER_H
#include <stdint.h>
#include "app-layer-events.h"

/* Flags for AppLayerParserState. */
// flag available                               BIT_U8(0)
#define APP_LAYER_PARSER_NO_INSPECTION          BIT_U8(1)
#define APP_LAYER_PARSER_NO_REASSEMBLY          BIT_U8(2)
#define APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD  BIT_U8(3)
#define APP_LAYER_PARSER_BYPASS_READY           BIT_U8(4)
#define APP_LAYER_PARSER_EOF_TS                 BIT_U8(5)
#define APP_LAYER_PARSER_EOF_TC                 BIT_U8(6)

typedef struct AppLayerParserState_ {
  /* coccinelle: AppLayerParserState:flags:APP_LAYER_PARSER_ */
  uint8_t flags;

  /* Indicates the current transaction that is being inspected.
     * We have a var per direction. */
  uint64_t inspect_id[2];
  /* Indicates the current transaction being logged.  Unlike inspect_id,
     * we don't need a var per direction since we don't log a transaction
     * unless we have the entire transaction. */
  uint64_t log_id;

  uint64_t min_id;

  /* Used to store decoder events. */
  AppLayerDecoderEvents *decoder_events;
}AppLayerParserState;

void AppLayerParserStateSetFlag(AppLayerParserState *pstate, uint8_t flag);

#endif // NET_THREAT_DETECT_APP_LAYER_PARSER_H
