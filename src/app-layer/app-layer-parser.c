#include "app-layer-parser.h"

void AppLayerParserStateSetFlag(AppLayerParserState *pstate, uint8_t flag)
{
  pstate->flags |= flag;
  return ;
}
