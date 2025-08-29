#include <stddef.h>
#include <malloc.h>
#include <string.h>

#include "decode-thread-var.h"
#include "utils/util-error.h"
#include "output/output-flow.h"

DecodeThreadVars *DecodeThreadVarsAlloc(ThreadVars *tv)
{
    DecodeThreadVars *dtv = NULL;

    if ( (dtv = malloc(sizeof(DecodeThreadVars))) == NULL)
        return NULL;
    memset(dtv, 0, sizeof(DecodeThreadVars));

    //TODO:modify by haolipeng
    //dtv->app_tctx = AppLayerGetCtxThread(tv);

    if (OutputFlowLogThreadInit(tv, NULL, &dtv->output_flow_thread_data) != TM_ECODE_OK) {
      SCLogError(SC_ERR_THREAD_INIT, "initializing flow log API for thread failed");
      DecodeThreadVarsFree(tv, dtv);
      return NULL;
    }

    return dtv;
}

void DecodeThreadVarsFree(ThreadVars *tv, DecodeThreadVars *dtv)
{
  if (dtv != NULL) {
    /*if (dtv->app_tctx != NULL)
      AppLayerDestroyCtxThread(dtv->app_tctx);
    */

    if (dtv->output_flow_thread_data != NULL){
        OutputFlowLogThreadDeinit(tv, dtv->output_flow_thread_data);
    }

    free(dtv);
  }
}