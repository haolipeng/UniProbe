#include <stddef.h>
#include <stdlib.h>
#include "app-layer-events.h"

void AppLayerDecoderEventsResetEvents(AppLayerDecoderEvents *events)
{
  if (events != NULL) {
    events->cnt = 0;
    events->event_last_logged = 0;
  }
}

void AppLayerDecoderEventsFreeEvents(AppLayerDecoderEvents **events)
{
  if (events && *events != NULL) {
    if ((*events)->events != NULL)
      free((*events)->events);
    free(*events);
    *events = NULL;
  }
}
