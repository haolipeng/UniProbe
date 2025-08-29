#ifndef NET_THREAT_DETECT_APP_LAYER_EVENTS_H
#define NET_THREAT_DETECT_APP_LAYER_EVENTS_H
#include <stdint.h>

typedef struct AppLayerDecoderEvents_ {
  /* array of events */
  uint8_t *events;
  /* number of events in the above buffer */
  uint8_t cnt;
  /* current event buffer size */
  uint8_t events_buffer_size;
  /* last logged */
  uint8_t event_last_logged;
}AppLayerDecoderEvents;

void AppLayerDecoderEventsResetEvents(AppLayerDecoderEvents *events);
void AppLayerDecoderEventsFreeEvents(AppLayerDecoderEvents **events);
#endif // NET_THREAT_DETECT_APP_LAYER_EVENTS_H
