#ifndef NET_THREAT_DETECT_DPI_MODULE_H
#define NET_THREAT_DETECT_DPI_MODULE_H
#include "apis.h"
#include "decode/decode.h"

// Thread data
typedef struct dpi_thread_data_ {
    Packet packet;//add by haolipeng for

    io_counter_t counter;//statistics per thread
} dpi_thread_data_t;

extern dpi_thread_data_t g_dpi_thread_data[];

#endif //NET_THREAT_DETECT_DPI_MODULE_H
