#ifndef NET_THREAT_DETECT_UTIL_BUFFER_H
#define NET_THREAT_DETECT_UTIL_BUFFER_H
#include <stdint.h>

typedef struct MemBuffer_ {
    uint8_t *buffer;
    uint32_t size;
    uint32_t offset;
} MemBuffer;

#define MemBufferReset(mem_buffer) do {                     \
        (mem_buffer)->buffer[0] = 0;                        \
        (mem_buffer)->offset = 0;                           \
    } while (0)

MemBuffer *MemBufferCreateNew(uint32_t size);
void MemBufferFree(MemBuffer *buffer);
#endif //NET_THREAT_DETECT_UTIL_BUFFER_H
