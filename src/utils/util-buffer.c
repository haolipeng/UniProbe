#include <stddef.h>
#include <string.h>
#include "util-buffer.h"
#include "util-mem.h"
#include "util-debug.h"
#include "base.h"

#define MAX_LIMIT 10485760

MemBuffer *MemBufferCreateNew(uint32_t size)
{
    if (size > MAX_LIMIT) {
        SCLogWarning(SC_ERR_MEM_BUFFER_API, "Mem buffer asked to create "
                                            "buffer with size greater than API limit - %d", MAX_LIMIT);
        return NULL;
    }

    uint32_t total_size = size + sizeof(MemBuffer);

    MemBuffer *buffer = SCMalloc(total_size);
    if (unlikely(buffer == NULL)) {
        return NULL;
    }
    memset(buffer, 0, total_size);

    buffer->size = size;
    buffer->buffer = (uint8_t *)buffer + sizeof(MemBuffer);

    return buffer;
}

void MemBufferFree(MemBuffer *buffer)
{
    SCFree(buffer);

    return;
}
