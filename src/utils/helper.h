//
// Created by haolipeng on 2/6/23.
//

#ifndef NET_THREAT_DETECT_HELPER_H
#define NET_THREAT_DETECT_HELPER_H
#include <arpa/inet.h>
#include <syscall.h>

#define ARRAY_ENTRIES(array) sizeof(array) / sizeof(array[0])//数组个数
#define STRUCT_OF(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#define SCGetThreadIdLong(...) ({ \
   pid_t tmpthid; \
   tmpthid = syscall(SYS_gettid); \
   unsigned long _scgetthread_tid = (unsigned long)tmpthid; \
   _scgetthread_tid; \
})

typedef struct buf_ {
    uint8_t *ptr;
    uint32_t len;
    uint32_t seq;
} buf_t;

static inline uint64_t htonll(uint64_t value)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint32_t high_part = htonl((uint32_t)(value >> 32));
    uint32_t low_part = htonl((uint32_t)(value & 0xFFFFFFFFLL));
    return ((uint64_t)(low_part) << 32) | high_part;
#else
    return value;
#endif
}

static inline void mac_cpy(uint8_t *m1, uint8_t *m2)
{
    *(uint32_t *)m1 = *(uint32_t *)m2;
    *(uint16_t *)(m1 + 4) = *(uint16_t *)(m2 + 4);
}
#endif //NET_THREAT_DETECT_HELPER_H
