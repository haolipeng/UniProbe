#ifndef NET_THREAT_DETECT_UTIL_HASH_LOOKUP3_H
#define NET_THREAT_DETECT_UTIL_HASH_LOOKUP3_H
#include <stddef.h>
#include <stdint.h>

uint32_t hashword(const uint32_t *k,size_t length,uint32_t initval);

#endif // NET_THREAT_DETECT_UTIL_HASH_LOOKUP3_H
