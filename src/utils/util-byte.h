#ifndef NET_THREAT_DETECT_UTIL_BYTE_H
#define NET_THREAT_DETECT_UTIL_BYTE_H
#include <stdint.h>

int StringParseUint32(uint32_t *res, int base, uint16_t len, const char *str);
int StringParseInt32(int32_t *res, int base, uint16_t len, const char *str);
#endif // NET_THREAT_DETECT_UTIL_BYTE_H
