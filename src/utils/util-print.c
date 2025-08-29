#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "util-print.h"
#include "util-debug.h"
#include "util-strlcatu.h"

#ifndef s6_addr16
# define s6_addr16 __u6_addr.__u6_addr16
#endif

static const char *PrintInetIPv6(const void *src, char *dst, socklen_t size)
{
    int i;
    char s_part[6];
    uint16_t x[8];
    memcpy(&x, src, 16);

    /* current IPv6 format is fixed size */
    if (size < 8 * 5) {
        SCLogWarning(SC_ERR_ARG_LEN_LONG, "Too small buffer to write IPv6 address");
        return NULL;
    }
    memset(dst, 0, size);
    for(i = 0; i < 8; i++) {
        snprintf(s_part, sizeof(s_part), "%04x:", htons(x[i]));
        strlcat(dst, s_part, size);
    }
    /* suppress last ':' */
    dst[strlen(dst) - 1] = 0;

    return dst;
}

const char *PrintInet(int af, const void *src, char *dst, socklen_t size)
{
    switch (af) {
        case AF_INET:
            return inet_ntop(af, src, dst, size);

        case AF_INET6:
            /* Format IPv6 without deleting zeroes */
            return PrintInetIPv6(src, dst, size);
        default:
            SCLogError(SC_ERR_INVALID_VALUE, "Unsupported protocol: %d", af);
    }
    return NULL;
}