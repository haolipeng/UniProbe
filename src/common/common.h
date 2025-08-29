#ifndef NET_THREAT_DETECT_COMMON_H
#define NET_THREAT_DETECT_COMMON_H
#include <assert.h>
#include <string.h>

#ifndef MIN
#define MIN(x, y) (((x)<(y))?(x):(y))
#endif

#ifndef MAX
#define MAX(x, y) (((x)<(y))?(y):(x))
#endif

#define BIT_U8(n)  ((uint8_t)(1 << (n)))
#define BIT_U16(n) ((uint16_t)(1 << (n)))
#define BIT_U32(n) (1UL  << (n))
#define BIT_U64(n) (1ULL << (n))

#define BUG_ON(x) assert(!(x))
#define DEBUG_VALIDATE_BUG_ON(exp) BUG_ON((exp))

#define SCNtohl(x) (uint32_t)ntohl((x))
#define SCNtohs(x) (uint16_t)ntohs((x))

/* wrapper around memcmp to match the retvals of the SIMD implementations */
#define SCMemcmp(a,b,c) ({ \
    memcmp((a), (b), (c)) ? 1 : 0; \
})

/* swap flags if one of them is set, otherwise do nothing. */
#define SWAP_FLAGS(flags, a, b)                     \
    do {                                            \
        if (((flags) & ((a)|(b))) == (a)) {         \
            (flags) &= ~(a);                        \
            (flags) |= (b);                         \
        } else if (((flags) & ((a)|(b))) == (b)) {  \
            (flags) &= ~(b);                        \
            (flags) |= (a);                         \
        }                                           \
    } while(0)

#define SWAP_VARS(type, a, b)           \
    do {                                \
        type t = (a);                   \
        (a) = (b);                      \
        (b) = t;                        \
    } while (0)

typedef enum {
    LOGGER_UNDEFINED,

    /* TX loggers first for low logger IDs */
    LOGGER_DNS_TS,
    LOGGER_DNS_TC,
    LOGGER_HTTP,
    LOGGER_TLS_STORE,
    LOGGER_TLS,
    LOGGER_JSON_DNS_TS,
    LOGGER_JSON_DNS_TC,
    LOGGER_JSON_HTTP,
    LOGGER_JSON_SMTP,
    LOGGER_JSON_TLS,
    LOGGER_JSON_NFS,
    LOGGER_JSON_TFTP,
    LOGGER_JSON_FTP,
    LOGGER_JSON_DNP3_TS,
    LOGGER_JSON_DNP3_TC,
    LOGGER_JSON_SSH,
    LOGGER_JSON_SMB,
    LOGGER_JSON_IKEV2,
    LOGGER_JSON_KRB5,
    LOGGER_JSON_DHCP,
    LOGGER_JSON_SNMP,
    LOGGER_JSON_SIP,
    LOGGER_JSON_TEMPLATE_RUST,
    LOGGER_JSON_RFB,
    LOGGER_JSON_MQTT,
    LOGGER_JSON_TEMPLATE,
    LOGGER_JSON_RDP,
    LOGGER_JSON_DCERPC,
    LOGGER_JSON_HTTP2,

    LOGGER_ALERT_DEBUG,
    LOGGER_ALERT_FAST,
    LOGGER_UNIFIED2,
    LOGGER_ALERT_SYSLOG,
    LOGGER_DROP,
    LOGGER_JSON_ALERT,
    LOGGER_JSON_ANOMALY,
    LOGGER_JSON_DROP,
    LOGGER_FILE_STORE,
    LOGGER_JSON_FILE,
    LOGGER_TCP_DATA,
    LOGGER_JSON_FLOW,
    LOGGER_JSON_NETFLOW,
    LOGGER_STATS,
    LOGGER_JSON_STATS,
    LOGGER_PRELUDE,
    LOGGER_PCAP,
    LOGGER_JSON_METADATA,
    LOGGER_SIZE,
} LoggerId;

//TODO: set HAVE_FWRITE_UNLOCKED = 1
#define HAVE_FWRITE_UNLOCKED 1

#ifndef HAVE_FWRITE_UNLOCKED
#define SCFwriteUnlocked    fwrite
#define SCFflushUnlocked    fflush
#define SCClearErrUnlocked  clearerr
#define SCFerrorUnlocked    ferror
#else
#define SCFwriteUnlocked    fwrite_unlocked
#define SCFflushUnlocked    fflush_unlocked
#define SCClearErrUnlocked  clearerr_unlocked
#define SCFerrorUnlocked    ferror_unlocked
#endif
#endif //NET_THREAT_DETECT_COMMON_H
