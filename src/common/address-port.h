#ifndef NET_THREAT_DETECT_ADDRESS_PORT_H
#define NET_THREAT_DETECT_ADDRESS_PORT_H
#include <netinet/ip.h>
#include <stdint.h>

/* Address */
typedef struct Address_ {
  char family;
  union {
    uint32_t        address_un_data32[4]; /* type-specific field */
    uint16_t        address_un_data16[8]; /* type-specific field */
    uint8_t         address_un_data8[16]; /* type-specific field */
    struct in6_addr address_un_in6;
  } address;
} Address;

typedef uint16_t Port;

#endif // NET_THREAT_DETECT_ADDRESS_PORT_H
