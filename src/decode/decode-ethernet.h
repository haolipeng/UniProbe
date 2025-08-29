#ifndef __DECODE_ETHERNET_H__
#define __DECODE_ETHERNET_H__

#include <stdint.h>

#define ETHERNET_HEADER_LEN           14

#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_IPV6            0x86dd

typedef struct EthernetHdr_ {
    uint8_t eth_dst[6];
    uint8_t eth_src[6];
    uint16_t eth_type;
} __attribute__((__packed__)) EthernetHdr;
#endif /* __DECODE_ETHERNET_H__ */

