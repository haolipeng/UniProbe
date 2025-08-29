#ifndef NET_THREAT_DETECT_DECODE_UDP_H
#define NET_THREAT_DETECT_DECODE_UDP_H

#include "common/common.h"
#include <stdint.h>

#define UDP_HEADER_LEN         8

/* XXX RAW* needs to be really 'raw', so no SCNtohs there */
#define UDP_GET_RAW_LEN(udph)                SCNtohs((udph)->uh_len)
#define UDP_GET_RAW_SRC_PORT(udph)           SCNtohs((udph)->uh_sport)
#define UDP_GET_RAW_DST_PORT(udph)           SCNtohs((udph)->uh_dport)
#define UDP_GET_RAW_SUM(udph)                SCNtohs((udph)->uh_sum)

#define UDP_GET_LEN(p)                       UDP_GET_RAW_LEN(p->udph)
#define UDP_GET_SRC_PORT(p)                  UDP_GET_RAW_SRC_PORT(p->udph)
#define UDP_GET_DST_PORT(p)                  UDP_GET_RAW_DST_PORT(p->udph)
#define UDP_GET_SUM(p)                       UDP_GET_RAW_SUM(p->udph)

/* UDP header structure */
typedef struct UDPHdr_
{
	uint16_t uh_sport;  /* source port */
	uint16_t uh_dport;  /* destination port */
	uint16_t uh_len;    /* length */
	uint16_t uh_sum;    /* checksum */
} __attribute__((__packed__)) UDPHdr;

#define CLEAR_UDP_PACKET(p) do {    \
    (p)->level4_comp_csum = -1;     \
    (p)->udph = NULL;               \
} while (0)

#endif //NET_THREAT_DETECT_DECODE_UDP_H
