#ifndef NET_THREAT_DETECT_DECODE_H
#define NET_THREAT_DETECT_DECODE_H

#include <limits.h>
#include <netinet/in.h>
#include <pcap/dlt.h>
#include <stdint.h>
#include <stdlib.h>

#include "decode-events.h"
#include "common/address-port.h"
#include "common/packet-define.h"
#include "utils/helper.h"

#include "decode-ethernet.h"
#include "decode-ipv4.h"
#include "decode-ipv6.h"
#include "decode-udp.h"
#include "decode-tcp.h"

#include "flow/flow.h"
#include "utils/util-debug.h"

enum PktSrcEnum {
    PKT_SRC_WIRE = 1,
    PKT_SRC_DECODER_GRE,
    PKT_SRC_DECODER_IPV4,
    PKT_SRC_DECODER_IPV6,
    PKT_SRC_DEFRAG,
    PKT_SRC_FFR,
    PKT_SRC_STREAM_TCP_DETECTLOG_FLUSH,
    PKT_SRC_DECODER_VXLAN,
    PKT_SRC_DETECT_RELOAD_FLUSH,
    PKT_SRC_CAPTURE_TIMEOUT,
    PKT_SRC_DECODER_GENEVE,
};

////////////////////////////////全局函数声明区////////////////////////////////
int PacketSetData(Packet *p, const uint8_t *pktdata, uint32_t pktlen);
int PacketCopyDataOffset(Packet *p, uint32_t offset, const uint8_t *data, uint32_t datalen);

int PacketCallocExtPkt(Packet *p, int datalen);

Packet *PacketGetFromQueueOrAlloc(void);
Packet *PacketGetFromAlloc(void);
void PacketFree(Packet *p);
void PacketFreeOrRelease(Packet *p);
int PacketCopyData(Packet *p, const uint8_t *pktdata, uint32_t pktlen);

int DecodeEthernet(ThreadVars *tv, Packet *, const uint8_t *, uint32_t);
int DecodeIPV4(ThreadVars* tv, Packet *, const uint8_t *, uint16_t);
int DecodeIPV6(ThreadVars* tv, Packet *, const uint8_t *, uint16_t);
int DecodeUDP(ThreadVars* tv, Packet *, const uint8_t *, uint16_t);
int DecodeTCP(ThreadVars* tv, Packet *, const uint8_t *, uint16_t);

#define LINKTYPE_RAW         DLT_RAW
#define MAX_PAYLOAD_SIZE (40 + 65536 + 28)

#define DecodeSetNoPacketInspectionFlag(p) do { \
        (p)->flags |= PKT_NOPACKET_INSPECTION;  \
    } while (0)

#define DecodeSetNoPayloadInspectionFlag(p) do { \
        (p)->flags |= PKT_NOPAYLOAD_INSPECTION;  \
    } while (0)

#define PKT_IS_IPV4(p)      (((p)->ip4h != NULL))
#define PKT_IS_IPV6(p)      (((p)->ip6h != NULL))
#define PKT_IS_TCP(p)       (((p)->tcph != NULL))
#define PKT_IS_UDP(p)       (((p)->udph != NULL))
//#define PKT_IS_ICMPV4(p)    (((p)->icmpv4h != NULL))
//#define PKT_IS_ICMPV6(p)    (((p)->icmpv6h != NULL))
#define PKT_IS_TOSERVER(p)  (((p)->flowflags & FLOW_PKT_TOSERVER))
#define PKT_IS_TOCLIENT(p)  (((p)->flowflags & FLOW_PKT_TOCLIENT))

/*Packet Flags*/
#define PKT_NOPACKET_INSPECTION         (1)         /**< Flag to indicate that packet header or contents should not be inspected*/
#define PKT_NOPAYLOAD_INSPECTION        (1<<2)      /**< Flag to indicate that packet contents should not be inspected*/
#define PKT_ALLOC                       (1<<3)      /**< Packet was alloc'd this run, needs to be freed */
#define PKT_HAS_TAG                     (1<<4)      /**< Packet has matched a tag */
#define PKT_STREAM_ADD                  (1<<5)      /**< Packet payload was added to reassembled stream */
#define PKT_STREAM_EST                  (1<<6)      /**< Packet is part of established stream */
#define PKT_STREAM_EOF                  (1<<7)      /**< Stream is in eof state */
#define PKT_HAS_FLOW                    (1<<8)
#define PKT_PSEUDO_STREAM_END           (1<<9)      /**< Pseudo packet to end the stream */
#define PKT_STREAM_MODIFIED             (1<<10)     /**< Packet is modified by the stream engine, we need to recalc the csum and reinject/replace */
#define PKT_MARK_MODIFIED               (1<<11)     /**< Packet mark is modified */
#define PKT_STREAM_NOPCAPLOG            (1<<12)     /**< Exclude packet from pcap logging as it's part of a stream that has reassembly depth reached. */

#define PKT_TUNNEL                      (1<<13)
#define PKT_TUNNEL_VERDICTED            (1<<14)

#define PKT_IGNORE_CHECKSUM             (1<<15)     /**< Packet checksum is not computed (TX packet for example) */
#define PKT_ZERO_COPY                   (1<<16)     /**< Packet comes from zero copy (ext_pkt must not be freed) */

#define PKT_HOST_SRC_LOOKED_UP          (1<<17)
#define PKT_HOST_DST_LOOKED_UP          (1<<18)

#define PKT_IS_FRAGMENT                 (1<<19)     /**< Packet is a fragment */
#define PKT_IS_INVALID                  (1<<20)
#define PKT_PROFILE                     (1<<21)

/** indication by decoder that it feels the packet should be handled by
 *  flow engine: Packet::flow_hash will be set */
#define PKT_WANTS_FLOW                  (1<<22)

/** protocol detection done */
#define PKT_PROTO_DETECT_TS_DONE        (1<<23)
#define PKT_PROTO_DETECT_TC_DONE        (1<<24)

#define PKT_REBUILT_FRAGMENT            (1<<25)     /**< Packet is rebuilt from
                                                     * fragments. */
#define PKT_DETECT_HAS_STREAMDATA       (1<<26)     /**< Set by Detect() if raw stream data is available. */

#define PKT_PSEUDO_DETECTLOG_FLUSH      (1<<27)     /**< Detect/log flush for protocol upgrade */

/** Packet is part of stream in known bad condition (loss, wrong thread),
 *  so flag it for not setting stream events */
#define PKT_STREAM_NO_EVENTS            (1<<28)

/** \brief return 1 if the packet is a pseudo packet */
#define PKT_IS_PSEUDOPKT(p) \
    ((p)->flags & (PKT_PSEUDO_STREAM_END|PKT_PSEUDO_DETECTLOG_FLUSH))

#define PKT_SET_SRC(p, src_val) ((p)->pkt_src = src_val)

/* Set the IPv4 addresses into the Addrs of the Packet.
 * Make sure p->ip4h is initialized and validated.
 *
 * We set the rest of the struct to 0 so we can
 * prevent using memset. */
#define SET_IPV4_SRC_ADDR(p, a) do {                              \
        (a)->family = AF_INET;                                    \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_src.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)

#define SET_IPV4_DST_ADDR(p, a) do {                              \
        (a)->family = AF_INET;                                    \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_dst.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)

/* clear the address structure by setting all fields to 0 */
#define CLEAR_ADDR(a) do {       \
        (a)->family = 0;         \
        (a)->addr_data32[0] = 0; \
        (a)->addr_data32[1] = 0; \
        (a)->addr_data32[2] = 0; \
        (a)->addr_data32[3] = 0; \
    } while (0)

/* Set the IPv6 addresses into the Addrs of the Packet.
 * Make sure p->ip6h is initialized and validated. */
#define SET_IPV6_SRC_ADDR(p, a) do {                    \
        (a)->family = AF_INET6;                         \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_src[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_src[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_src[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_src[3];  \
    } while (0)

#define SET_IPV6_DST_ADDR(p, a) do {                    \
        (a)->family = AF_INET6;                         \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_dst[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_dst[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_dst[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_dst[3];  \
    } while (0)

/* Set the TCP ports into the Ports of the Packet.
 * Make sure p->tcph is initialized and validated. */
#define SET_TCP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(TCP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)

#define SET_TCP_DST_PORT(pkt, prt) do {            \
        SET_PORT(TCP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)

/* Set the UDP ports into the Ports of the Packet.
 * Make sure p->udph is initialized and validated. */
#define SET_UDP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(UDP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)
#define SET_UDP_DST_PORT(pkt, prt) do {            \
        SET_PORT(UDP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)

#define GET_IPV4_SRC_ADDR_PTR(p) ((p)->src.addr_data32)
#define GET_IPV4_DST_ADDR_PTR(p) ((p)->dst.addr_data32)

#define GET_IPV6_SRC_ADDR(p) ((p)->src.addr_data32)
#define GET_IPV6_DST_ADDR(p) ((p)->dst.addr_data32)

#define GET_PKT_LEN(p) ((p)->pktlen)
#define GET_PKT_DATA(p) ((((p)->ext_pkt) == NULL ) ? (uint8_t *)((p) + 1) : (p)->ext_pkt)
#define GET_PKT_DIRECT_DATA(p) (uint8_t *)((p) + 1)
#define GET_PKT_DIRECT_MAX_SIZE(p) (default_packet_size)

#define SET_PKT_LEN(p, len) do { \
    (p)->pktlen = (len); \
    } while (0)

#define DEFAULT_MTU 1500
#define DEFAULT_PACKET_SIZE (DEFAULT_MTU + ETHERNET_HEADER_LEN)

/* Port is just a uint16_t */
typedef uint16_t Port;
#define SET_PORT(v, p) ((p) = (v))
#define COPY_PORT(a,b) ((b) = (a))
#define CMP_ADDR(a1, a2) \
    (((a1)->addr_data32[3] == (a2)->addr_data32[3] && \
      (a1)->addr_data32[2] == (a2)->addr_data32[2] && \
      (a1)->addr_data32[1] == (a2)->addr_data32[1] && \
      (a1)->addr_data32[0] == (a2)->addr_data32[0]))
#define CMP_PORT(p1, p2) \
    ((p1) == (p2))

/*Given a packet pkt offset to the start of the ip header in a packet
 *We determine the ip version. */
#define IP_GET_RAW_VER(pkt) ((((pkt)[0] & 0xf0) >> 4))

#define PACKET_CLEAR_L4VARS(p) do {                         \
        memset(&(p)->l4vars, 0x00, sizeof((p)->l4vars));    \
    } while (0)

/* pcap provides this, but we don't want to depend on libpcap */
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#define LINKTYPE_ETHERNET    DLT_EN10MB

typedef struct AppLayerDecoderEvents_ AppLayerDecoderEvents;
void AppLayerDecoderEventsResetEvents(AppLayerDecoderEvents *events);

#define PACKET_RESET_CHECKSUMS(p) do { \
        (p)->level3_comp_csum = -1;   \
        (p)->level4_comp_csum = -1;   \
    } while (0)

/* if p uses extended data, free them */
#define PACKET_FREE_EXTDATA(p) do {                 \
        if ((p)->ext_pkt) {                         \
            if (!((p)->flags & PKT_ZERO_COPY)) {    \
                free((p)->ext_pkt);               \
            }                                       \
            (p)->ext_pkt = NULL;                    \
        }                                           \
    } while(0)

#define PACKET_RELEASE_REFS(p) do {              \
        FlowDeReference(&((p)->flow));          \
    } while (0)

#define PACKET_INITIALIZE(p)                                                                       \
    {                                                                                              \
        PACKET_RESET_CHECKSUMS((p));                                                               \
        (p)->livedev = NULL;                                                                       \
    }

#define PACKET_REINIT(p)                                                                           \
    do {                                                                                           \
        CLEAR_ADDR(&(p)->src);                                                                     \
        CLEAR_ADDR(&(p)->dst);                                                                     \
        (p)->sp = 0;                                                                               \
        (p)->dp = 0;                                                                               \
        (p)->proto = 0;                                                                            \
        PACKET_FREE_EXTDATA((p));                                                                  \
        (p)->flags = (p)->flags & PKT_ALLOC;                                                       \
        (p)->flowflags = 0;                                                                        \
        (p)->pkt_src = 0;                                                                          \
        (p)->vlan_id[0] = 0;                                                                       \
        (p)->vlan_id[1] = 0;                                                                       \
        (p)->vlan_idx = 0;                                                                         \
        (p)->ts.tv_sec = 0;                                                                        \
        (p)->ts.tv_usec = 0;                                                                       \
        (p)->datalink = 0;                                                                         \
        (p)->ethh = NULL;                                                                          \
        if ((p)->ip4h != NULL) {                                                                   \
            CLEAR_IPV4_PACKET((p));                                                                \
        }                                                                                          \
        if ((p)->ip6h != NULL) {                                                                   \
            CLEAR_IPV6_PACKET((p));                                                                \
        }                                                                                          \
        if ((p)->tcph != NULL) {                                                                   \
            CLEAR_TCP_PACKET((p));                                                                 \
        }                                                                                          \
        if ((p)->udph != NULL) {                                                                   \
            CLEAR_UDP_PACKET((p));                                                                 \
        }                                                                                          \
        (p)->payload = NULL;                                                                       \
        (p)->payload_len = 0;                                                                      \
        (p)->pktlen = 0;                                                                           \
        (p)->events.cnt = 0;                                                                       \
        AppLayerDecoderEventsResetEvents((p)->app_layer_events);                                   \
        (p)->next = NULL;                                                                          \
        (p)->prev = NULL;                                                                          \
        (p)->livedev = NULL;                                                                       \
        PACKET_RESET_CHECKSUMS((p));                                                               \
    } while (0)

#define PACKET_DESTRUCTOR(p)                                                                       \
    do {                                                                                           \
        PACKET_RELEASE_REFS((p));                                                                  \
        PACKET_FREE_EXTDATA((p));                                                                  \
        AppLayerDecoderEventsFreeEvents(&(p)->app_layer_events);                                   \
    } while (0)

#define ENGINE_SET_EVENT(p, e) do { \
    SCLogDebug("p %p event %d", (p), e); \
    if ((p)->events.cnt < PACKET_ENGINE_EVENT_MAX) { \
        (p)->events.events[(p)->events.cnt] = e; \
        (p)->events.cnt++; \
    } \
} while(0)

#define ENGINE_SET_INVALID_EVENT(p, e) do { \
    p->flags |= PKT_IS_INVALID; \
    ENGINE_SET_EVENT(p, e); \
} while(0)

static inline bool DecodeNetworkLayer(ThreadVars* tv, const uint16_t proto, Packet *p, const uint8_t *data, const uint32_t len)
{
    switch (proto) {
        case ETHERNET_TYPE_IP: {
            uint16_t ip_len = (len < USHRT_MAX) ? (uint16_t)len : (uint16_t)USHRT_MAX;
            DecodeIPV4(tv, p, data, ip_len);
            break;
        }
        case ETHERNET_TYPE_IPV6: {
            uint16_t ip_len = (len < USHRT_MAX) ? (uint16_t)len : (uint16_t)USHRT_MAX;
            DecodeIPV6(tv, p, data, ip_len);
            break;
        }
        default:
            SCLogDebug("unknown ether type: %" PRIx16 "", proto);
            return false;
    }
    return true;
}

#endif //NET_THREAT_DETECT_DECODE_H
