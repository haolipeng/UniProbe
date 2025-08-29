#ifndef NET_THREAT_DETECT_PACKET_DEFINE_H
#define NET_THREAT_DETECT_PACKET_DEFINE_H

#include "address-port.h"
#include "app-layer/app-layer-events.h"
#include "decode/decode-ethernet.h"
#include "decode/decode-ipv4.h"
#include "decode/decode-ipv6.h"
#include "decode/decode-tcp.h"
#include "decode/decode-udp.h"
#include "modules/source-af-packet.h"

/** number of decoder events we support per packet. Power of 2 minus 1
 *  for memory layout */
#define PACKET_ENGINE_EVENT_MAX 15

/** data structure to store decoder, defrag and stream events */
typedef struct PacketEngineEvents_ {
  uint8_t cnt;                                /**< number of events */
  uint8_t events[PACKET_ENGINE_EVENT_MAX];   /**< array of events */
} PacketEngineEvents;

typedef struct Packet_
{
  /* Addresses, Ports and protocol
     * these are on top so we can use
     * the Packet as a hash key */
  Address src;
  Address dst;
  union {
    Port sp;
    // icmp type and code of this packet
    struct {
      uint8_t type;
      uint8_t code;
    } icmp_s;
  };
  union {
    Port dp;
    // icmp type and code of the expected counterpart (for flows)
    struct {
      uint8_t type;
      uint8_t code;
    } icmp_d;
  };
  uint8_t proto;

  uint16_t vlan_id[2];
  uint8_t vlan_idx;

  /* flow */
  uint8_t flowflags;
  /* coccinelle: Packet:flowflags:FLOW_PKT_ */

  /* Pkt Flags */
  uint32_t flags;

  struct Flow_* flow;

  /* raw hash value for looking up the flow, will need to modulated to the
     * hash size still */
  uint32_t flow_hash;

  struct timeval ts;

  union {
#ifdef AF_PACKET
    AFPPacketVars afp_v;
#endif
  };

  /** The release function for packet structure and data */
  void (*ReleasePacket)(struct Packet_ *);

  /* header pointers */
  EthernetHdr *ethh;
  uint16_t eth_type;

  /* Checksum for IP packets. */
  int32_t level3_comp_csum;
  /* Check sum for TCP, UDP or ICMP packets */
  int32_t level4_comp_csum;

  IPV4Hdr *ip4h;

  IPV6Hdr *ip6h;

  /* IPv4 and IPv6 are mutually exclusive */
  union {
    IPV4Vars ip4vars;
    struct {
      IPV6Vars ip6vars;
      IPV6ExtHdrs ip6eh;
    };
  };
  /* Can only be one of TCP, UDP, ICMP at any given time */
  union {
    TCPVars tcpvars;
    //ICMPV4Vars icmpv4vars;
    //ICMPV6Vars icmpv6vars;
  } l4vars;
#define tcpvars     l4vars.tcpvars
#define icmpv4vars  l4vars.icmpv4vars
#define icmpv6vars  l4vars.icmpv6vars

  TCPHdr *tcph;

  UDPHdr *udph;

  //ICMPV4Hdr *icmpv4h;

  //ICMPV6Hdr *icmpv6h;

  uint8_t *payload;
  uint16_t payload_len;

  uint8_t pkt_src;

  /* storage: set to pointer to heap and extended via allocation if necessary */
  uint32_t pktlen;
  uint8_t *ext_pkt;

  /* Incoming interface */
  struct LiveDevice_ *livedev;

    /** packet number in the pcap file, matches wireshark */
    uint64_t pcap_cnt;

  /* engine events */
  PacketEngineEvents events;

  AppLayerDecoderEvents *app_layer_events;

  /* double linked list ptrs */
  struct Packet_ *next;
  struct Packet_ *prev;

  /** data linktype in host order */
  int datalink;

  uint8_t *ep_mac;

  uint64_t id;

  /* The Packet pool from which this packet was allocated. Used when returning
     * the packet to its owner's stack. If NULL, then allocated with malloc.
   */
  struct PktPool_ *pool;
} Packet;

extern uint32_t default_packet_size;
#define SIZE_OF_PACKET (default_packet_size + sizeof(Packet))

#endif // NET_THREAT_DETECT_PACKET_DEFINE_H
