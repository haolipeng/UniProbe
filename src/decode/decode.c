#include "decode.h"
#include "modules/tmqh-packetpool.h"

uint32_t default_packet_size = DEFAULT_PACKET_SIZE;

inline int PacketCallocExtPkt(Packet *p, int datalen)
{
  if (! p->ext_pkt) {
    p->ext_pkt = calloc(1, datalen);
    if (unlikely(p->ext_pkt == NULL)) {
      SET_PKT_LEN(p, 0);
      return -1;
    }
  }
  return 0;
}

void PacketFree(Packet *p)
{
   PACKET_DESTRUCTOR(p);
   free(p);
}



/**
 * \brief Get a malloced packet.
 *
 * \retval p packet, NULL on error
 */
Packet *PacketGetFromAlloc(void)
{
  Packet *p = malloc(SIZE_OF_PACKET);
  if (unlikely(p == NULL)) {
    return NULL;
  }

  memset(p, 0, SIZE_OF_PACKET);
  PACKET_INITIALIZE(p);//init the packet
  p->ReleasePacket = PacketFree;
  p->flags |= PKT_ALLOC;

  SCLogDebug("allocated a new packet only using alloc...");
  return p;
}

void PacketFreeOrRelease(Packet *p)
{
  if (p->flags & PKT_ALLOC)
    PacketFree(p);
  else {
    p->ReleasePacket = PacketPoolReturnPacket;
    PacketPoolReturnPacket(p);
  }
}

int PacketCopyDataOffset(Packet *p, uint32_t offset, const uint8_t *data, uint32_t datalen)
{
  if (unlikely(offset + datalen > MAX_PAYLOAD_SIZE)) {
    /* too big */
    SET_PKT_LEN(p, 0);
    return -1;
  }

  /* Do we have already an packet with allocated data */
  if (! p->ext_pkt) {
    uint32_t newsize = offset + datalen;
    // check overflow
    if (newsize < offset)
      return -1;
    if (newsize <= default_packet_size) {
      /* data will fit in memory allocated with packet */
      memcpy(GET_PKT_DIRECT_DATA(p) + offset, data, datalen);
    } else {
      /* here we need a dynamic allocation */
      p->ext_pkt = malloc(MAX_PAYLOAD_SIZE);
      if (unlikely(p->ext_pkt == NULL)) {
        SET_PKT_LEN(p, 0);
        return -1;
      }
      /* copy initial data */
      memcpy(p->ext_pkt, GET_PKT_DIRECT_DATA(p), GET_PKT_DIRECT_MAX_SIZE(p));
      /* copy data as asked */
      memcpy(p->ext_pkt + offset, data, datalen);
    }
  } else {
    memcpy(p->ext_pkt + offset, data, datalen);
  }
  return 0;
}

inline int PacketCopyData(Packet *p, const uint8_t *pktdata, uint32_t pktlen)
{
  SET_PKT_LEN(p, (size_t)pktlen);
  return PacketCopyDataOffset(p, 0, pktdata, pktlen);
}

Packet *PacketGetFromQueueOrAlloc(void)
{
    /* try the pool first */
    Packet *p = PacketPoolGetPacket();

    if (p == NULL) {
        /* non fatal, we're just not processing a packet then */
        p = PacketGetFromAlloc();
    }

    return p;
}

inline int PacketSetData(Packet *p, const uint8_t *pktdata, uint32_t pktlen)
{
  SET_PKT_LEN(p, (size_t)pktlen);
  if (unlikely(!pktdata)) {
    return -1;
  }
  // ext_pkt cannot be const (because we sometimes copy)
  p->ext_pkt = (uint8_t *) pktdata;
  p->flags |= PKT_ZERO_COPY;

  return 0;
}
