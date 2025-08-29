#include "decode-udp.h"
#include "decode.h"

static int DecodeUDPPacket(Packet *p, const uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < UDP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, UDP_HLEN_TOO_SMALL);
        return -1;
    }

    p->udph = (UDPHdr *)pkt;

    if (unlikely(len < UDP_GET_LEN(p))) {
        ENGINE_SET_INVALID_EVENT(p, UDP_PKT_TOO_SMALL);
        return -1;
    }

    if (unlikely(len != UDP_GET_LEN(p))) {
        // packet can still be valid, keeping for consistency with decoder.udp.hlen_invalid event
        ENGINE_SET_INVALID_EVENT(p, UDP_HLEN_INVALID);
    }
    if (unlikely(UDP_GET_LEN(p) < UDP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, UDP_LEN_INVALID);
        return -1;
    }

    SET_UDP_SRC_PORT(p,&p->sp);
    SET_UDP_DST_PORT(p,&p->dp);

    p->payload = (uint8_t *)pkt + UDP_HEADER_LEN;
    p->payload_len = UDP_GET_LEN(p) - UDP_HEADER_LEN;

    p->proto = IPPROTO_UDP;

    return 0;
}

int DecodeUDP(ThreadVars* tv, Packet *p,const uint8_t *pkt, uint16_t len)
{
    if (unlikely(DecodeUDPPacket(p, pkt,len) < 0)) {
        CLEAR_UDP_PACKET(p);
        return TM_ECODE_FAILED;
    }

    FlowSetupPacket(p);

    return TM_ECODE_OK;
}
