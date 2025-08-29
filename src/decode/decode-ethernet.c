#include <stdio.h>
#include "decode-ethernet.h"
#include "decode.h"
#include "dpi/dpi_module.h"

int DecodeEthernet(ThreadVars *tv, Packet *p,const uint8_t *pkt, uint32_t len)
{
    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->ethh = (EthernetHdr *)pkt;
    if (unlikely(p->ethh == NULL))
        return TM_ECODE_FAILED;

    p->eth_type = SCNtohs(p->ethh->eth_type);
    const uint8_t * data = pkt + ETHERNET_HEADER_LEN;
    uint32_t new_len = len - ETHERNET_HEADER_LEN;

#ifdef DEBUG
#define DBG_MAC_FORMAT "%02x:%02x:%02x:%02x:%02x:%02x"
#define DBG_MAC_TUPLE(mac) \
        ((uint8_t *)&(mac))[0], ((uint8_t *)&(mac))[1], ((uint8_t *)&(mac))[2], \
        ((uint8_t *)&(mac))[3], ((uint8_t *)&(mac))[4], ((uint8_t *)&(mac))[5]

    char srcMac[64] = {};
    sprintf(srcMac,DBG_MAC_FORMAT, DBG_MAC_TUPLE(p->ethh->eth_src));

    char dstMac[64] = {};
    sprintf(dstMac,DBG_MAC_FORMAT, DBG_MAC_TUPLE(p->ethh->eth_dst));
#endif

    DecodeNetworkLayer(tv, SCNtohs(p->ethh->eth_type), p,data, new_len);

    return TM_ECODE_OK;
}
