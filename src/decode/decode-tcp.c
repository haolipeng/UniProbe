#include "decode-tcp.h"
#include "decode.h"

#define SET_OPTS(dst, src) \
    (dst).type = (src).type; \
    (dst).len  = (src).len; \
    (dst).data = (src).data

static void DecodeTCPOptions(Packet *p, const uint8_t *pkt, uint16_t pktlen)
{
    uint8_t tcp_opt_cnt = 0;
    TCPOpt tcp_opts[TCP_OPTMAX];

    uint16_t plen = pktlen;
    while (plen)
    {
        const uint8_t type = *pkt;

        /* single byte options */
        if (type == TCP_OPT_EOL) {
            break;
        } else if (type == TCP_OPT_NOP) {
            pkt++;
            plen--;

            /* multibyte options */
        } else {
            if (plen < 2) {
                break;
            }

            const uint8_t olen = *(pkt+1);

            /* we already know that the total options len is valid,
             * so here the len of the specific option must be bad.
             * Also check for invalid lengths 0 and 1. */
            if (unlikely(olen > plen || olen < 2)) {
                ENGINE_SET_INVALID_EVENT(p, TCP_OPT_INVALID_LEN);
                p->flags |= PKT_IS_INVALID;
                return;
            }

            tcp_opts[tcp_opt_cnt].type = type;
            tcp_opts[tcp_opt_cnt].len  = olen;
            tcp_opts[tcp_opt_cnt].data = (olen > 2) ? (pkt+2) : NULL;

            /* we are parsing the most commonly used opts to prevent
             * us from having to walk the opts list for these all the
             * time. */
            switch (type) {
                case TCP_OPT_WS:
                    if (olen != TCP_OPT_WS_LEN) {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.ws.type != 0) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(p->tcpvars.ws, tcp_opts[tcp_opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_MSS:
                    if (olen != TCP_OPT_MSS_LEN) {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.mss.type != 0) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(p->tcpvars.mss, tcp_opts[tcp_opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_SACKOK:
                    if (olen != TCP_OPT_SACKOK_LEN) {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.sackok.type != 0) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(p->tcpvars.sackok, tcp_opts[tcp_opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_TS:
                    if (olen != TCP_OPT_TS_LEN) {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.ts_set) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            uint32_t values[2];
                            memcpy(&values, tcp_opts[tcp_opt_cnt].data, sizeof(values));
                            p->tcpvars.ts_val = SCNtohl(values[0]);
                            p->tcpvars.ts_ecr = SCNtohl(values[1]);
                            p->tcpvars.ts_set = TRUE;
                        }
                    }
                    break;
                case TCP_OPT_SACK:
                    SCLogDebug("SACK option, len %u", olen);
                    if ((olen != 2) &&
                        (olen < TCP_OPT_SACK_MIN_LEN ||
                         olen > TCP_OPT_SACK_MAX_LEN ||
                         !((olen - 2) % 8 == 0)))
                    {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.sack.type != 0) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(p->tcpvars.sack, tcp_opts[tcp_opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_TFO:
                    SCLogDebug("TFO option, len %u", olen);
                    if ((olen != 2) && (olen < TCP_OPT_TFO_MIN_LEN || olen > TCP_OPT_TFO_MAX_LEN ||
                                        !(((olen - 2) & 0x1) == 0))) {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.tfo.type != 0) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(p->tcpvars.tfo, tcp_opts[tcp_opt_cnt]);
                        }
                    }
                    break;
                    /* experimental options, could be TFO */
                case TCP_OPT_EXP1:
                case TCP_OPT_EXP2:
                    SCLogDebug("TCP EXP option, len %u", olen);
                    if (olen == 4 || olen == 12) {
                        uint16_t magic = SCNtohs(*(uint16_t *)tcp_opts[tcp_opt_cnt].data);
                        if (magic == 0xf989) {
                            if (p->tcpvars.tfo.type != 0) {
                                ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                            } else {
                                SET_OPTS(p->tcpvars.tfo, tcp_opts[tcp_opt_cnt]);
                                p->tcpvars.tfo.type = TCP_OPT_TFO; // treat as regular TFO
                            }
                        }
                    } else {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    }
                    break;
                    /* RFC 2385 MD5 option */
                case TCP_OPT_MD5:
                    SCLogDebug("MD5 option, len %u", olen);
                    if (olen != 18) {
                        ENGINE_SET_INVALID_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        /* we can't validate the option as the key is out of band */
                        p->tcpvars.md5_option_present = true;
                    }
                    break;
                    /* RFC 5925 AO option */
                case TCP_OPT_AO:
                    SCLogDebug("AU option, len %u", olen);
                    if (olen < 4) {
                        ENGINE_SET_INVALID_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        /* we can't validate the option as the key is out of band */
                        p->tcpvars.ao_option_present = true;
                    }
                    break;
            }

            pkt += olen;
            plen -= olen;
            tcp_opt_cnt++;
            tcp_opt_cnt++;
        }
    }
}

static int DecodeTCPPacket(Packet *p, const uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < TCP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, TCP_PKT_TOO_SMALL);
        return -1;
    }

    p->tcph = (TCPHdr *)pkt;

    uint8_t hlen = TCP_GET_HLEN(p);
    if (unlikely(len < hlen)) {
        ENGINE_SET_INVALID_EVENT(p, TCP_HLEN_TOO_SMALL);
        return -1;
    }

    uint8_t tcp_opt_len = hlen - TCP_HEADER_LEN;
    if (unlikely(tcp_opt_len > TCP_OPTLENMAX)) {
        ENGINE_SET_INVALID_EVENT(p, TCP_INVALID_OPTLEN);
        return -1;
    }

    if (likely(tcp_opt_len > 0)) {
        DecodeTCPOptions(p, pkt + TCP_HEADER_LEN, tcp_opt_len);
    }

    SET_TCP_SRC_PORT(p,&p->sp);
    SET_TCP_DST_PORT(p,&p->dp);

    p->proto = IPPROTO_TCP;

    p->payload = (uint8_t *)pkt + hlen;
    p->payload_len = len - hlen;

    return 0;
}

int DecodeTCP(ThreadVars* tv, Packet *p,const uint8_t *pkt, uint16_t len)
{
    if (unlikely(DecodeTCPPacket(p, pkt,len) < 0)) {
        SCLogDebug("invalid TCP packet");
        CLEAR_TCP_PACKET(p);
        return TM_ECODE_FAILED;
    }

    FlowSetupPacket(p);

    return TM_ECODE_OK;
}