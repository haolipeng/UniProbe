#include "decode-ipv4.h"
#include "decode.h"
#include "dpi/dpi_module.h"
#include "utils/packet-queue.h"
#include "utils/util-print.h"
#include "modules/threadvars.h"

static int IPV4OptValidateGeneric(Packet *p, const IPV4Opt *o)
{
    switch (o->type) {
        /* See: RFC 4782 */
        case IPV4_OPT_QS:
            if (o->len < IPV4_OPT_QS_MIN) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }
            break;
            /* See: RFC 1108 */
        case IPV4_OPT_SEC:
            if (o->len != IPV4_OPT_SEC_LEN) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }
            break;
        case IPV4_OPT_SID:
            if (o->len != IPV4_OPT_SID_LEN) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }
            break;
            /* See: RFC 2113 */
        case IPV4_OPT_RTRALT:
            if (o->len != IPV4_OPT_RTRALT_LEN) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }
            break;
        default:
            /* Should never get here unless there is a coding error */
            ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_UNKNOWN);
            return -1;
    }

    return 0;
}

/* Validate route type options
 *
 * [--type--][--len---][--ptr---][address1]...[addressN]
 *
 * See: RFC 791
 */
static int IPV4OptValidateRoute(Packet *p, const IPV4Opt *o)
{
    uint8_t ptr;

    /* Check length */
    if (unlikely(o->len < IPV4_OPT_ROUTE_MIN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
        return -1;
    }

    /* Data is required */
    if (unlikely(o->data == NULL)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }
    ptr = *o->data;

    /* Address pointer is 1 based and points at least after type+len+ptr,
     * must be a incremented by 4 bytes (address size) and cannot extend
     * past option length.
     */
    if (unlikely((ptr < 4) || (ptr % 4) || (ptr > o->len + 1))) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }

    return 0;
}

/* Validate timestamp type options
 *
 * [--type--][--len---][--ptr---][ovfl][flag][rec1----...]...[recN----...]
 * NOTE: rec could be 4 (ts only) or 8 (ip+ts) bytes in length.
 *
 * See: RFC 781
 */
static int IPV4OptValidateTimestamp(Packet *p, const IPV4Opt *o)
{
    uint8_t ptr;
    uint8_t flag;
    uint8_t rec_size;

    /* Check length */
    if (unlikely(o->len < IPV4_OPT_TS_MIN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
        return -1;
    }

    /* Data is required */
    if (unlikely(o->data == NULL)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }
    ptr = *o->data;

    /* We need the flag to determine what is in the option payload */
    if (unlikely(ptr < 5)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }
    flag = *(o->data + 1) & 0x0f;

    /* A flag of 1|3 means we have both the ip+ts in each record */
    rec_size = ((flag == 1) || (flag == 3)) ? 8 : 4;

    /* Address pointer is 1 based and points at least after
     * type+len+ptr+ovfl+flag, must be incremented by by the rec_size
     * and cannot extend past option length.
     */
    if (unlikely(((ptr - 5) % rec_size) || (ptr > o->len + 1))) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }

    return 0;
}

/* Validate CIPSO option
 *
 * [--type--][--len---][--doi---][tags--...]
 *
 * See: draft-ietf-cipso-ipsecurity-01.txt
 * See: FIPS 188 (tags 6 & 7)
 */
static int IPV4OptValidateCIPSO(Packet *p, const IPV4Opt *o)
{
//    uint32_t doi;
    const uint8_t *tag;
    uint16_t len;

    /* Check length */
    if (unlikely(o->len < IPV4_OPT_CIPSO_MIN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
        return -1;
    }

    /* Data is required */
    if (unlikely(o->data == NULL)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
        return -1;
    }
//    doi = *o->data;
    tag = o->data + 4;
    len = o->len - 1 - 1 - 4; /* Length of tags after header */

    /* NOTE: We know len has passed min tests prior to this call */

    /* Check that tags are formatted correctly
     * [-ttype--][--tlen--][-tagdata-...]
     */
    while (len) {
        uint8_t ttype;
        uint8_t tlen;

        /* Tag header must fit within option length */
        if (unlikely(len < 2)) {
            //printf("CIPSO tag header too large %" PRIu16 " < 2\n", len);
            ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
            return -1;
        }

        /* Tag header is type+len */
        ttype = *(tag++);
        tlen = *(tag++);

        /* Tag length must fit within the option length */
        if (unlikely(tlen > len)) {
            //printf("CIPSO tag len too large %" PRIu8 " > %" PRIu16 "\n", tlen, len);
            ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
            return -1;
        }

        switch(ttype) {
            case 1:
            case 2:
            case 5:
            case 6:
            case 7:
                /* Tag is at least 4 and at most the remainder of option len */
                if (unlikely((tlen < 4) || (tlen > len))) {
                    //printf("CIPSO tag %" PRIu8 " bad tlen=%" PRIu8 " len=%" PRIu8 "\n", ttype, tlen, len);
                    ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
                    return -1;
                }

                /* The alignment octet is always 0 except tag
                 * type 7, which has no such field.
                 */
                if (unlikely((ttype != 7) && (*tag != 0))) {
                    //printf("CIPSO tag %" PRIu8 " ao=%" PRIu8 "\n", ttype, tlen);
                    ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
                    return -1;
                }

                /* Skip the rest of the tag payload */
                tag += tlen - 2;
                len -= tlen;

                continue;
            case 0:
                /* Tag type 0 is reserved and thus invalid */
                /** \todo Wireshark marks this a padding, but spec says reserved. */
                ENGINE_SET_INVALID_EVENT(p,IPV4_OPT_MALFORMED);
                return -1;
            default:
                //printf("CIPSO tag %" PRIu8 " unknown tag\n", ttype);
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_MALFORMED);
                /** \todo May not want to return error here on unknown tag type (at least not for 3|4) */
                return -1;
        }
    }

    return 0;
}

typedef struct IPV4Options_ {
    IPV4Opt o_rr;
    IPV4Opt o_qs;
    IPV4Opt o_ts;
    IPV4Opt o_sec;
    IPV4Opt o_lsrr;
    IPV4Opt o_cipso;
    IPV4Opt o_sid;
    IPV4Opt o_ssrr;
    IPV4Opt o_rtralt;
} IPV4Options;

static int DecodeIPV4Options(Packet *p, const uint8_t *pkt, uint16_t len, IPV4Options *opts)
{
    uint16_t plen = len;

    /* Options length must be padded to 8byte boundary */
    if (plen % 8) {
        ENGINE_SET_EVENT(p,IPV4_OPT_PAD_REQUIRED);
        /* Warn - we can keep going */
    }

    while (plen)
    {
        p->ip4vars.opt_cnt++;

        /* single byte options */
        if (*pkt == IPV4_OPT_EOL) {
            /** \todo What if more data exist after EOL (possible covert channel or data leakage)? */
            SCLogDebug("IPV4OPT %" PRIu8 " len 1 @ %d/%d",
                       *pkt, (len - plen), (len - 1));
            p->ip4vars.opts_set |= IPV4_OPT_FLAG_EOL;
            break;
        } else if (*pkt == IPV4_OPT_NOP) {
            /*SCLogDebug("IPV4OPT %" PRIu8 " len 1 @ %d/%d",
                       *pkt, (len - plen), (len - 1));*/
            pkt++;
            plen--;

            p->ip4vars.opts_set |= IPV4_OPT_FLAG_NOP;

            /* multibyte options */
        } else {
            if (unlikely(plen < 2)) {
                /** \todo What if padding is non-zero (possible covert channel or data leakage)? */
                /** \todo Spec seems to indicate EOL required if there is padding */
                ENGINE_SET_EVENT(p,IPV4_OPT_EOL_REQUIRED);
                break;
            }

            /* Option length is too big for packet */
            if (unlikely(*(pkt+1) > plen)) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }

            IPV4Opt opt = {*pkt, *(pkt+1), plen > 2 ? (pkt + 2) : NULL };

            /* we already know that the total options len is valid,
             * so here the len of the specific option must be bad.
             * Also check for invalid lengths 0 and 1. */
            if (unlikely(opt.len > plen || opt.len < 2)) {
                ENGINE_SET_INVALID_EVENT(p, IPV4_OPT_INVALID_LEN);
                return -1;
            }
            /* we are parsing the most commonly used opts to prevent
             * us from having to walk the opts list for these all the
             * time. */
            /** \todo Figure out which IP options are more common and list them first */
            switch (opt.type) {
                case IPV4_OPT_TS:
                    if (opts->o_ts.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateTimestamp(p, &opt) == 0) {
                        opts->o_ts = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_TS;
                    }
                    break;
                case IPV4_OPT_RR:
                    if (opts->o_rr.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateRoute(p, &opt) == 0) {
                        opts->o_rr = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_RR;
                    }
                    break;
                case IPV4_OPT_QS:
                    if (opts->o_qs.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(p, &opt) == 0) {
                        opts->o_qs = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_QS;
                    }
                    break;
                case IPV4_OPT_SEC:
                    if (opts->o_sec.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(p, &opt) == 0) {
                        opts->o_sec = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_SEC;
                    }
                    break;
                case IPV4_OPT_LSRR:
                    if (opts->o_lsrr.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateRoute(p, &opt) == 0) {
                        opts->o_lsrr = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_LSRR;
                    }
                    break;
                case IPV4_OPT_CIPSO:
                    if (opts->o_cipso.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateCIPSO(p, &opt) == 0) {
                        opts->o_cipso = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_CIPSO;
                    }
                    break;
                case IPV4_OPT_SID:
                    if (opts->o_sid.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(p, &opt) == 0) {
                        opts->o_sid = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_SID;
                    }
                    break;
                case IPV4_OPT_SSRR:
                    if (opts->o_ssrr.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateRoute(p, &opt) == 0) {
                        opts->o_ssrr = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_SSRR;
                    }
                    break;
                case IPV4_OPT_RTRALT:
                    if (opts->o_rtralt.type != 0) {
                        ENGINE_SET_EVENT(p,IPV4_OPT_DUPLICATE);
                        /* Warn - we can keep going */
                    } else if (IPV4OptValidateGeneric(p, &opt) == 0) {
                        opts->o_rtralt = opt;
                        p->ip4vars.opts_set |= IPV4_OPT_FLAG_RTRALT;
                    }
                    break;
                default:
                    SCLogDebug("IPV4OPT <unknown> (%" PRIu8 ") len %" PRIu8,opt.type, opt.len);
                    ENGINE_SET_EVENT(p,IPV4_OPT_INVALID);
                    /* Warn - we can keep going */
                    break;
            }

            pkt += opt.len;
            plen -= opt.len;
        }
    }

    return 0;
}

static int DecodeIPV4Packet(Packet *p, const uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < IPV4_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_PKT_TOO_SMALL);
        return -1;
    }

    if (unlikely(IP_GET_RAW_VER(pkt) != 4)) {
        SCLogDebug("wrong ip version %d",IP_GET_RAW_VER(pkt));
        ENGINE_SET_INVALID_EVENT(p, IPV4_WRONG_IP_VER);
        return -1;
    }

    p->ip4h = (IPV4Hdr *)pkt;

    if (unlikely(IPV4_GET_HLEN(p) < IPV4_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_HLEN_TOO_SMALL);
        return -1;
    }

    if (unlikely(IPV4_GET_IPLEN(p) < IPV4_GET_HLEN(p))) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_IPLEN_SMALLER_THAN_HLEN);
        return -1;
    }

    if (unlikely(len < IPV4_GET_IPLEN(p))) {
        ENGINE_SET_INVALID_EVENT(p, IPV4_TRUNC_PKT);
        return -1;
    }

    /* set the address struct */
    SET_IPV4_SRC_ADDR(p,&p->src);
    SET_IPV4_DST_ADDR(p,&p->dst);

    /* save the options len */
    uint8_t ip_opt_len = IPV4_GET_HLEN(p) - IPV4_HEADER_LEN;
    if (ip_opt_len > 0) {
        IPV4Options opts;
        memset(&opts, 0x00, sizeof(opts));
        if (DecodeIPV4Options(p, pkt + IPV4_HEADER_LEN, ip_opt_len, &opts) < 0) {
            return -1;
        }
    }

    return 0;
}

int DecodeIPV4(ThreadVars* tv,Packet *p,const uint8_t *pkt, uint16_t len)
{
    tv->counter_ipv4++;

    //ipv4数据包解析
    if (unlikely(DecodeIPV4Packet (p, pkt, len) < 0)) {
        SCLogDebug("decoding IPv4 packet failed");
        CLEAR_IPV4_PACKET((p));
        return TM_ECODE_FAILED;
    }
    p->proto = IPV4_GET_IPPROTO(p);

    /* If a fragment, pass off for re-assembly. */
    /*if (unlikely(IPV4_GET_IPOFFSET(p) > 0 || IPV4_GET_MF(p) == 1)) {
        Packet *rp = Defrag(p);
        if (rp != NULL) {
            PacketEnqueueNoLock(&tv->decode_pq, rp);
        }
        p->flags |= PKT_IS_FRAGMENT;
        return TM_ECODE_OK;
    }*/

#ifdef DEBUG
    /* debug print */
    char s[16], d[16];
    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), s, sizeof(s));
    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), d, sizeof(d));
    SCLogDebug("IPV4 %s->%s PROTO: %" PRIu32 " OFFSET: %" PRIu32 " RF: %" PRIu32 " DF: %" PRIu32 " MF: %" PRIu32 " ID: %" PRIu32 "", s,d,
            IPV4_GET_IPPROTO(p), IPV4_GET_IPOFFSET(p), IPV4_GET_RF(p),
            IPV4_GET_DF(p), IPV4_GET_MF(p), IPV4_GET_IPID(p));
#endif /* DEBUG */

    switch (IPV4_GET_IPPROTO(p)) {
        case IPPROTO_TCP:
            tv->counter_tcp++;//统计tcp数据包个数
            DecodeTCP(tv,p, pkt + IPV4_GET_HLEN(p),
                      IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p));
            break;
        case IPPROTO_UDP:
            tv->counter_udp++;//统计udp数据包个数
            DecodeUDP(tv,p, pkt + IPV4_GET_HLEN(p),
                      IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p));
            break;
        case IPPROTO_ICMP:
            tv->counter_icmpv4++;//统计icmp数据包个数
            //TODO:comment by haolipeng
            //DecodeICMPV4(p, pkt + IPV4_GET_HLEN(p),IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p));
            break;
        default:
            tv->counter_others++;//统计other数据包个数
            break;
    }

    return TM_ECODE_OK;
}

