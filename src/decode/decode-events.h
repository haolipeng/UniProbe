#ifndef __DECODE_EVENTS_H__
#define __DECODE_EVENTS_H__
#include <stdint.h>

/* packet decoder events */
enum {
    /* IPV4 EVENTS */
    IPV4_PKT_TOO_SMALL = 0,       /**< ipv4 pkt smaller than minimum header size */
    IPV4_HLEN_TOO_SMALL,          /**< ipv4 header smaller than minimum size */
    IPV4_IPLEN_SMALLER_THAN_HLEN, /**< ipv4 pkt len smaller than ip header size */
    IPV4_TRUNC_PKT,               /**< truncated ipv4 packet */

    /* IPV4 OPTIONS */
    IPV4_OPT_INVALID,      /**< invalid ip options */
    IPV4_OPT_INVALID_LEN,  /**< ip options with invalid len */
    IPV4_OPT_MALFORMED,    /**< malformed ip options */
    IPV4_OPT_PAD_REQUIRED, /**< pad bytes are needed in ip options */
    IPV4_OPT_EOL_REQUIRED, /**< "end of list" needed in ip options */
    IPV4_OPT_DUPLICATE,    /**< duplicated ip option */
    IPV4_OPT_UNKNOWN,      /**< unknown ip option */
    IPV4_WRONG_IP_VER,     /**< wrong ip version in ip options */
    IPV4_WITH_ICMPV6,      /**< IPv4 packet with ICMPv6 header */

    /* ICMP EVENTS */
    ICMPV4_PKT_TOO_SMALL,    /**< icmpv4 packet smaller than minimum size */
    ICMPV4_UNKNOWN_TYPE,     /**< icmpv4 unknown type */
    ICMPV4_UNKNOWN_CODE,     /**< icmpv4 unknown code */
    ICMPV4_IPV4_TRUNC_PKT,   /**< truncated icmpv4 packet */
    ICMPV4_IPV4_UNKNOWN_VER, /**< unknown version in icmpv4 packet*/

    /* ICMPv6 EVENTS */
    ICMPV6_UNKNOWN_TYPE,                /**< icmpv6 unknown type */
    ICMPV6_UNKNOWN_CODE,                /**< icmpv6 unknown code */
    ICMPV6_PKT_TOO_SMALL,               /**< icmpv6 smaller than minimum size */
    ICMPV6_IPV6_UNKNOWN_VER,            /**< unknown version in icmpv6 packet */
    ICMPV6_IPV6_TRUNC_PKT,              /**< truncated icmpv6 packet */
    ICMPV6_MLD_MESSAGE_WITH_INVALID_HL, /**< invalid MLD that doesn't have HL 1 */
    ICMPV6_UNASSIGNED_TYPE,             /**< unsassigned ICMPv6 type */
    ICMPV6_EXPERIMENTATION_TYPE,        /**< uprivate experimentation ICMPv6 type */

    /* IPV6 EVENTS */
    IPV6_PKT_TOO_SMALL,     /**< ipv6 packet smaller than minimum size */
    IPV6_TRUNC_PKT,         /**< truncated ipv6 packet */
    IPV6_TRUNC_EXTHDR,      /**< truncated ipv6 extension header */
    IPV6_EXTHDR_DUPL_FH,    /**< duplicated "fragment" header in ipv6 extension headers */
    IPV6_EXTHDR_USELESS_FH, /**< useless FH: offset 0 + no more fragments */
    IPV6_EXTHDR_DUPL_RH,    /**< duplicated "routing" header in ipv6 extension headers */
    IPV6_EXTHDR_DUPL_HH,    /**< duplicated "hop-by-hop" header in ipv6 extension headers */
    IPV6_EXTHDR_DUPL_DH,    /**< duplicated "destination" header in ipv6 extension headers */
    IPV6_EXTHDR_DUPL_AH,    /**< duplicated "authentication" header in ipv6 extension headers */
    IPV6_EXTHDR_DUPL_EH,    /**< duplicated "ESP" header in ipv6 extension headers */

    IPV6_EXTHDR_INVALID_OPTLEN,  /**< the opt len in an hop or dst hdr is invalid. */
    IPV6_WRONG_IP_VER,           /**< wrong version in ipv6 */
    IPV6_EXTHDR_AH_RES_NOT_NULL, /**< AH hdr reserved fields not null (rfc 4302) */

    IPV6_HOPOPTS_UNKNOWN_OPT,  /**< unknown HOP opt */
    IPV6_HOPOPTS_ONLY_PADDING, /**< all options in HOP opts are padding */
    IPV6_DSTOPTS_UNKNOWN_OPT,  /**< unknown DST opt */
    IPV6_DSTOPTS_ONLY_PADDING, /**< all options in DST opts are padding */

    IPV6_EXTHDR_RH_TYPE_0,       /**< RH 0 is deprecated as per rfc5095 */
    IPV6_EXTHDR_ZERO_LEN_PADN,   /**< padN w/o data (0 len) */
    IPV6_FH_NON_ZERO_RES_FIELD,  /**< reserved field not zero */
    IPV6_DATA_AFTER_NONE_HEADER, /**< data after 'none' (59) header */

    IPV6_UNKNOWN_NEXT_HEADER, /**< unknown/unsupported next header */
    IPV6_WITH_ICMPV4,         /**< IPv6 packet with ICMPv4 header */

    /* TCP EVENTS */
    TCP_PKT_TOO_SMALL,  /**< tcp packet smaller than minimum size */
    TCP_HLEN_TOO_SMALL, /**< tcp header smaller than minimum size */
    TCP_INVALID_OPTLEN, /**< invalid len in tcp options */

    /* TCP OPTIONS */
    TCP_OPT_INVALID_LEN, /**< tcp option with invalid len */
    TCP_OPT_DUPLICATE,   /**< duplicated tcp option */

    /* UDP EVENTS */
    UDP_PKT_TOO_SMALL,  /**< udp packet smaller than minimum size */
    UDP_HLEN_TOO_SMALL, /**< udp header smaller than minimum size */
    UDP_HLEN_INVALID,   /**< invalid len of upd header */
    UDP_LEN_INVALID,    /**< packet len in header is invalid */

    /* ETHERNET EVENTS */
    ETHERNET_PKT_TOO_SMALL, /**< ethernet packet smaller than minimum size */

    /* Fragmentation reasembly events. */
    IPV4_FRAG_PKT_TOO_LARGE,
    IPV6_FRAG_PKT_TOO_LARGE,
    IPV4_FRAG_OVERLAP,
    IPV6_FRAG_OVERLAP,
    IPV6_FRAG_INVALID_LENGTH,

    /* Fragment ignored due to internal error */
    IPV4_FRAG_IGNORED,
    IPV6_FRAG_IGNORED,

    /* generic events */
    GENERIC_TOO_MANY_LAYERS,

    /* END OF DECODE EVENTS ON SINGLE PACKET */
    DECODE_EVENT_PACKET_MAX = GENERIC_TOO_MANY_LAYERS,

    /* STREAM EVENTS */
    STREAM_3WHS_ACK_IN_WRONG_DIR,
    STREAM_3WHS_ASYNC_WRONG_SEQ,
    STREAM_3WHS_RIGHT_SEQ_WRONG_ACK_EVASION,
    STREAM_3WHS_SYNACK_IN_WRONG_DIRECTION,
    STREAM_3WHS_SYNACK_RESEND_WITH_DIFFERENT_ACK,
    STREAM_3WHS_SYNACK_RESEND_WITH_DIFF_SEQ,
    STREAM_3WHS_SYNACK_TOSERVER_ON_SYN_RECV,
    STREAM_3WHS_SYNACK_WITH_WRONG_ACK,
    STREAM_3WHS_SYNACK_FLOOD,
    STREAM_3WHS_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV,
    STREAM_3WHS_SYN_TOCLIENT_ON_SYN_RECV,
    STREAM_3WHS_WRONG_SEQ_WRONG_ACK,
    STREAM_3WHS_ACK_DATA_INJECT,
    STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW,
    STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW,
    STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK,
    STREAM_CLOSEWAIT_INVALID_ACK,
    STREAM_CLOSING_ACK_WRONG_SEQ,
    STREAM_CLOSING_INVALID_ACK,
    STREAM_EST_PACKET_OUT_OF_WINDOW,
    STREAM_EST_PKT_BEFORE_LAST_ACK,
    STREAM_EST_SYNACK_RESEND,
    STREAM_EST_SYNACK_RESEND_WITH_DIFFERENT_ACK,
    STREAM_EST_SYNACK_RESEND_WITH_DIFF_SEQ,
    STREAM_EST_SYNACK_TOSERVER,
    STREAM_EST_SYN_RESEND,
    STREAM_EST_SYN_RESEND_DIFF_SEQ,
    STREAM_EST_SYN_TOCLIENT,
    STREAM_EST_INVALID_ACK,
    STREAM_FIN_INVALID_ACK,
    STREAM_FIN1_ACK_WRONG_SEQ,
    STREAM_FIN1_FIN_WRONG_SEQ,
    STREAM_FIN1_INVALID_ACK,
    STREAM_FIN2_ACK_WRONG_SEQ,
    STREAM_FIN2_FIN_WRONG_SEQ,
    STREAM_FIN2_INVALID_ACK,
    STREAM_FIN_BUT_NO_SESSION,
    STREAM_FIN_OUT_OF_WINDOW,
    STREAM_FIN_SYN,
    STREAM_LASTACK_ACK_WRONG_SEQ,
    STREAM_LASTACK_INVALID_ACK,
    STREAM_RST_BUT_NO_SESSION,
    STREAM_TIMEWAIT_ACK_WRONG_SEQ,
    STREAM_TIMEWAIT_INVALID_ACK,
    STREAM_SHUTDOWN_SYN_RESEND,
    STREAM_PKT_INVALID_TIMESTAMP,
    STREAM_PKT_INVALID_ACK,
    STREAM_PKT_BROKEN_ACK,
    STREAM_RST_INVALID_ACK,
    STREAM_PKT_RETRANSMISSION,
    STREAM_PKT_BAD_WINDOW_UPDATE,

    STREAM_SUSPECTED_RST_INJECT,
    STREAM_WRONG_THREAD,

    STREAM_REASSEMBLY_SEGMENT_BEFORE_BASE_SEQ,
    STREAM_REASSEMBLY_NO_SEGMENT,
    STREAM_REASSEMBLY_SEQ_GAP,
    STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA,

    /* should always be last! */
    DECODE_EVENT_MAX,
};

#define EVENT_IS_DECODER_PACKET_ERROR(e)    \
    ((e) < (DECODE_EVENT_PACKET_MAX))

/* supported decoder events */

struct DecodeEvents_ {
    const char *event_name;
    uint8_t code;
};
/* +1 for the end of table marker */
extern const struct DecodeEvents_ DEvents[DECODE_EVENT_MAX + 1];

#endif /* __DECODE_EVENTS_H__ */