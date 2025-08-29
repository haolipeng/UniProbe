//
// Created by haolipeng on 3/30/23.
//
#include <stdint.h>
#include <stddef.h>
#include "stream-tcp-inline.h"

/**
 *  \brief Compare the shared data portion of two segments
 *
 *  If no data is shared, 0 will be returned.
 *
 *  \param seg1 first segment
 *  \param seg2 second segment
 *
 *  \retval 0 shared data is the same (or no data is shared)
 *  \retval 1 shared data is different
 */
int StreamTcpInlineSegmentCompare(const TcpStream *stream,const Packet *p, const TcpSegment *seg)
{
    if (p == NULL || seg == NULL) {
        return (0);
    }

    const uint8_t *seg_data;
    uint32_t seg_datalen;
    StreamingBufferSegmentGetData(&stream->sb, &seg->sbseg, &seg_data, &seg_datalen);
    if (seg_data == NULL || seg_datalen == 0)
        return (0);

    const uint32_t pkt_seq = TCP_GET_SEQ(p);

    if (SEQ_EQ(pkt_seq, seg->seq) && p->payload_len == seg_datalen) {
        int r = SCMemcmp(p->payload, seg_data, seg_datalen);
        return (r);
    } else if (SEQ_GT(pkt_seq, (seg->seq + seg_datalen))) {
        return (0);
    } else if (SEQ_GT(seg->seq, (pkt_seq + p->payload_len))) {
        return (0);
    } else {
        SCLogDebug("p %u (%u), seg2 %u (%u)", pkt_seq,
                   p->payload_len, seg->seq, seg_datalen);

        uint32_t pkt_end = pkt_seq + p->payload_len;
        uint32_t seg_end = seg->seq + seg_datalen;
        SCLogDebug("pkt_end %u, seg_end %u", pkt_end, seg_end);

        /* get the minimal seg*_end */
        uint32_t end = (SEQ_GT(pkt_end, seg_end)) ? seg_end : pkt_end;
        /* and the max seq */
        uint32_t seq = (SEQ_LT(pkt_seq, seg->seq)) ? seg->seq : pkt_seq;

        SCLogDebug("seq %u, end %u", seq, end);

        uint16_t pkt_off = seq - pkt_seq;
        uint16_t seg_off = seq - seg->seq;
        SCLogDebug("pkt_off %u, seg_off %u", pkt_off, seg_off);

        uint32_t range = end - seq;
        SCLogDebug("range %u", range);
        BUG_ON(range > 65536);

        if (range) {
            int r = SCMemcmp(p->payload + pkt_off, seg_data + seg_off, range);
            return (r);
        }
        return (0);
    }
}
