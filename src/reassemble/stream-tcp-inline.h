#ifndef NET_THREAT_DETECT_STREAM_TCP_INLINE_H
#define NET_THREAT_DETECT_STREAM_TCP_INLINE_H

#include "common/common.h"
#include "decode/decode.h"
#include "stream-tcp-private.h"

int StreamTcpInlineSegmentCompare(const TcpStream *, const Packet *, const TcpSegment *);

#endif //NET_THREAT_DETECT_STREAM_TCP_INLINE_H
