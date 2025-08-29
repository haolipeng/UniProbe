#ifndef NET_THREAT_DETECT_STREAM_TCP_SACK_H
#define NET_THREAT_DETECT_STREAM_TCP_SACK_H

#include "stream-tcp-private.h"

static inline uint32_t StreamTcpSackedSize(TcpStream *stream)
{
    return stream->sack_size;
}

int StreamTcpSackUpdatePacket(TcpStream *, Packet *);
void StreamTcpSackPruneList(TcpStream *);

#endif //NET_THREAT_DETECT_STREAM_TCP_SACK_H
