#ifndef NET_THREAT_DETECT_RING_H
#define NET_THREAT_DETECT_RING_H

#include "common.h"

//头文件包含区
int open_socket(packet_context_t *ctx, const char *iface, bool tap, bool jumboframe, uint blocks, uint batch);//申请socket
void close_socket(packet_context_t *ctx);//释放socket
int net_rx(packet_context_t *ctx, uint32_t tick);

#endif //NET_THREAT_DETECT_RING_H
