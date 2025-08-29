#ifndef NET_THREAT_DETECT_APIS_H
#define NET_THREAT_DETECT_APIS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include "urcu/rculfhash.h"

typedef struct io_ctx_ {
    void *dp_ctx;
    uint32_t tick;//important!,必须赋值
    struct ether_addr ep_mac;
    bool large_frame;
    bool tap;
}io_ctx_t;

typedef struct io_counter_ {
    //ip,tcp,udp,icmp字段
    uint64_t pkt_id, err_pkts, ipv4_pkts, ipv6_pkts;
    uint64_t tcp_pkts, tcp_nosess_pkts; //tcp
    uint64_t udp_pkts, icmp_pkts, other_pkts;//udp,icmp,other
} io_counter_t;

extern __thread int THREAD_ID;
#endif //NET_THREAT_DETECT_APIS_H
