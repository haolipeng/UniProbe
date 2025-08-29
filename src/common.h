#ifndef NET_THREAT_DETECT_DP_COMMON_H
#define NET_THREAT_DETECT_DP_COMMON_H
#include <stdbool.h>
#include <sys/epoll.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include "urcu/hlist.h"
#include "base.h"
#include "utils/timer_queue.h"

typedef struct dp_stats_ {
    uint64_t rx;//接收字节数
    uint64_t rx_drops;//接收字节的丢包数
    //uint64_t tx_drops;
    //uint64_t tx;//发送字节数
} dp_stats_t;

struct packet_context_;//前置声明
typedef struct dp_ring_ {
    uint8_t *rx_map;
    uint32_t rx_offset;
    union {
        struct tpacket_req req; //v1 request
        struct tpacket_req3 req3;//v3 request
    };
    uint32_t size;
    uint32_t map_size;
    uint32_t batch;

    int (*rx)(struct packet_context_ *ctx, uint32_t tick);//接收数据的回调函数
    void (*stats)(int fd, dp_stats_t *stats);//
}dp_ring_t;

typedef struct packet_context_ {
    struct cds_hlist_node link;
    timer_node_t free_node;
    struct epoll_event ee;
    int fd;
#define CTX_NAME_LEN 64
    char name[CTX_NAME_LEN];
    dp_ring_t ring;
    dp_stats_t stats;
    struct ether_addr ep_mac;
    uint8_t thr_id  :4,//标识线程id
            released:1;
    bool epoll;         //
    bool jumboframe;    //巨帧
}packet_context_t;

//定义线程相关的数据成员
typedef struct thread_data_{
    int epoll_fd;
    packet_context_t *ctx_inline;
    pthread_mutex_t ctrl_dp_lock;
    struct cds_hlist_head ctx_list;
    timer_queue_t ctx_free_list;
}thread_data_t;

#define FRAME_SIZE_V1 (1024 * 2)
#define BLOCK_SIZE_V1 (FRAME_SIZE_V1 * 4)

#define FRAME_SIZE_JUMBO_V1 (1024 * 16)
#define BLOCK_SIZE_JUMBO_V1 (FRAME_SIZE_JUMBO_V1 * 2)

#define FRAME_SIZE_V3 (1024 * 2)
#define BLOCK_SIZE_V3 (1024 * 64)

#define DP_RX_DONE 0
#define DP_RX_MORE (-1)

#endif //NET_THREAT_DETECT_COMMON_H
