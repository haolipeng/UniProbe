//
// Created by haolipeng on 12/28/22.
//
#define _GNU_SOURCE
#define __USE_GNU
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <asm-generic/errno.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <bits/sched.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "apis.h"
#include "base.h"
#include "common.h"
#include "packet.h"
#include "ring.h"
#include "urcu/rcuhlist.h"
#include "utils/helper.h"
#include "utils/util-debug.h"

extern int g_threads;
bool g_running = false;

#define MAX_EPOLL_EVENTS 128
#define INLINE_BLOCK 2048
#define INLINE_BATCH 4096
#define TAP_BLOCK 512
#define TAP_BATCH 256

// For a context in free list, usually it can be release when all packets in the queue
// are processed, but there are cases that sessions send out RST after idling some
// time, ctx_inline is used in that case, so we can recycle pretty quickly.
#define RELEASED_CTX_PRUNE_FREQ 5   // 10 second

thread_data_t g_thread_data[MAX_THREADS];
#define per_core_ctx_list(thr_id)         (g_thread_data[thr_id].ctx_list)
#define per_core_ctx_free_list(thr_id)    (g_thread_data[thr_id].ctx_free_list)
#define per_core_epoll_fd(thr_id)         (g_thread_data[thr_id].epoll_fd)
#define per_core_ctx_inline(thr_id)       (g_thread_data[thr_id].ctx_inline)
#define per_core_ctrl_dp_lock(thr_id)     (g_thread_data[thr_id].ctrl_dp_lock)

//////////////////////全局变量//////////////////////
static uint32_t g_seconds;
//static time_t g_start_time;

////////////////////函数原型定义////////////////////
void* acs_data_thr(void* args);
void *acs_timer_thr(void *args);
int acs_data_add_port(const char *iface, bool jumboframe, int thr_id); //针对物理网口
int acs_data_add_tap(const char *netns, const char *iface, int thr_id);//针对容器虚拟接口
int acs_epoll_add_ctx(packet_context_t *ctx, int thr_id);

void acs_get_stats(packet_context_t *ctx)
{
    if(NULL != ctx->ring.stats){
        ctx->ring.stats(ctx->fd, &ctx->stats);
    }
}

int net_run(const char *in_iface){
    g_running = true;
    pthread_t dp_thr[MAX_THREADS];
    pthread_t timer_thr;
    int i,thr_id[MAX_THREADS],timer_thr_id;

    //1.create data thread
    for (i = 0; i < g_threads; i ++) {
        thr_id[i] = i;
        pthread_create(&dp_thr[i], NULL, acs_data_thr, &thr_id[i]);
    }

    //TODO:读取yaml配置文件，进行线程cpu亲合性绑定
    //2.create timer thread
    pthread_create(&timer_thr, NULL, acs_timer_thr, &timer_thr_id);

    //3.capture network traffic for nic
    //一个网口对应一个抓包线程,从0号线程开始使用
    if(NULL != in_iface){
        int target_thr_id = 0;
        sleep(2);

        //acs_data_add_tap("/proc/4547/ns/net", in_iface, 0);//TODO: test container capture
        acs_data_add_port(in_iface, false, target_thr_id);//pass thr_id 0
    }

    //4.thread join
    pthread_join(timer_thr,NULL);
    for (i = 0; i < g_threads; i++) {
        pthread_join(dp_thr[i],NULL);
    }

    return 0;
}

static packet_context_t *acs_lookup_context(struct cds_hlist_head *list, const char *name)
{
    packet_context_t *ctx;
    struct cds_hlist_node *itr;

    cds_hlist_for_each_entry_rcu(ctx, itr, list, link) {
        if (strcmp(ctx->name, name) == 0) {
            return ctx;
        }
    }

    return NULL;
}

packet_context_t *acs_alloc_context(const char *iface, int thr_id, bool tap, bool jumboframe, uint blocks, uint batch)
{
    int fd;
    packet_context_t *ctx;

    ctx = (packet_context_t *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    fd = open_socket(ctx, iface, tap, jumboframe, blocks, batch);
    if (fd < 0) {
        free(ctx);
        return NULL;
    }

    ctx->thr_id = thr_id;
    ctx->fd = fd;
    ctx->jumboframe = jumboframe;

    return ctx;
}


static int enter_netns(const char *netns)
{
    int curfd, netfd;

    if ((curfd = open("/proc/self/ns/net", O_RDONLY)) == -1) {
        SCLogError(SC_ERR_CAPTURE_PACKET,"failed to open current network namespace\n");
        return -1;
    }
    if ((netfd = open(netns, O_RDONLY)) == -1) {
        SCLogError(SC_ERR_CAPTURE_PACKET,"failed to open network namespace: netns=%s\n", netns);
        close(curfd);
        return -1;
    }
    if (setns(netfd, CLONE_NEWNET) == -1) {
        SCLogError(SC_ERR_CAPTURE_PACKET, "failed to enter network namespace: netns=%s error=%s\n", netns, strerror(errno));
        close(netfd);
        close(curfd);
        return -1;
    }
    close(netfd);
    return curfd;
}

static int restore_netns(int fd)
{
    if (setns(fd, CLONE_NEWNET) == -1) {
        SCLogError(SC_ERR_CAPTURE_PACKET, "failed to restore network namespace: error=%s\n", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static const char *get_tap_name(char *name, const char *netns, const char *iface)
{
    snprintf(name, CTX_NAME_LEN, "%s-%s", netns, iface);
    return name;
}

//bool get_ifhwaddr(sock, info.if_name, info.if_eth.if_ethmac, sizeof(info.if_eth.if_ethmac)

int acs_data_add_tap(const char *netns, const char *iface, int thr_id)
{
    int ret = 0;
    packet_context_t *ctx;

    thr_id = thr_id % MAX_THREADS;
    if(NULL == iface){
        SCLogError(SC_ERR_CAPTURE_PACKET, "iface can't be empty!\n");
        return -1;
    }

    if (per_core_epoll_fd(thr_id) == 0) {
        // TODO: May need to wait a while for dp thread ready
        SCLogError(SC_ERR_CAPTURE_PACKET, "epoll is not initiated, netns=%s thr_id=%d\n", netns, thr_id);
        return -1;
    }

    int curns_fd;
    //进入指定容器的网络命名空间
    if ((curns_fd = enter_netns(netns)) < 0) {
        return -1;
    }

    pthread_mutex_lock(&per_core_ctrl_dp_lock(thr_id));

    do {
        char name[CTX_NAME_LEN];
        get_tap_name(name, netns, iface);

        // get mac of tap interface
        int fd;
        struct ifreq ifr;
        unsigned char* ep_mac = NULL;

        fd = socket(AF_INET, SOCK_DGRAM,0);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name,iface,IF_NAMESIZE -1);

        ioctl(fd,SIOCGIFHWADDR,&ifr);
        close(fd);
        ep_mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;

        ctx = acs_lookup_context(&per_core_ctx_list(thr_id), name);
        if (ctx != NULL) {
            // handle mac address change
            ether_aton_r((const char*)ep_mac, &ctx->ep_mac);
            SCLogError(SC_ERR_CAPTURE_PACKET,"tap already exists, netns=%s iface=%s\n", netns, iface);
            break;
        }

        ctx = acs_alloc_context(iface, thr_id, true, false, TAP_BLOCK, TAP_BATCH);
        if (ctx == NULL) {
            ret = -1;
            break;
        }

        if (acs_epoll_add_ctx(ctx, thr_id) < 0) {
            close_socket(ctx);
            free(ctx);
            ret = -1;
            break;
        }

        // handle mac address change
        ether_aton_r((const char*)ep_mac, &ctx->ep_mac);
        strncpy(ctx->name, name, sizeof(ctx->name));
        cds_hlist_add_head_rcu(&ctx->link, &per_core_ctx_list(thr_id));
        SCLogDebug("tap added netns=%s iface=%s fd=%d\n", netns, iface, ctx->fd);
    } while (false);

    pthread_mutex_unlock(&per_core_ctrl_dp_lock(thr_id));

    restore_netns(curns_fd);

    return ret;
}

int acs_data_add_port(const char *iface, bool jumboframe, int thr_id)
{
    int ret = 0;
    packet_context_t *ctx;

    thr_id = thr_id % MAX_THREADS;

    //保证线程相关的epoll环境已初始化
    if (per_core_epoll_fd(thr_id) == 0) {
        //May need to wait a while for dp thread ready
        SCLogError(SC_ERR_CAPTURE_PACKET, "epoll is not initiated, iface=%s thr_id=%d\n", iface, thr_id);
        return -1;
    }

    //TODO:why add mutex lock, I don't know.
    pthread_mutex_lock(&per_core_ctrl_dp_lock(thr_id));//lock

    do {
        if (per_core_ctx_inline(thr_id) != NULL) {
            SCLogError(SC_ERR_CAPTURE_PACKET, "iface already exists, iface=%s\n", iface);
            break;
        }

        ctx = acs_alloc_context(iface, thr_id, false, jumboframe, INLINE_BLOCK, INLINE_BATCH);
        if (NULL == ctx) {
            ret = -1;
            break;
        }
        per_core_ctx_inline(thr_id) = ctx;

        strncpy(ctx->name, iface, sizeof(ctx->name));

        //TODO:add by haolipeng,juest for test
        ether_aton_r("01:0c:29:87:a4:02", &ctx->ep_mac);

        //将ctx节点加入到链表中
        cds_hlist_add_head_rcu(&ctx->link, &per_core_ctx_list(thr_id));
        SCLogDebug("added iface=%s fd=%d\n", iface, ctx->fd);
    } while (false);

    pthread_mutex_unlock(&per_core_ctrl_dp_lock(thr_id));//unlock

    return ret;
}

int acs_epoll_add_ctx(packet_context_t *ctx, int thr_id){
    ctx->ee.events = EPOLLIN;
    ctx->ee.data.ptr = ctx;
    if(epoll_ctl(per_core_epoll_fd(thr_id), EPOLL_CTL_ADD, ctx->fd, &ctx->ee) == -1){
        //If the fd already in the epoll,not return error.
        if(errno != EEXIST){
            SCLogError(SC_ERR_CAPTURE_PACKET, "fail to add socket to epoll: %s\n", strerror(errno));
            return -1;
        }
    }
    ctx->epoll = true;
    return 0;
}

int dp_epoll_remove_ctx(packet_context_t *ctx){
    if(!ctx->epoll){
        return 0;
    }

    if(epoll_ctl(per_core_epoll_fd(ctx->thr_id), EPOLL_CTL_DEL, ctx->fd, &ctx->ee) == -1){
        //failed to delete socket from epoll
        return -1;
    }

    ctx->epoll = false;
    return 0;
}

static void acs_remove_context(timer_node_t *node)
{
    packet_context_t *ctx = STRUCT_OF(node, packet_context_t, free_node);
    SCLogDebug("ctx=%s\n", ctx->name);
    close_socket(ctx);
    free(ctx);
}

// Not to release socket memory if 'kill' is false
static void acs_release_context(packet_context_t *ctx, bool kill)
{
    SCLogDebug("ctx=%s fd=%d\n", ctx->name, ctx->fd);

    cds_hlist_del(&ctx->link);
    dp_epoll_remove_ctx(ctx);

    if (kill) {
        close_socket(ctx);
        free(ctx);
    } else {
        SCLogDebug("add context to free list, ctx=%s, ts=%u\n", ctx->name, g_seconds);
        //TODO:add context to free list,wait timer trigger(or timeout) to remove some context
        timer_queue_append(&per_core_ctx_free_list(ctx->thr_id), &ctx->free_node, g_seconds);
        ctx->released = 1;
    }
}

//TODO:Not Finished because of timeout deal
void* acs_data_thr(void* args){
    struct epoll_event epoll_evs[MAX_EPOLL_EVENTS];
    uint32_t tmo;

    int thr_id = *(int*)args;
    thr_id = thr_id % MAX_THREADS;//value such as 0,1,2,3

    THREAD_ID = thr_id;//important

    //1.创建epoll文件描述符
    int epollfd = epoll_create(MAX_EPOLL_EVENTS);
    if(epollfd < 0){
        return  NULL;
    }
    per_core_epoll_fd(thr_id) = epollfd;

    //2.初始化mutext锁
    pthread_mutex_init(&per_core_ctrl_dp_lock(thr_id), NULL);

#define NO_WAIT 0
#define SHORT_WAIT 2
#define LONG_WAIT 1000
    tmo = SHORT_WAIT;
    //uint32_t last_seconds = g_seconds;

    while(g_running) {
        // Check if polling context exist, if yes, keep polling it.
        packet_context_t *polling_ctx = per_core_ctx_inline(thr_id);

        if (likely(polling_ctx != NULL)) {
            if (likely(net_rx(polling_ctx, g_seconds) == DP_RX_MORE)) {
                // If there are more packets to consume, not to add polling context to epoll,
                // use no-wait time out so we can get back to polling right away.
                tmo = NO_WAIT;
                polling_ctx = NULL;
            } else {
                // If all packets are consumed, add polling context to epoll, so once there is
                // a packet, it can be handled.
                if (acs_epoll_add_ctx(polling_ctx, thr_id) < 0) {
                    tmo = SHORT_WAIT;//wait short time
                    polling_ctx = NULL;
                } else {
                    tmo = LONG_WAIT;//wait long time
                }
            }
        }//end polling_ctx != NULL

        //epoll_wait等待事件，并进行处理
        int i,evs;
        evs = epoll_wait(per_core_epoll_fd(thr_id), epoll_evs, MAX_EPOLL_EVENTS, tmo);
        if(evs > 0){
            //遍历事件集合
            for(i = 0; i < evs; i++){
                struct epoll_event *ee = &epoll_evs[i];
                packet_context_t *ctx = ee->data.ptr;

                //处理不同的事件
                if( (ee->events & EPOLLHUP) || (ee->events & EPOLLERR) ){
                    //When switch mode,port is pulled first,then poll error happens first.
                    //ctx is more likely to be released here
                    if(ctx != polling_ctx){
                        pthread_mutex_lock(&per_core_ctrl_dp_lock(thr_id));
                        if (acs_lookup_context(&per_core_ctx_list(thr_id), ctx->name)) {
                            acs_release_context(ctx, false);
                        }
                        pthread_mutex_unlock(&per_core_ctrl_dp_lock(thr_id));
                    }
                }else if(ee->events & EPOLLIN){
                    net_rx(ctx, g_seconds);
                }
            }
        }//end if(evs > 0)

        if(NULL != polling_ctx){
            dp_epoll_remove_ctx(polling_ctx);
        }

        //TODO:超时处理
        /*if (unlikely(g_seconds - last_seconds >= 1)) {
            static int ctx_tick = 0;
            //ctx_tick bigger than 10 seconds
            if (++ ctx_tick >= RELEASED_CTX_PRUNE_FREQ) {
                acs_remove_context(thr_id);
                ctx_tick = 0;
            }

            last_seconds = g_seconds;
        }*/
    }

    close(per_core_epoll_fd(thr_id));
    per_core_epoll_fd(thr_id) = 0;
    SCLogDebug("dp thread exits\n");

    //TODO:need deal something
    return NULL;
}

int dp_read_ring_stats(dp_stats_t *s, int thr_id)
{
    packet_context_t *ctx;
    struct cds_hlist_node *itr;
    struct cds_hlist_head *list;

    thr_id = thr_id % MAX_THREADS;
    list = &per_core_ctx_list(thr_id);

    pthread_mutex_lock(&per_core_ctrl_dp_lock(thr_id));

    cds_hlist_for_each_entry_rcu(ctx, itr, list, link) {
        acs_get_stats(ctx);

        s->rx += ctx->stats.rx;
        s->rx_drops += ctx->stats.rx_drops;
    }

    pthread_mutex_unlock(&per_core_ctrl_dp_lock(thr_id));
    return 0;
}
/*
void *acs_timer_thr(void *args)
{
    g_start_time = time(NULL);
    while (g_running) {
        sleep(1);
        g_seconds ++;
        if ((g_seconds & 0x1f) == 0) {
            time_t time_elapsed = time(NULL) - g_start_time;
            if (time_elapsed > g_seconds) {
                DEBUG_TIMER("Advance timer for %us\n", time_elapsed - g_seconds);
                g_seconds = time_elapsed;
            }
        }
    }
    return NULL;
}*/

void *acs_timer_thr(void *args)
{
    while (g_running) {
        //定时检测pod上是否有端口增删 detect_port_create_or_miss
        sleep(5);
    }
    return NULL;
}