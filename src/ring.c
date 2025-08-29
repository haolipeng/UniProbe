#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include "common.h"
#include "apis.h"
#include "base.h"
#include "dpi/dpi_entry.h"
#include "utils/helper.h"
#include "utils/util-debug.h"

#define ERR_UNSUPPORT_v3 (-255)
#define MAX_TSO_SIZE 65536

static uint8_t g_tso_packet[MAX_TSO_SIZE];

int afpacket_ring_bind(int fd, const char *iface)
{
    struct sockaddr_ll ll;
    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex = (int)if_nametoindex(iface);
    ll.sll_hatype = 0;
    ll.sll_pkttype = 0;
    ll.sll_halen = 0;

    return bind(fd, (struct sockaddr *)&ll, sizeof(ll));
}

//////////////////////////////////////afpacket v3版本//////////////////////////////////////////////
int af_packet_rx_v1(packet_context_t *ctx, uint32_t tick)
{
    io_ctx_t context;
    uint32_t count = 0;
    dp_ring_t *ring = &ctx->ring;

    //context.stats_slot = g_stats_slot;
    context.dp_ctx = ctx;
    context.tick = tick;

    while (count < ring->batch) {
        struct tpacket_hdr *tp;

        tp = (struct tpacket_hdr *)(ring->rx_map + ring->rx_offset);

        if ((tp->tp_status & TP_STATUS_USER) == 0) {
            return count;
        }

        count ++;

        if (unlikely(tp->tp_len != tp->tp_snaplen)) {
            if (tp->tp_status & TP_STATUS_COPY) {
                if (tp->tp_len <= MAX_TSO_SIZE) {
                    size_t len = recv(ctx->fd, g_tso_packet, MAX_TSO_SIZE, 0);
                    SCLogDebug("Recv large frame: len=%u from %s\n", len, ctx->name);

                    context.large_frame = true;
                    //处理接收的数据包
                    dpi_recv_packet(&context, g_tso_packet, (int)len);
                } else {
                    // read to consume
                    recv(ctx->fd, g_tso_packet, 1, 0);
                    SCLogDebug("Discard: len=%u snap=%u from %s\n",tp->tp_len, tp->tp_snaplen, ctx->name);
                }
            } else {
                SCLogDebug("Discard: len=%u snap=%u from %s\n",tp->tp_len, tp->tp_snaplen, ctx->name);
            }
        } else {
            context.large_frame = false;
            //处理接收的数据包
            dpi_recv_packet(&context, (uint8_t *)tp + tp->tp_mac, tp->tp_snaplen);
        }

        tp->tp_status = TP_STATUS_KERNEL;
        if (ctx->jumboframe) {
            ring->rx_offset = (ring->rx_offset + FRAME_SIZE_JUMBO_V1) & (ring->size - 1);
        } else {
            ring->rx_offset = (ring->rx_offset + FRAME_SIZE_V1) & (ring->size - 1);
        }
    }

    return DP_RX_MORE;
}

static void af_packet_stats_v1(int fd, dp_stats_t *stats)
{
    struct tpacket_stats s;
    socklen_t len;
    int err;

    len = sizeof(s);
    err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &s, &len);
    if (err < 0) {
        return;
    }

    stats->rx += s.tp_packets;
    stats->rx_drops += s.tp_drops;
}

//////////////////////////////////////afpacket v1版本//////////////////////////////////////////////
static int dp_ring_v1(int fd, const char *iface, dp_ring_t *ring, bool tap, bool jumboframe, uint blocks, uint batch)
{
    int enable = 1;
    // Discard malformed packets
    setsockopt(fd, SOL_PACKET, PACKET_LOSS, &enable, sizeof(enable));
    // Packet truncated indication
    setsockopt(fd, SOL_PACKET, PACKET_COPY_THRESH, &enable, sizeof(enable));

    struct tpacket_req *req = &ring->req;
    if (!tap && jumboframe){
        req->tp_block_size = BLOCK_SIZE_JUMBO_V1;
        req->tp_frame_size = FRAME_SIZE_JUMBO_V1;
    } else {
        req->tp_block_size = BLOCK_SIZE_V1;
        req->tp_frame_size = FRAME_SIZE_V1;
    }
    req->tp_block_nr = blocks;
    req->tp_frame_nr = (req->tp_block_size * blocks) / req->tp_frame_size;

    ring->size = req->tp_block_size * blocks;
    if (!tap) {
        ring->map_size = ring->size * 2;
    } else {
        ring->map_size = ring->size;
    }
    ring->batch = batch;

    setsockopt(fd, SOL_PACKET, PACKET_RX_RING, req, sizeof(*req));
    if (!tap) {
        setsockopt(fd, SOL_PACKET, PACKET_TX_RING, req, sizeof(*req));
    }

    ring->rx_map = mmap(NULL, ring->map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,fd, 0);
    if (ring->rx_map == MAP_FAILED) {
        SCLogError(SC_ERR_CAPTURE_PACKET,"fail to mmap (size=0x%x).\n", ring->map_size);
        close(fd);
        return -1;
    }

    ring->rx = af_packet_rx_v1;
    ring->stats = af_packet_stats_v1;
    return fd;
}

//////////////////////////////////////afpacket v3版本//////////////////////////////////////////////
static int af_packet_rx_v3(packet_context_t *ctx, uint32_t tick)
{
    io_ctx_t context;
    uint32_t count = 0;
    dp_ring_t *ring = &ctx->ring;

    context.dp_ctx = ctx;
    context.tick = tick;
    //context.stats_slot = g_stats_slot; //TODO:not finished
    //context.tap = ctx->tap;           //TODO:not finished
    mac_cpy(context.ep_mac.ether_addr_octet, ctx->ep_mac.ether_addr_octet);

    while (count < ring->batch) {
        struct tpacket_block_desc *desc;
        desc = (struct tpacket_block_desc *)(ring->rx_map + ring->rx_offset);
        if ((desc->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            return count;
        }

        if (unlikely(desc->hdr.bh1.block_status & TP_STATUS_COPY)) {
            SCLogError(SC_ERR_CAPTURE_PACKET,"Discard: status=0x%x len=%u from %s\n",
                         desc->hdr.bh1.block_status, desc->hdr.bh1.blk_len, ctx->name);
        } else {
            uint8_t *ptr = (uint8_t *)desc + desc->hdr.bh1.offset_to_first_pkt;
            uint32_t c = desc->hdr.bh1.num_pkts;
            count += c;

            // always consume the whole block
            uint32_t i;
            for (i = 0; i < c; i ++) {
                struct tpacket3_hdr *tp = (struct tpacket3_hdr *)ptr;
                dpi_recv_packet(&context, ptr + tp->tp_mac, tp->tp_snaplen);
                ptr += tp->tp_next_offset;
            }
        }

        desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
        ring->rx_offset = (ring->rx_offset + BLOCK_SIZE_V3) & (ring->size - 1);
    }

    return 0;
}

static void af_packet_stats_v3(int fd, dp_stats_t *stats)
{
    struct tpacket_stats_v3 s;
    socklen_t len;
    int err;

    len = sizeof(s);
    err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &s, &len);
    if (err < 0) {
        return;
    }

    stats->rx += s.tp_packets;
    stats->rx_drops += s.tp_drops;
}

static int dp_ring_v3(int fd, const char *iface, dp_ring_t *ring, bool tap, uint blocks, uint batch)
{
    int val = TPACKET_V3;
    //packet版本信息
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val))) {
        SCLogError(SC_ERR_CAPTURE_PACKET, "fail to set TPACKET_V3.\n");
        return ERR_UNSUPPORT_v3;
    }

    int enable = 1;
    // Discard malformed packets
    setsockopt(fd, SOL_PACKET, PACKET_LOSS, &enable, sizeof(enable));
    // Packet truncated indication
    setsockopt(fd, SOL_PACKET, PACKET_COPY_THRESH, &enable, sizeof(enable));

    struct tpacket_req3 *req = &ring->req3;
    req->tp_block_size = BLOCK_SIZE_V3;
    req->tp_frame_size = FRAME_SIZE_V3;
    req->tp_block_nr = blocks;
    req->tp_frame_nr = (req->tp_block_size * blocks) / req->tp_frame_size;
    req->tp_retire_blk_tov = 64;
    req->tp_sizeof_priv = 0;
    req->tp_feature_req_word = 0;
    ring->size = req->tp_block_size * blocks;
    ring->map_size = ring->size;
    ring->batch = batch;

    setsockopt(fd, SOL_PACKET, PACKET_RX_RING, req, sizeof(*req));

    ring->rx_map = mmap(NULL, ring->map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,fd, 0);
    if (ring->rx_map == MAP_FAILED) {
        SCLogError(SC_ERR_CAPTURE_PACKET, "fail to mmap (size=0x%x).\n", ring->map_size);
        close(fd);
        return -1;
    }

    ring->rx = af_packet_rx_v3;
    ring->stats = af_packet_stats_v3;
    return fd;
}

void close_socket(packet_context_t* ctx){
    munmap(ctx->ring.rx_map,ctx->ring.map_size);
    close(ctx->fd);
}

int open_socket(packet_context_t *ctx, const char *iface, bool tap, bool jumboframe, uint blocks, uint batch)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        SCLogError(SC_ERR_CAPTURE_PACKET,"fail to open socket.\n");
        return -1;
    }

    //v3版本的性能好,优先使用v3版本,不支持则改用v1版本
    int err = 0;
    err = dp_ring_v3(fd, iface, &ctx->ring, tap, blocks, batch);
    if(ERR_UNSUPPORT_v3 == err){
        err = dp_ring_v1(fd, iface, &ctx->ring, tap, jumboframe, blocks, batch);
    }
    //TODO:tap param is not need
    if (err < 0) {
        close(fd);
        return -1;
    }

    err = afpacket_ring_bind(fd, iface);
    if (err < 0) {
        close_socket(ctx);
        return -1;
    }

    return fd;
}

int net_rx(packet_context_t *ctx, uint32_t tick){
    int result = -1;
    if(ctx->ring.rx != NULL){
        result = ctx->ring.rx(ctx,tick);
    }else{
        SCLogError(SC_ERR_CAPTURE_PACKET, "ctx->ring.rx is NULL.");
    }
    return result;
}