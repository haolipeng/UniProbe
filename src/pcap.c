//
// Created by haolipeng on 1/11/23.
//
#include "apis.h"
#include "decode/decode.h"
#include "dpi/dpi_entry.h"
#include <dirent.h>
#include <pcap/pcap.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

struct timeval g_now;
static struct timeval tv_diff(struct timeval s, struct timeval e)
{
    struct timeval d;
    if (e.tv_usec < s.tv_usec) {
        d.tv_sec = e.tv_sec - s.tv_sec - 1;
        d.tv_usec = 1000000 + e.tv_usec - s.tv_usec;
    } else {
        d.tv_sec = e.tv_sec - s.tv_sec;
        d.tv_usec = e.tv_usec - s.tv_usec;
    }
    return d;
}

static void pcap_packet(char *user, struct pcap_pkthdr *hdr, uint8_t *pkt)
{
    io_ctx_t context;
    struct timeval last_now = g_now;

    context.dp_ctx = NULL;
    g_now = hdr->ts;
    context.tick = g_now.tv_sec;
    context.tap = true;

    dpi_recv_packet(&context, pkt, hdr->caplen);

    struct timeval td = tv_diff(last_now, g_now);
    if (td.tv_sec > 0) {
        //TODO:not call dpi_timeout function
        //此处需要处理超时的情况
        //dpi_timeout(g_now.tv_sec);
    }
}

int pcap_run(const char *path)
{
    struct stat st;

    memset(&st, 0, sizeof(st));
    if (lstat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            DIR *dir = opendir(path);
            struct dirent *file;

            if (dir == NULL) {
                return -1;
            }

            while ((file = readdir(dir)) != NULL) {
                if (file->d_name[0] == '.') {
                    continue;
                }

                char dir_path[1024];
                snprintf(dir_path, sizeof(dir_path), "%s/%s", path, file->d_name);
                printf("Enter: %s\n", dir_path);
                pcap_run(dir_path);
            }
        } else {
            pcap_t *pcap;
            char err[PCAP_ERRBUF_SIZE];

            //打开pcap离线包
            pcap = pcap_open_offline(path, err);
            if (pcap == NULL) {
                printf("Cannot open g_pcap_path file: %s\n", path);
                return -1;
            }

            pcap_loop(pcap, -1, (pcap_handler)pcap_packet, NULL);

            pcap_close(pcap);

            return 0;
        }
    }

    return -1;
}