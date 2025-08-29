#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "util-ioctl.h"
#include "conf.h"
#include "util-debug.h"
#include "decode/decode-ethernet.h"

int GetIfaceMTU(const char *pcap_dev)
{
#if defined SIOCGIFMTU
    struct ifreq ifr;
    int fd;

    (void)strlcpy(ifr.ifr_name, pcap_dev, sizeof(ifr.ifr_name));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return -1;
    }

    if (ioctl(fd, SIOCGIFMTU, (char *)&ifr) < 0) {
        SCLogWarning(SC_ERR_SYSCALL,"Failure when trying to get MTU via ioctl for '%s': %s (%d)",pcap_dev, strerror(errno), errno);
        close(fd);
        return -1;
    }
    close(fd);
    SCLogInfo("Found an MTU of %d for '%s'", ifr.ifr_mtu,pcap_dev);
    return ifr.ifr_mtu;
#else
    /* ioctl is not defined, let's pretend returning 0 is ok */
    return 0;
#endif
}

#define SLL_HEADER_LEN                16
static int GetIfaceMaxHWHeaderLength(const char *pcap_dev)
{
    if ((!strcmp("eth", pcap_dev))
        ||
        (!strcmp("br", pcap_dev))
        ||
        (!strcmp("bond", pcap_dev))
        ||
        (!strcmp("wlan", pcap_dev))
        ||
        (!strcmp("tun", pcap_dev))
        ||
        (!strcmp("tap", pcap_dev))
        ||
        (!strcmp("lo", pcap_dev))) {
        /* Add possible VLAN tag or Qing headers */
        return 8 + ETHERNET_HEADER_LEN;
    }

    if (!strcmp("ppp", pcap_dev))
        return SLL_HEADER_LEN;
    /* SLL_HEADER_LEN is the biggest one and
       add possible VLAN tag and Qing headers */
    return 8 + SLL_HEADER_LEN;
}

int GetIfaceMaxPacketSize(const char *pcap_dev)
{
    if ((pcap_dev == NULL) || strlen(pcap_dev) == 0)
        return 0;

    int mtu = GetIfaceMTU(pcap_dev);
    switch (mtu) {
        case 0:
        case -1:
            return 0;
    }
    int ll_header = GetIfaceMaxHWHeaderLength(pcap_dev);
    if (ll_header == -1) {
        /* be conservative, choose a big one */
        ll_header = 16;
    }
    return ll_header + mtu;
}
