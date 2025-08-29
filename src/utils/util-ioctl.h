#ifndef NET_THREAT_DETECT_UTIL_IOCTL_H
#define NET_THREAT_DETECT_UTIL_IOCTL_H

int GetIfaceMTU(const char *pcap_dev);
int GetIfaceMaxPacketSize(const char *pcap_dev);
#endif //NET_THREAT_DETECT_UTIL_IOCTL_H
