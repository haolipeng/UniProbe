#ifndef NET_THREAT_DETECT_SOURCE_PCAP_FILE_H
#define NET_THREAT_DETECT_SOURCE_PCAP_FILE_H

#define CHECKSUM_SAMPLE_COUNT 1000ULL
#define CHECKSUM_INVALID_RATIO 10

void TmModuleReceivePcapFileRegister (void);
void TmModuleDecodePcapFileRegister (void);
void PcapFileGlobalInit(void);

#endif //NET_THREAT_DETECT_SOURCE_PCAP_FILE_H
