#ifndef NET_THREAT_DETECT_RUNMODE_AF_PACKET_H
#define NET_THREAT_DETECT_RUNMODE_AF_PACKET_H

typedef void *(*ConfigIfaceParserFunc) (const char *);

int RunModeIdsAFPSingle(void);
void RunModeIdsAFPRegister(void);

const char *RunModeAFPGetDefaultMode(void);
#endif //NET_THREAT_DETECT_RUNMODE_AF_PACKET_H
