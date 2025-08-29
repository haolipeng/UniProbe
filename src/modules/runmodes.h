#ifndef NET_THREAT_DETECT_RUNMODES_H
#define NET_THREAT_DETECT_RUNMODES_H

#include <stdlib.h>
#include <string.h>
/* Run mode */
enum RunModes {
    RUNMODE_UNKNOWN = 0,
    RUNMODE_PCAP_DEV,
    RUNMODE_PCAP_FILE,
    RUNMODE_AFP_DEV,
    RUNMODE_UNIX_SOCKET,
    RUNMODE_USER_MAX, /* Last standard running mode */
    RUNMODE_MAX,
};

void RunModeRegisterNewRunMode(enum RunModes, const char *, const char *,
                               int (*RunModeFunc)(void));
void RunModeRegisterRunModes(void);
void RunModeDispatch(int runmode, const char *custom_mode);
char *RunmodeGetActive(void);

void RunModeInitializeOutputs(void);
#endif //NET_THREAT_DETECT_RUNMODES_H
