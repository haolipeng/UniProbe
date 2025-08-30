#ifndef NET_THREAT_DETECT_MAIN_H
#define NET_THREAT_DETECT_MAIN_H
#include <stdint.h>
#include <stdbool.h>

#include "modules/runmodes.h"

/* Engine stage/status*/
enum {
    SURICATA_INIT = 0,
    SURICATA_RUNTIME,
    SURICATA_DEINIT
};

extern volatile uint8_t suricata_ctl_flags;
/* runtime engine control flags */
#define SURICATA_STOP    (1 << 0)   /**< gracefully stop the engine: process all
                                     outstanding packets first */
#define SURICATA_DONE    (1 << 2)   /**< packets capture ended */

typedef struct SCInstance_ {
    enum RunModes run_mode;
    enum RunModes aux_run_mode;

    char pcap_dev[128];
    char *sig_file;
    int sig_file_exclusive;
    char *pid_filename;
    char *regex_arg;

    char *keyword_info;
    char *runmode_custom_mode;

    bool system;
    bool set_logdir;
    bool set_datadir;

    int delayed_detect;
    int disabled_detect;
    int daemon;
    int offline;
    int verbose;
    int checksum_validation;

    struct timeval start_time;

    const char *log_dir;
    const char *progname; /**< pointer to argv[0] */
    const char *conf_filename;
    char *strict_rule_parsing_string;
} SCInstance;

void EngineDone(void);
void EngineStop(void);
#endif //NET_THREAT_DETECT_MAIN_H
