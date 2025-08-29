#ifndef NET_THREAT_DETECT_UTIL_LOGOPENFILE_H
#define NET_THREAT_DETECT_UTIL_LOGOPENFILE_H

#include <bits/types/FILE.h>
#include <stdbool.h>
#include <stdint.h>

#include "threads.h"
#include "conf.h"

#define LOGFILE_ROTATE_INTERVAL 0x04

enum LogFileType {
    LOGFILE_TYPE_FILE
};

struct LogFileCtx_;
typedef struct LogThreadedFileCtx_ {
    int slot_count;
    SCMutex mutex;
    struct LogFileCtx_ **lf_slots;
    char *append;
} LogThreadedFileCtx;

typedef struct LogFileCtx_ {
    union {
        FILE *fp;
        LogThreadedFileCtx *threads;
        void *plugin_data;
    };

    int (*Write)(const char *buffer, int buffer_len, struct LogFileCtx_ *fp);
    void (*Close)(struct LogFileCtx_ *fp);

    /** It will be locked if the log/alert
     * record cannot be written to the file in one call */
    SCMutex fp_mutex;

    /** When threaded, track of the parent and thread id */
    bool threaded;
    struct LogFileCtx_ *parent;
    int id;

    /** the type of file */
    enum LogFileType type;

    /** The name of the file */
    char *filename;

    /** File permissions */
    uint32_t filemode;

    /** Suricata sensor name */
    char *sensor_name;

    /** Handle auto-connecting / reconnecting sockets */
    int is_sock;
    int sock_type;
    uint64_t reconn_timer;

    /** The next time to rotate log file, if rotate interval is
        specified. */
    time_t rotate_time;

    /** The interval to rotate the log file */
    uint64_t rotate_interval;

    /** Generic size_limit and size_current
     * They must be common to the threads accessing the same file */
    uint64_t size_limit;    /**< file size limit */
    uint64_t size_current;  /**< file current size */

    /* flag to avoid multiple threads printing the same stats */
    uint8_t flags;

    /* flags to set when sending over a socket */
    uint8_t send_flags;

    /* Flag if file is a regular file or not.  Only regular files
     * allow for rotation. */
    uint8_t is_regular;

    /* JSON flags */
    size_t json_flags;  /* passed to json_dump_callback() */

    /* Flag set when file rotation notification is received. */
    int rotation_flag;

    /* Set to true if the filename should not be timestamped. */
    bool nostamp;

    /* if set to true EVE will add a pcap file record */
    bool is_pcap_offline;

    /* Socket types may need to drop events to keep from blocking
     * Suricata. */
    uint64_t dropped;

    uint64_t output_errors;
} LogFileCtx;

LogFileCtx *LogFileNewCtx(void);
int LogFileFreeCtx(LogFileCtx *);

LogFileCtx *LogFileEnsureExists(LogFileCtx *parent_ctx, int thread_id);
int SCConfLogOpenGeneric(ConfNode *conf, LogFileCtx *, const char *, int);
int SCConfLogReopen(LogFileCtx *);
#endif
