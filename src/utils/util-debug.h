#ifndef NET_THREAT_DETECT_UTIL_DEBUG_H
#define NET_THREAT_DETECT_UTIL_DEBUG_H

#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include "util-error.h"

typedef enum {
    SC_LOG_NOTSET = -1,
    SC_LOG_NONE = 0,
    SC_LOG_EMERGENCY,
    SC_LOG_ALERT,
    SC_LOG_CRITICAL,
    SC_LOG_ERROR,
    SC_LOG_WARNING,
    SC_LOG_NOTICE,
    SC_LOG_INFO,
    SC_LOG_PERF,
    SC_LOG_CONFIG,
    SC_LOG_DEBUG,
    SC_LOG_LEVEL_MAX,
} SCLogLevel;

/* The default log level, if it is not supplied by the user */
#define SC_LOG_DEF_LOG_LEVEL SC_LOG_INFO

/* The maximum length of the log message */
#define SC_LOG_MAX_LOG_MSG_LEN 2048

/* The default log_format, if it is not supplied by the user */
#define SC_LOG_DEF_LOG_FORMAT_REL "%t - <%d> - "
#define SC_LOG_DEF_LOG_FORMAT_DEV "[%i] %t - (%f:%l) <%d> (%n) -- "

/* The default output interface to be used */
#define SC_LOG_DEF_LOG_OP_IFACE SC_LOG_OP_IFACE_CONSOLE

/**
 * \brief The various output interfaces supported
 */
typedef enum {
    SC_LOG_OP_IFACE_CONSOLE,
    SC_LOG_OP_IFACE_FILE,
    SC_LOG_OP_IFACE_SYSLOG,
    SC_LOG_OP_IFACE_MAX,
} SCLogOPIface;

typedef enum {
    SC_LOG_OP_TYPE_REGULAR = 0,
    SC_LOG_OP_TYPE_JSON,
} SCLogOPType;
/**
 * \brief The output interface context for the logging module
 */
typedef struct SCLogOPIfaceCtx_ {
    SCLogOPIface iface;

    int16_t use_color;
    int16_t type;

    /* the output file to be used if the interface is SC_LOG_IFACE_FILE */
    const char *file;
    /* the output file descriptor for the above file */
    //FILE * file_d;

    /* registered to be set on a file rotation signal */
    int rotation_flag;

    /* the facility code if the interface is SC_LOG_IFACE_SYSLOG */
    int facility;

    /* override for the global_log_level */
    SCLogLevel log_level;

    /* override for the global_log_format(currently not used) */
    const char *log_format;

    /* Mutex used for locking around rotate/write to a file. */
    pthread_mutex_t fp_mutex;

    struct SCLogOPIfaceCtx_ *next;
} SCLogOPIfaceCtx;

/**
 * \brief Structure containing init data, that would be passed to
 *        SCInitDebugModule()
 */
typedef struct SCLogInitData_ {
    /* startup message */
    const char *startup_message;

    /* the log level */
    SCLogLevel global_log_level;

    /* the log format */
    const char *global_log_format;

    /* output filter */
    const char *op_filter;

    /* list of output interfaces to be used */
    SCLogOPIfaceCtx *op_ifaces;
    /* no of op ifaces */
    uint8_t op_ifaces_cnt;
} SCLogInitData;

typedef struct SCLogConfig_ {
    char *startup_message;
    SCLogLevel log_level;
    char *log_format;

    char *op_filter;

    /* op ifaces used */
    SCLogOPIfaceCtx *op_ifaces;

    /* no of op ifaces */
    uint8_t op_ifaces_cnt;
} SCLogConfig;

/* The different log format specifiers supported by the API */
#define SC_LOG_FMT_TIME             't' /* Timestamp in standard format */
#define SC_LOG_FMT_PID              'p' /* PID */
#define SC_LOG_FMT_TID              'i' /* Thread ID */
#define SC_LOG_FMT_TM               'm' /* Thread module name */
#define SC_LOG_FMT_LOG_LEVEL        'd' /* Log level */
#define SC_LOG_FMT_FILE_NAME        'f' /* File name */
#define SC_LOG_FMT_LINE             'l' /* Line number */
#define SC_LOG_FMT_FUNCTION         'n' /* Function */

/* The log format prefix for the format specifiers */
#define SC_LOG_FMT_PREFIX           '%'

#define ATTR_FMT_PRINTF(x, y) __attribute__((format(printf, (x), (y))))

extern SCLogLevel sc_log_global_log_level;

extern int sc_log_module_initialized;

extern int sc_log_module_cleaned;

SCError SCLogMessage(const SCLogLevel, const char *, const unsigned int,
                     const char *, const SCError, const char *message);

void SCLog(int x, const char *file, const char *func, const int line,
           const char *fmt, ...) ATTR_FMT_PRINTF(5,6);
void SCLogErr(int x, const char *file, const char *func, const int line,
              const int err, const char *fmt, ...) ATTR_FMT_PRINTF(6,7);

#define SCLogNotice(...) SCLog(SC_LOG_NOTICE, \
        __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define SCLogError(err_code, ...) SCLogErr(SC_LOG_ERROR, \
        __FILE__, __FUNCTION__, __LINE__, \
        err_code, __VA_ARGS__)

#define SCLogInfo(...) SCLog(SC_LOG_INFO, \
        __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define SCLogPerf(...) SCLog(SC_LOG_PERF, \
        __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define FatalError(x, ...) do {                                             \
    SCLogError(x, __VA_ARGS__);                                             \
    exit(EXIT_FAILURE);                                                     \
} while(0)

#define SCLogWarning(err_code, ...) SCLogErr(SC_LOG_WARNING, \
        __FILE__, __FUNCTION__, __LINE__, \
        err_code, __VA_ARGS__)

#define SCLogConfig(...) SCLog(SC_LOG_CONFIG, \
        __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define FatalErrorOnInit(x, ...) FatalError(x, __VA_ARGS__)

/* Avoid the overhead of using the debugging subsystem, in production mode */
#ifndef DEBUG
  #define SCLogDebug(...)                 do { } while (0)
/* Please use it only for debugging purposes */
#else
  #define SCLogDebug(...)       SCLog(SC_LOG_DEBUG, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#endif

void SCLogInitLogModule(SCLogInitData *);
#endif //NET_THREAT_DETECT_UTIL_DEBUG_H
