#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>

#include "util-debug.h"
#include "common/common.h"
#include "utils/helper.h"
#include "util-enum.h"
#include "base.h"
#include "conf.h"

/* holds the string-enum mapping for the enums held in the table SCLogLevel */
SCEnumCharMap sc_log_level_map[ ] = {
        { "Not set",        SC_LOG_NOTSET},
        { "None",           SC_LOG_NONE },
        { "Emergency",      SC_LOG_EMERGENCY },
        { "Alert",          SC_LOG_ALERT },
        { "Critical",       SC_LOG_CRITICAL },
        { "Error",          SC_LOG_ERROR },
        { "Warning",        SC_LOG_WARNING },
        { "Notice",         SC_LOG_NOTICE },
        { "Info",           SC_LOG_INFO },
        { "Perf",           SC_LOG_PERF },
        { "Config",         SC_LOG_CONFIG },
        { "Debug",          SC_LOG_DEBUG },
        { NULL,             -1 }
};

/**
 * \brief Holds the config state for the logging module
 */
static SCLogConfig *sc_log_config = NULL;

/**
 * \brief Holds the global log level.  Is the same as sc_log_config->log_level
 */
SCLogLevel sc_log_global_log_level;

/**
 * \brief Used to indicate whether the logging module has been init or not
 */
int sc_log_module_initialized = 0;

/**
 * \brief Used to indicate whether the logging module has been cleaned or not
 */
int sc_log_module_cleaned = 0;

static SCError SCLogMessageGetBuffer(
        struct timeval *tval, int color, SCLogOPType type,
        char *buffer, size_t buffer_size,
        const char *log_format,

        const SCLogLevel log_level, const char *file,
        const unsigned int line, const char *function,
        const SCError error_code, const char *message)
{
    char *temp = buffer;
    const char *s = NULL;
    struct tm *tms = NULL;

    const char *redb = "";
    const char *red = "";
    const char *yellowb = "";
    const char *yellow = "";
    const char *green = "";
    const char *blue = "";
    const char *reset = "";
    if (color) {
        redb = "\x1b[1;31m";
        red = "\x1b[31m";
        yellowb = "\x1b[1;33m";
        yellow = "\x1b[33m";
        green = "\x1b[32m";
        blue = "\x1b[34m";
        reset = "\x1b[0m";
    }
    /* no of characters_written(cw) by snprintf */
    int cw = 0;

    BUG_ON(sc_log_module_initialized != 1);

    /* make a copy of the format string as it will be modified below */
    char local_format[strlen(log_format) + 1];
    strlcpy(local_format, log_format, sizeof(local_format));
    char *temp_fmt = local_format;
    char *substr = temp_fmt;

    while ( (temp_fmt = strchr(temp_fmt, SC_LOG_FMT_PREFIX)) ) {
        if ((temp - buffer) > SC_LOG_MAX_LOG_MSG_LEN) {
            return SC_OK;
        }
        switch(temp_fmt[1]) {
            case SC_LOG_FMT_TIME:
                temp_fmt[0] = '\0';

                struct tm local_tm;
                tms = localtime_r(&(tval->tv_sec), &local_tm);

                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%d/%d/%04d -- %02d:%02d:%02d%s",
                              substr, green, tms->tm_mday, tms->tm_mon + 1,
                              tms->tm_year + 1900, tms->tm_hour, tms->tm_min,
                              tms->tm_sec, reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_PID:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%u%s", substr, yellow, getpid(), reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_TID:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%lu%s", substr, yellow, SCGetThreadIdLong(), reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_TM:
                temp_fmt[0] = '\0';
/* disabled to prevent dead lock:
 * log or alloc (which calls log on error) can call TmThreadsGetCallingThread
 * which will lock tv_root_lock. This can happen while we already hold this
 * lock. */
#if 0
                ThreadVars *tv = TmThreadsGetCallingThread();
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - *msg),
                              "%s%s", substr, ((tv != NULL)? tv->name: "UNKNOWN TM"));
#endif
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s", substr, "N/A");
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_LOG_LEVEL:
                temp_fmt[0] = '\0';
                s = SCMapEnumValueToName(log_level, sc_log_level_map);
                if (s != NULL) {
                    if (log_level <= SC_LOG_ERROR)
                        cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                      "%s%s%s%s", substr, redb, s, reset);
                    else if (log_level == SC_LOG_WARNING)
                        cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                      "%s%s%s%s", substr, red, s, reset);
                    else if (log_level == SC_LOG_NOTICE)
                        cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                      "%s%s%s%s", substr, yellowb, s, reset);
                    else
                        cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                      "%s%s%s%s", substr, yellow, s, reset);
                } else {
                    cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s", substr, "INVALID");
                }
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_FILE_NAME:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%s%s", substr, blue, file, reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_LINE:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%u%s", substr, green, line, reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case SC_LOG_FMT_FUNCTION:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%s%s", substr, green, function, reset);
                if (cw < 0)
                    return SC_ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

        }
        temp_fmt++;
    }
    if ((temp - buffer) > SC_LOG_MAX_LOG_MSG_LEN) {
        return SC_OK;
    }
    cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer), "%s", substr);
    if (cw < 0) {
        return SC_ERR_SPRINTF;
    }
    temp += cw;
    if ((temp - buffer) > SC_LOG_MAX_LOG_MSG_LEN) {
        return SC_OK;
    }

    if (error_code != SC_OK) {
        cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                      "[%sERRCODE%s: %s%s%s(%s%d%s)] - ", yellow, reset, red, SCErrorToString(error_code), reset, yellow, error_code, reset);
        if (cw < 0) {
            return SC_ERR_SPRINTF;
        }
        temp += cw;
        if ((temp - buffer) > SC_LOG_MAX_LOG_MSG_LEN) {
            return SC_OK;
        }
    }

    const char *hi = "";
    if (error_code > SC_OK)
        hi = red;
    else if (log_level <= SC_LOG_NOTICE)
        hi = yellow;
    cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - buffer), "%s%s%s", hi, message, reset);
    if (cw < 0) {
        return SC_ERR_SPRINTF;
    }
    temp += cw;
    if ((temp - buffer) > SC_LOG_MAX_LOG_MSG_LEN) {
        return SC_OK;
    }

    return SC_OK;
}

static inline void SCLogPrintToStream(FILE *fd, char *msg)
{
    /* Would only happen if the log file failed to re-open during rotation. */
    if (fd == NULL) {
        return;
    }

    if (fprintf(fd, "%s\n", msg) < 0)
        printf("Error writing to stream using fprintf\n");

    fflush(fd);

    return;
}

SCError SCLogMessage(const SCLogLevel log_level, const char *file,
                     const unsigned int line, const char *function,
                     const SCError error_code, const char *message)
{
    char buffer[SC_LOG_MAX_LOG_MSG_LEN] = "";
    SCLogOPIfaceCtx *op_iface_ctx = NULL;

    if (sc_log_module_initialized != 1) {
        printf("Logging module not initialized.  Call SCLogInitLogModule() "
               "first before using the debug API\n");
        return SC_OK;
    }

    /* get ts here so we log the same ts to each output */
    struct timeval tval;
    gettimeofday(&tval, NULL);

    op_iface_ctx = sc_log_config->op_ifaces;
    while (op_iface_ctx != NULL) {
        if (log_level != SC_LOG_NOTSET && log_level > op_iface_ctx->log_level) {
            op_iface_ctx = op_iface_ctx->next;
            continue;
        }

        switch (op_iface_ctx->iface) {
            case SC_LOG_OP_IFACE_CONSOLE:
                if (SCLogMessageGetBuffer(&tval, op_iface_ctx->use_color, op_iface_ctx->type,
                                          buffer, sizeof(buffer),
                                          op_iface_ctx->log_format ?
                                          op_iface_ctx->log_format : sc_log_config->log_format,
                                          log_level, file, line, function,
                                          error_code, message) == 0)
                {
                    SCLogPrintToStream((log_level == SC_LOG_ERROR)? stderr: stdout, buffer);
                }
                break;
            default:
                break;
        }
        op_iface_ctx = op_iface_ctx->next;
    }
    return SC_OK;
}

void SCLog(int x, const char *file, const char *func, const int line,
           const char *fmt, ...)
{
  if (sc_log_global_log_level >= x)
  {
    char msg[SC_LOG_MAX_LOG_MSG_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    SCLogMessage(x, file, line, func, SC_OK, msg);
  }
}

void SCLogErr(int x, const char *file, const char *func, const int line,
              const int err, const char *fmt, ...)
{
    if (sc_log_global_log_level >= x)
    {
        char msg[SC_LOG_MAX_LOG_MSG_LEN];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
        SCLogMessage(x, file, line, func, err, msg);
    }
}

static inline void SCLogSetLogLevel(SCLogInitData *sc_lid, SCLogConfig *sc_lc)
{
    SCLogLevel log_level = SC_LOG_NOTSET;

    if (sc_lid != NULL) {
        log_level = sc_lid->global_log_level;
    }

    /* deal with the global_log_level to be used */
    if (log_level > SC_LOG_NOTSET && log_level < SC_LOG_LEVEL_MAX)
        sc_lc->log_level = log_level;
    else {
        sc_lc->log_level = SC_LOG_DEF_LOG_LEVEL;
        if (sc_lid != NULL) {
            printf("Warning: Invalid/No global_log_level assigned by user.  Falling "
                   "back on the default_log_level \"%s\"\n",
                   SCMapEnumValueToName(sc_lc->log_level, sc_log_level_map));
        }
    }

    /* we also set it to a global var, as it is easier to access it */
    sc_log_global_log_level = sc_lc->log_level;

    return;
}

static inline const char *SCLogGetDefaultLogFormat(void)
{
    return SC_LOG_DEF_LOG_FORMAT_DEV;
}

static inline void SCLogSetLogFormat(SCLogInitData *sc_lid, SCLogConfig *sc_lc)
{
    const char *format = NULL;

    /* deal with the global log format to be used */
    format = SCLogGetDefaultLogFormat();
    if (sc_lid != NULL) {
        printf("Warning: Invalid/No global_log_format supplied by user or format "
               "length exceeded limit  characters.  Falling back on "
               "default log_format \"%s\"\n",format);
    }

    if (format != NULL && (sc_lc->log_format = strdup(format)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    return;
}

static inline SCLogOPIfaceCtx *SCLogAllocLogOPIfaceCtx(void)
{
    SCLogOPIfaceCtx *iface_ctx = NULL;

    if ( (iface_ctx = malloc(sizeof(SCLogOPIfaceCtx))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogallocLogOPIfaceCtx. Exiting...");
    }
    memset(iface_ctx, 0, sizeof(SCLogOPIfaceCtx));

    return iface_ctx;
}

static inline SCLogOPIfaceCtx *SCLogInitConsoleOPIface(const char *log_format,
                                                       SCLogLevel log_level, SCLogOPType type)
{
    SCLogOPIfaceCtx *iface_ctx = SCLogAllocLogOPIfaceCtx();

    if (iface_ctx == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogInitConsoleOPIface. Exiting...");
    }

    iface_ctx->iface = SC_LOG_OP_IFACE_CONSOLE;
    iface_ctx->type = type;

    /* console log format is overridden by envvars */
    const char *tmp_log_format = log_format;

    if (tmp_log_format != NULL &&
        (iface_ctx->log_format = strdup(tmp_log_format)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    /* console log level is overridden by envvars */
    SCLogLevel tmp_log_level = log_level;
    iface_ctx->log_level = tmp_log_level;

    if (isatty(fileno(stdout)) && isatty(fileno(stderr))) {
        iface_ctx->use_color = TRUE;
    }

    return iface_ctx;
}

static inline void SCLogSetOPIface(SCLogInitData *sc_lid, SCLogConfig *sc_lc)
{
    SCLogOPIfaceCtx *op_ifaces_ctx = NULL;
    int op_iface = 0;

    if (sc_lid != NULL && sc_lid->op_ifaces != NULL) {
        sc_lc->op_ifaces = sc_lid->op_ifaces;
        sc_lid->op_ifaces = NULL;
        sc_lc->op_ifaces_cnt = sc_lid->op_ifaces_cnt;
    } else {
        op_iface = SC_LOG_DEF_LOG_OP_IFACE;
        if (sc_lid != NULL) {
            printf("Warning: Output_interface not supplied by user.  Falling "
                   "back on default_output_interface\n");
        }

        switch (op_iface) {
            case SC_LOG_OP_IFACE_CONSOLE:
                op_ifaces_ctx = SCLogInitConsoleOPIface(NULL, SC_LOG_LEVEL_MAX,0);
                break;
        }
        sc_lc->op_ifaces = op_ifaces_ctx;
        sc_lc->op_ifaces_cnt++;
    }
    return;
}

void SCLogInitLogModule(SCLogInitData *sc_lid)
{
    /* sc_log_config is a global variable */
    if ( (sc_log_config = malloc(sizeof(SCLogConfig))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCLogInitLogModule. Exiting...");
    }
    memset(sc_log_config, 0, sizeof(SCLogConfig));

    SCLogSetLogLevel(sc_lid, sc_log_config);
    SCLogSetLogFormat(sc_lid, sc_log_config);
    SCLogSetOPIface(sc_lid, sc_log_config);

    sc_log_module_initialized = 1;
    sc_log_module_cleaned = 0;

    //SCOutputPrint(sc_did->startup_message);
    return;
}
