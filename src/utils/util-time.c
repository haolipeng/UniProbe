#include "threads.h"
#include "util-debug.h"
#include "modules/tm-threads.h"
#include "conf.h"
#include <stdbool.h>
#include <sys/time.h>
#include <stdio.h>

// static SCMutex current_time_mutex = SCMUTEX_INITIALIZER;
static SCSpinlock current_time_spinlock;
static bool live_time_tracking = true;

void TimeInit(void)
{
    SCSpinInit(&current_time_spinlock, 0);

    /* Initialize Time Zone settings. */
    tzset();
}

void TimeDeinit(void)
{
    SCSpinDestroy(&current_time_spinlock);
}

void TimeModeSetLive(void)
{
    live_time_tracking = true;
    SCLogDebug("live time mode enabled");
}

bool TimeModeIsReady(void)
{
    if (live_time_tracking)
        return true;
    return TmThreadsTimeSubsysIsReady();
}

bool TimeModeIsLive(void)
{
    return live_time_tracking;
}

void TimeGet(struct timeval *tv) {
  if (tv == NULL)
    return;

  if(live_time_tracking){
    gettimeofday(tv, NULL);
  }

  SCLogDebug("time we got is %" PRIuMAX " sec, %" PRIuMAX " usec",
             (uintmax_t)tv->tv_sec, (uintmax_t)tv->tv_usec);
}

struct tm *SCLocalTime(time_t timep, struct tm *result)
{
    return localtime_r(&timep, result);
}

void TimeSetByThread(const int thread_id, const struct timeval *tv)
{
    if (live_time_tracking)
        return;

    TmThreadsSetThreadTimestamp(thread_id, tv);
}

void TimeModeSetOffline (void)
{
    live_time_tracking = false;
    SCLogDebug("offline time mode enabled");
}

void CreateIsoTimeString (const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    memset(&local_tm, 0, sizeof(local_tm));
    struct tm *t = (struct tm*)SCLocalTime(time, &local_tm);

    if (likely(t != NULL)) {
        char time_fmt[64] = { 0 };
        int64_t usec = ts->tv_usec;
        strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%dT%H:%M:%S.%%06" PRIi64 "%z", t);
        snprintf(str, size, time_fmt, usec);
    } else {
        snprintf(str, size, "ts-error");
    }
}

int SCTimeToStringPattern (time_t epoch, const char *pattern, char *str, size_t size)
{
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    struct tm *tp = (struct tm *)SCLocalTime(epoch, &tm);
    char buffer[PATH_MAX] = { 0 };

    if (unlikely(tp == NULL)) {
        return 1;
    }

    int r = strftime(buffer, sizeof(buffer), pattern, tp);
    if (r == 0) {
        return 1;
    }

    strlcpy(str, buffer, size);

    return 0;
}

uint64_t SCParseTimeSizeString (const char *str)
{
    uint64_t size = 0;
    uint64_t modifier = 1;
    char last = str[strlen(str)-1];

    switch (last)
    {
        case '0' ... '9':
            break;
            /* seconds */
        case 's':
            break;
            /* minutes */
        case 'm':
            modifier = 60;
            break;
            /* hours */
        case 'h':
            modifier = 60 * 60;
            break;
            /* days */
        case 'd':
            modifier = 60 * 60 * 24;
            break;
            /* weeks */
        case 'w':
            modifier = 60 * 60 * 24 * 7;
            break;
            /* invalid */
        default:
            return 0;
    }

    errno = 0;
    size = strtoumax(str, NULL, 10);
    if (errno) {
        return 0;
    }

    return (size * modifier);
}

uint64_t SCGetSecondsUntil (const char *str, time_t epoch)
{
    uint64_t seconds = 0;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    struct tm *tp = (struct tm *)SCLocalTime(epoch, &tm);

    if (strcmp(str, "minute") == 0)
        seconds = 60 - tp->tm_sec;
    else if (strcmp(str, "hour") == 0)
        seconds = (60 * (60 - tp->tm_min)) + (60 - tp->tm_sec);
    else if (strcmp(str, "day") == 0)
        seconds = (3600 * (24 - tp->tm_hour)) + (60 * (60 - tp->tm_min)) +
                  (60 - tp->tm_sec);

    return seconds;
}