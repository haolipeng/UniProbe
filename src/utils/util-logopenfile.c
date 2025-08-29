#include <stdio.h>
#include <string.h>
#include <jansson.h>
#include <sys/stat.h>
#include "util-logopenfile.h"
#include "util-mem.h"
#include "util-debug.h"
#include "output/output.h"
#include "util-path.h"
#include "util-byte.h"
#include "util-conf.h"
#include "util-time.h"

// Threaded eve.json identifier
static SC_ATOMIC_DECL_AND_INIT_WITH_VAL(uint32_t, eve_file_id, 1);

static FILE * SCLogOpenFileFp(const char *path, const char *append_setting, uint32_t mode);

static inline void OutputWriteLock(pthread_mutex_t *m)
{
    SCMutexLock(m);
}

static int SCLogFileWrite(const char *buffer, int buffer_len, LogFileCtx *log_ctx)
{
    OutputWriteLock(&log_ctx->fp_mutex);
    int ret = 0;

#ifdef BUILD_WITH_UNIXSOCKET
    if (log_ctx->is_sock) {
        ret = SCLogFileWriteSocket(buffer, buffer_len, log_ctx);
    } else
#endif
    {

        /* Check for rotation. */
        if (log_ctx->rotation_flag) {
            log_ctx->rotation_flag = 0;
            SCConfLogReopen(log_ctx);
        }

        if (log_ctx->flags & LOGFILE_ROTATE_INTERVAL) {
            time_t now = time(NULL);
            if (now >= log_ctx->rotate_time) {
                SCConfLogReopen(log_ctx);
                log_ctx->rotate_time = now + log_ctx->rotate_interval;
            }
        }

        if (log_ctx->fp) {
            clearerr(log_ctx->fp);
            if (1 != fwrite(buffer, buffer_len, 1, log_ctx->fp)) {
                /* Only the first error is logged */
                if (!log_ctx->output_errors) {
                    SCLogError(SC_ERR_LOG_OUTPUT, "%s error while writing to %s",
                               ferror(log_ctx->fp) ? strerror(errno) : "unknown error",
                               log_ctx->filename);
                }
                log_ctx->output_errors++;
            } else {
                fflush(log_ctx->fp);
            }
        }
    }

    SCMutexUnlock(&log_ctx->fp_mutex);

    return ret;
}

static int SCLogFileWriteNoLock(const char *buffer, int buffer_len, LogFileCtx *log_ctx)
{
    int ret = 0;

    BUG_ON(log_ctx->is_sock);

    /* Check for rotation. */
    if (log_ctx->rotation_flag) {
        log_ctx->rotation_flag = 0;
        SCConfLogReopen(log_ctx);
    }

    if (log_ctx->flags & LOGFILE_ROTATE_INTERVAL) {
        time_t now = time(NULL);
        if (now >= log_ctx->rotate_time) {
            SCConfLogReopen(log_ctx);
            log_ctx->rotate_time = now + log_ctx->rotate_interval;
        }
    }

    if (log_ctx->fp) {
        SCClearErrUnlocked(log_ctx->fp);
        if (1 != SCFwriteUnlocked(buffer, buffer_len, 1, log_ctx->fp)) {
            /* Only the first error is logged */
            if (!log_ctx->output_errors) {
                SCLogError(SC_ERR_LOG_OUTPUT, "%s error while writing to %s",
                           SCFerrorUnlocked(log_ctx->fp) ? strerror(errno) : "unknown error",
                           log_ctx->filename);
            }
            log_ctx->output_errors++;
        } else {
            SCFflushUnlocked(log_ctx->fp);
        }
    }

    return ret;
}

static void SCLogFileCloseNoLock(LogFileCtx *log_ctx)
{
    SCLogDebug("Closing %s", log_ctx->filename);
    if (log_ctx->fp)
        fclose(log_ctx->fp);

    if (log_ctx->output_errors) {
        /*SCLogError(SC_ERR_LOG_OUTPUT, "There were %"PRIu64" output errors to %s",
                log_ctx->output_errors, log_ctx->filename);*/
    }
}

static void SCLogFileClose(LogFileCtx *log_ctx)
{
    SCMutexLock(&log_ctx->fp_mutex);
    SCLogFileCloseNoLock(log_ctx);
    SCMutexUnlock(&log_ctx->fp_mutex);
}

LogFileCtx *LogFileNewCtx(void)
{
    LogFileCtx* lf_ctx;
    lf_ctx = (LogFileCtx*)SCCalloc(1, sizeof(LogFileCtx));

    if (lf_ctx == NULL)
        return NULL;

    lf_ctx->Write = SCLogFileWrite;
    lf_ctx->Close = SCLogFileClose;

    return lf_ctx;
}

int LogFileFreeCtx(LogFileCtx *lf_ctx)
{
    if (lf_ctx == NULL) {
        return (0);
    }

    if (lf_ctx->threaded) {
        SCMutexDestroy(&lf_ctx->threads->mutex);
        for(int i = 0; i < lf_ctx->threads->slot_count; i++) {
            if (lf_ctx->threads->lf_slots[i]) {
                OutputUnregisterFileRotationFlag(&lf_ctx->threads->lf_slots[i]->rotation_flag);
                lf_ctx->threads->lf_slots[i]->Close(lf_ctx->threads->lf_slots[i]);
                SCFree(lf_ctx->threads->lf_slots[i]->filename);
                SCFree(lf_ctx->threads->lf_slots[i]);
            }
        }
        SCFree(lf_ctx->threads->lf_slots);
        SCFree(lf_ctx->threads->append);
        SCFree(lf_ctx->threads);
    } else {
        if (lf_ctx->fp != NULL) {
            lf_ctx->Close(lf_ctx);
        }
        if (lf_ctx->parent) {
            SCMutexLock(&lf_ctx->parent->threads->mutex);
            lf_ctx->parent->threads->lf_slots[lf_ctx->id] = NULL;
            SCMutexUnlock(&lf_ctx->parent->threads->mutex);
        }
        SCMutexDestroy(&lf_ctx->fp_mutex);
    }

    if(lf_ctx->filename != NULL)
        SCFree(lf_ctx->filename);

    if (lf_ctx->sensor_name)
        SCFree(lf_ctx->sensor_name);

    if (!lf_ctx->threaded) {
        OutputUnregisterFileRotationFlag(&lf_ctx->rotation_flag);
    }

    SCFree(lf_ctx);

    return (1);
}

static bool LogFileThreadedName(
        const char *original_name, char *threaded_name, size_t len, uint32_t unique_id)
{
    const char *base = SCBasename(original_name);
    if (!base) {
        FatalError(SC_ERR_FATAL,
                   "Invalid filename for threaded mode \"%s\"; "
                   "no basename found.",
                   original_name);
    }

    /* Check if basename has an extension */
    char *dot = strrchr(base, '.');
    if (dot) {
        char *tname = SCStrdup(original_name);
        if (!tname) {
            return false;
        }

        /* Fetch extension location from original, not base
         * for update
         */
        dot = strrchr(original_name, '.');
        int dotpos = dot - original_name;
        tname[dotpos] = '\0';
        char *ext = tname + dotpos + 1;
        if (strlen(tname) && strlen(ext)) {
            snprintf(threaded_name, len, "%s.%u.%s", tname, unique_id, ext);
        } else {
            FatalError(SC_ERR_FATAL,
                       "Invalid filename for threaded mode \"%s\"; "
                       "filenames must include an extension, e.g: \"name.ext\"",
                       original_name);
        }
        SCFree(tname);
    } else {
        snprintf(threaded_name, len, "%s.%u", original_name, unique_id);
    }
    return true;
}

static bool LogFileNewThreadedCtx(LogFileCtx *parent_ctx, const char *log_path, const char *append, int thread_id)
{
    LogFileCtx *thread = SCCalloc(1, sizeof(LogFileCtx));
    if (!thread) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate thread file context slot %d", thread_id);
        return false;
    }

    *thread = *parent_ctx;
    char fname[NAME_MAX];
    if (!LogFileThreadedName(log_path, fname, sizeof(fname), SC_ATOMIC_ADD(eve_file_id, 1))) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to create threaded filename for log");
        goto error;
    }
    SCLogDebug("Thread open -- using name %s [replaces %s]", fname, log_path);
    thread->fp = SCLogOpenFileFp(fname, append, thread->filemode);
    if (thread->fp == NULL) {
        goto error;
    }
    thread->filename = SCStrdup(fname);
    if (!thread->filename) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to duplicate filename for context slot %d", thread_id);
        goto error;
    }

    thread->threaded = false;
    thread->parent = parent_ctx;
    thread->id = thread_id;
    thread->is_regular = true;
    thread->Write = SCLogFileWriteNoLock;
    thread->Close = SCLogFileCloseNoLock;
    OutputRegisterFileRotationFlag(&thread->rotation_flag);

    parent_ctx->threads->lf_slots[thread_id] = thread;
    return true;

    error:
    SC_ATOMIC_SUB(eve_file_id, 1);
    if (thread->fp) {
        thread->Close(thread);
    }
    if (thread) {
        SCFree(thread);
    }
    parent_ctx->threads->lf_slots[thread_id] = NULL;
    return false;
}

LogFileCtx *LogFileEnsureExists(LogFileCtx *parent_ctx, int thread_id)
{
    /* threaded output disabled */
    if (!parent_ctx->threaded)
        return parent_ctx;

    SCLogDebug("Adding reference %d to file ctx %p", thread_id, parent_ctx);
    SCMutexLock(&parent_ctx->threads->mutex);
    /* are there enough context slots already */
    if (thread_id < parent_ctx->threads->slot_count) {
        /* has it been opened yet? */
        if (!parent_ctx->threads->lf_slots[thread_id]) {
            SCLogDebug("Opening new file for %d reference to file ctx %p", thread_id, parent_ctx);
            LogFileNewThreadedCtx(parent_ctx, parent_ctx->filename, parent_ctx->threads->append, thread_id);
        }
        SCLogDebug("Existing file for %d reference to file ctx %p", thread_id, parent_ctx);
        SCMutexUnlock(&parent_ctx->threads->mutex);
        return parent_ctx->threads->lf_slots[thread_id];
    }

    /* ensure there's a slot for the caller */
    int new_size = MAX(parent_ctx->threads->slot_count << 1, thread_id + 1);
    SCLogDebug("Increasing slot count; current %d, trying %d",
               parent_ctx->threads->slot_count, new_size);
    LogFileCtx **new_array = SCRealloc(parent_ctx->threads->lf_slots, new_size * sizeof(LogFileCtx *));
    if (new_array == NULL) {
        /* Try one more time */
        SCLogDebug("Unable to increase file context array size to %d; trying %d",
                   new_size, thread_id + 1);
        new_size = thread_id + 1;
        new_array = SCRealloc(parent_ctx->threads->lf_slots, new_size * sizeof(LogFileCtx *));
    }

    if (new_array == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to increase file context array size to %d", new_size);
        SCMutexUnlock(&parent_ctx->threads->mutex);
        return NULL;
    }

    parent_ctx->threads->lf_slots = new_array;
    /* initialize newly added slots */
    for (int i = parent_ctx->threads->slot_count; i < new_size; i++) {
        parent_ctx->threads->lf_slots[i] = NULL;
    }
    parent_ctx->threads->slot_count = new_size;
    LogFileNewThreadedCtx(parent_ctx, parent_ctx->filename, parent_ctx->threads->append, thread_id);

    SCMutexUnlock(&parent_ctx->threads->mutex);

    return parent_ctx->threads->lf_slots[thread_id];
}

static bool
SCLogOpenThreadedFileFp(const char *log_path, const char *append, LogFileCtx *parent_ctx, int slot_count)
{
    parent_ctx->threads = SCCalloc(1, sizeof(LogThreadedFileCtx));
    if (!parent_ctx->threads) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate threads container");
        return false;
    }
    parent_ctx->threads->append = SCStrdup(append);
    if (!parent_ctx->threads->append) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate threads append setting");
        goto error_exit;
    }

    parent_ctx->threads->slot_count = slot_count;
    parent_ctx->threads->lf_slots = SCCalloc(slot_count, sizeof(LogFileCtx *));
    if (!parent_ctx->threads->lf_slots) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate thread slots");
        goto error_exit;
    }
    SCLogDebug("Allocated %d file context pointers for threaded array",
               parent_ctx->threads->slot_count);
    int slot = 1;
    for (; slot < parent_ctx->threads->slot_count; slot++) {
        if (!LogFileNewThreadedCtx(parent_ctx, log_path, append, slot)) {
            /* TODO: clear allocated entries [1, slot) */
            goto error_exit;
        }
    }
    SCMutexInit(&parent_ctx->threads->mutex, NULL);
    return true;

    error_exit:

    if (parent_ctx->threads->lf_slots) {
        SCFree(parent_ctx->threads->lf_slots);
    }
    if (parent_ctx->threads->append) {
        SCFree(parent_ctx->threads->append);
    }
    SCFree(parent_ctx->threads);
    parent_ctx->threads = NULL;
    return false;
}

int SCConfLogOpenGeneric(ConfNode *conf,LogFileCtx *log_ctx,const char *default_filename,int rotate)
{
    char log_path[PATH_MAX];
    const char *log_dir;
    const char *filename, *filetype;

    // Arg check
    if (conf == NULL || log_ctx == NULL || default_filename == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "SCConfLogOpenGeneric(conf %p, ctx %p, default %p) "
                   "missing an argument",
                   conf, log_ctx, default_filename);
        return -1;
    }
    if (log_ctx->fp != NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "SCConfLogOpenGeneric: previously initialized Log CTX "
                   "encountered");
        return -1;
    }

    // Resolve the given config
    filename = ConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL)
        filename = default_filename;

    log_dir = ConfigGetLogDirectory();

    if (PathIsAbsolute(filename)) {
        snprintf(log_path, PATH_MAX, "%s", filename);
    } else {
        snprintf(log_path, PATH_MAX, "%s/%s", log_dir, filename);
    }

    /* Rotate log file based on time */
    const char *rotate_int = ConfNodeLookupChildValue(conf, "rotate-interval");
    if (rotate_int != NULL) {
        time_t now = time(NULL);
        log_ctx->flags |= LOGFILE_ROTATE_INTERVAL;

        /* Use a specific time */
        if (strcmp(rotate_int, "minute") == 0) {
            log_ctx->rotate_time = now + SCGetSecondsUntil(rotate_int, now);
            log_ctx->rotate_interval = 60;
        } else if (strcmp(rotate_int, "hour") == 0) {
            log_ctx->rotate_time = now + SCGetSecondsUntil(rotate_int, now);
            log_ctx->rotate_interval = 3600;
        } else if (strcmp(rotate_int, "day") == 0) {
            log_ctx->rotate_time = now + SCGetSecondsUntil(rotate_int, now);
            log_ctx->rotate_interval = 86400;
        }

            /* Use a timer */
        else {
            log_ctx->rotate_interval = SCParseTimeSizeString(rotate_int);
            if (log_ctx->rotate_interval == 0) {
                FatalError(SC_ERR_FATAL,
                           "invalid rotate-interval value");
            }
            log_ctx->rotate_time = now + log_ctx->rotate_interval;
        }
    }

    filetype = ConfNodeLookupChildValue(conf, "filetype");
    if (filetype == NULL)
        filetype = DEFAULT_LOG_FILETYPE;

    const char *filemode = ConfNodeLookupChildValue(conf, "filemode");
    uint32_t mode = 0;
    if (filemode != NULL &&
        StringParseUint32(&mode, 8, strlen(filemode),
                          filemode) > 0) {
        log_ctx->filemode = mode;
    }

    const char *append = ConfNodeLookupChildValue(conf, "append");
    if (append == NULL)
        append = DEFAULT_LOG_MODE_APPEND;

    /* JSON flags */
    log_ctx->json_flags = JSON_PRESERVE_ORDER|JSON_COMPACT|
                          JSON_ENSURE_ASCII|JSON_ESCAPE_SLASH;

    ConfNode *json_flags = ConfNodeLookupChild(conf, "json");

    if (json_flags != 0) {
    }

    // Now, what have we been asked to open?
    if (strcasecmp(filetype, DEFAULT_LOG_FILETYPE) == 0 ||
               strcasecmp(filetype, "file") == 0) {
        log_ctx->is_regular = 1;
        if (!log_ctx->threaded) {//single thread
            log_ctx->fp = SCLogOpenFileFp(log_path, append, log_ctx->filemode);
            if (log_ctx->fp == NULL)
                return -1; // Error already logged by Open...Fp routine
        } else {
            if (!SCLogOpenThreadedFileFp(log_path, append, log_ctx, 1)) {
                return -1;
            }
        }
        if (rotate) {
            OutputRegisterFileRotationFlag(&log_ctx->rotation_flag);
        }
    } else {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                                                   "%s.filetype.  Expected \"regular\" (default), \"unix_stream\", "
                                                   "or \"unix_dgram\"",
                   conf->name);
    }
    log_ctx->filename = SCStrdup(log_path);
    if (unlikely(log_ctx->filename == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC,
                   "Failed to allocate memory for filename");
        return -1;
    }

    SCLogInfo("%s output device (%s) initialized: %s", conf->name, filetype,
              filename);

    return 0;
}

int SCConfLogReopen(LogFileCtx *log_ctx)
{
    if (!log_ctx->is_regular) {
        /* Not supported and not needed on non-regular files. */
        return 0;
    }

    if (log_ctx->filename == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                     "Can't re-open LogFileCtx without a filename.");
        return -1;
    }

    if (log_ctx->fp != NULL) {
        fclose(log_ctx->fp);
    }

    /* Reopen the file. Append is forced in case the file was not
     * moved as part of a rotation process. */
    SCLogDebug("Reopening log file %s.", log_ctx->filename);
    log_ctx->fp = SCLogOpenFileFp(log_ctx->filename, "yes", log_ctx->filemode);
    if (log_ctx->fp == NULL) {
        return -1; // Already logged by Open..Fp routine.
    }

    return 0;
}

static char *SCLogFilenameFromPattern(const char *pattern)
{
    char *filename = SCMalloc(PATH_MAX);
    if (filename == NULL) {
        return NULL;
    }

    int rc = SCTimeToStringPattern(time(NULL), pattern, filename, PATH_MAX);
    if (rc != 0) {
        SCFree(filename);
        return NULL;
    }

    return filename;
}

static FILE * SCLogOpenFileFp(const char *path, const char *append_setting, uint32_t mode)
{
    FILE *ret = NULL;

    char *filename = SCLogFilenameFromPattern(path);
    if (filename == NULL) {
        return NULL;
    }

    int rc = SCCreateDirectoryTree(filename, false);
    if (rc < 0) {
        SCFree(filename);
        return NULL;
    }

    if (ConfValIsTrue(append_setting)) {
        ret = fopen(filename, "a");
    } else {
        ret = fopen(filename, "w");
    }

    if (ret == NULL) {
        SCLogError(SC_ERR_FOPEN, "Error opening file: \"%s\": %s",
                   filename, strerror(errno));
    } else {
        if (mode != 0) {
            int r = chmod(filename, mode);
            if (r < 0) {
                SCLogWarning(SC_WARN_CHMOD, "Could not chmod %s to %o: %s",
                             filename, mode, strerror(errno));
            }
        }
    }

    SCFree(filename);
    return ret;
}