#include <string.h>
#include <linux/limits.h>
#include <errno.h>
#include "util-path.h"
#include "conf.h"

#ifdef OS_WIN32
#define DIRECTORY_SEPARATOR '\\'
#else
#define DIRECTORY_SEPARATOR '/'
#endif

int PathIsAbsolute(const char *path)
{
    if (strlen(path) > 1 && path[0] == '/') {
        return 1;
    }

    return 0;
}

const char *SCBasename(const char *path)
{
    if (!path || strlen(path) == 0)
        return NULL;

    char *final = strrchr(path, DIRECTORY_SEPARATOR);
    if (!final)
        return path;

    if (*(final + 1) == '\0')
        return NULL;

    return final + 1;
}

int SCDefaultMkDir(const char *path)
{
    return SCMkDir(path, S_IRWXU | S_IRGRP | S_IXGRP);
}

int SCCreateDirectoryTree(const char *path, const bool final)
{
    char pathbuf[PATH_MAX];
    char *p;
    size_t len = strlen(path);

    if (len > PATH_MAX - 1) {
        return -1;
    }

    strlcpy(pathbuf, path, sizeof(pathbuf));

    for (p = pathbuf + 1; *p; p++) {
        if (*p == '/') {
            /* Truncate, while creating directory */
            *p = '\0';

            if (SCDefaultMkDir(pathbuf) != 0) {
                if (errno != EEXIST) {
                    return -1;
                }
            }

            *p = '/';
        }
    }

    if (final) {
        if (SCDefaultMkDir(pathbuf) != 0) {
            if (errno != EEXIST) {
                return -1;
            }
        }
    }

    return 0;
}