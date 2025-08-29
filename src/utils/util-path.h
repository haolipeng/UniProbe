#ifndef NET_THREAT_DETECT_UTIL_PATH_H
#define NET_THREAT_DETECT_UTIL_PATH_H

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef HAVE_NON_POSIX_MKDIR
#define SCMkDir(a, b) mkdir(a, b)
#else
#define SCMkDir(a, b) mkdir(a)
#endif

int PathIsAbsolute(const char *);
const char *SCBasename(const char *path);
int SCCreateDirectoryTree(const char *path, const bool final);
#endif //NET_THREAT_DETECT_UTIL_PATH_H
