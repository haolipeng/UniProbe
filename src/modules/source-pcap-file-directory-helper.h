
#ifndef NET_THREAT_DETECT_SOURCE_PCAP_FILE_DIRECTORY_HELPER_H
#define NET_THREAT_DETECT_SOURCE_PCAP_FILE_DIRECTORY_HELPER_H

#include <bits/types/struct_timespec.h>
#include <dirent.h>
#include "utils/queue.h"
#include "source-pcap-file-helper.h"

typedef struct PendingFile_
{
    char *filename;
    struct timespec modified_time;
    TAILQ_ENTRY(PendingFile_) next;
} PendingFile;
/**
 * Data specific to a directory of pcap files
 */
typedef struct PcapFileDirectoryVars_
{
    char *filename;
    DIR *directory;
    PcapFileFileVars *current_file;
    bool should_loop;
    bool should_recurse;
    uint8_t cur_dir_depth;
    time_t delay;
    time_t poll_interval;

    TAILQ_HEAD(PendingFiles, PendingFile_) directory_content;

    PcapFileSharedVars *shared;
} PcapFileDirectoryVars;

/**
 * Cleanup resources associated with a PcapFileDirectoryVars object
 * @param ptv Object to be cleaned up
 */
void CleanupPcapFileDirectoryVars(PcapFileDirectoryVars *ptv);
TmEcode PcapDirectoryDispatch(PcapFileDirectoryVars *ptv);
TmEcode PcapDetermineDirectoryOrFile(char *filename, DIR **directory);
#endif //NET_THREAT_DETECT_SOURCE_PCAP_FILE_DIRECTORY_HELPER_H
