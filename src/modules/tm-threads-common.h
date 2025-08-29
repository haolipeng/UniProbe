#ifndef NET_THREAT_DETECT_TM_THREADS_COMMON_H
#define NET_THREAT_DETECT_TM_THREADS_COMMON_H

typedef enum {
    TMM_FLOWWORKER,
    TMM_RECEIVEPCAP,
    TMM_RECEIVEPCAPFILE,
    TMM_DECODEPCAP,
    TMM_DECODEPCAPFILE,
    TMM_RESPONDREJECT,
    TMM_RECEIVEAFP,
    TMM_DECODEAFP,

    TMM_FLOWMANAGER,
    TMM_FLOWRECYCLER,
    TMM_BYPASSEDFLOWMANAGER,
    TMM_DETECTLOADER,

    TMM_UNIXMANAGER,
    TMM_SIZE,
} TmmId;

/*Error codes for the thread modules*/
typedef enum {
    TM_ECODE_OK = 0,    /**< Thread module exits OK*/
    TM_ECODE_FAILED,    /**< Thread module exits due to failure*/
    TM_ECODE_DONE,    /**< Thread module task is finished*/
} TmEcode;

#endif //NET_THREAT_DETECT_TM_THREADS_COMMON_H
