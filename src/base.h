//
// Created by haolipeng on 1/10/23.
//

#ifndef NET_THREAT_DETECT_BASE_H
#define NET_THREAT_DETECT_BASE_H

#include <inttypes.h>

//typedef unsigned char bool;

#undef true
#undef false
#define true  1
#define false 0

#define TRUE   1
#define FALSE  0

#define max(x,y) (((x)>(y))?(x):(y))
#define min(x,y) (((x)<(y))?(x):(y))

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define MAX_THREADS (4)


#endif //NET_THREAT_DETECT_BASE_H
