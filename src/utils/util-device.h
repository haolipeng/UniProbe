#ifndef NET_THREAT_DETECT_UTIL_DEVICE_H
#define NET_THREAT_DETECT_UTIL_DEVICE_H

#include <stdbool.h>
#include <stdint.h>
#include "queue.h"
#include "util-atomic.h"

#define MAX_DEVNAME 10

/** storage for live device names */
typedef struct LiveDevice_ {
    char *dev;  /**< the device (e.g. "eth0") */
    char dev_short[MAX_DEVNAME + 1];
    bool tenant_id_set;

    int id;

    SC_ATOMIC_DECLARE(uint64_t, pkts);
    SC_ATOMIC_DECLARE(uint64_t, drop);
    SC_ATOMIC_DECLARE(uint64_t, bypassed);
    SC_ATOMIC_DECLARE(uint64_t, invalid_checksums);
    TAILQ_ENTRY(LiveDevice_) next;

    uint32_t tenant_id;     /**< tenant id in multi-tenancy */
    uint32_t offload_orig;  /**< original offload settings to restore @exit */
} LiveDevice;

typedef struct LiveDeviceName_ {
  char *dev;  /**< the device (e.g. "eth0") */
  TAILQ_ENTRY(LiveDeviceName_) next;
} LiveDeviceName;

int LiveRegisterDevice(const char *dev);
int LiveBuildDeviceList(const char *base);
int LiveBuildDeviceListCustom(const char *runmode, const char *itemname);
int LiveRegisterDeviceName(const char *dev);
int LiveGetDeviceNameCount(void);
const char *LiveGetDeviceNameName(int number);
LiveDevice *LiveGetDevice(const char *name);

void LiveDeviceFinalize(void);
int LiveGetDeviceCount(void);
#endif // NET_THREAT_DETECT_UTIL_DEVICE_H
