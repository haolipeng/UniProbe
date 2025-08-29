#include "util-device.h"
#include "base.h"
#include "conf.h"
#include "util-debug.h"
#include "util-mem.h"
#include "util-misc.h"
#include <stdlib.h>
#include <string.h>

/** private device list */
static TAILQ_HEAD(, LiveDevice_) live_devices =
        TAILQ_HEAD_INITIALIZER(live_devices);

/** List of the name of devices
 *
 * As we don't know the size of the Storage on devices
 * before the parsing we need to wait and use this list
 * to create later the LiveDevice via LiveDeviceFinalize()
 */
static TAILQ_HEAD(, LiveDeviceName_) pre_live_devices =
    TAILQ_HEAD_INITIALIZER(pre_live_devices);

static int LiveSafeDeviceName(const char *devname, char *newdevname, size_t destlen);

int LiveRegisterDevice(const char *dev)
{
    LiveDevice *pd = NULL;

    //pd = SCCalloc(1, sizeof(LiveDevice) + LiveDevStorageSize());
    pd = SCCalloc(1, sizeof(LiveDevice));
    if (unlikely(pd == NULL)) {
        return -1;
    }

    pd->dev = SCStrdup(dev);
    if (unlikely(pd->dev == NULL)) {
        SCFree(pd);
        return -1;
    }
    /* create a short version to be used in thread names */
    LiveSafeDeviceName(pd->dev, pd->dev_short, sizeof(pd->dev_short));

    SC_ATOMIC_INIT(pd->pkts);
    SC_ATOMIC_INIT(pd->drop);
    SC_ATOMIC_INIT(pd->invalid_checksums);
    pd->id = LiveGetDeviceCount();
    TAILQ_INSERT_TAIL(&live_devices, pd, next);

    SCLogDebug("Device \"%s\" registered and created.", dev);
    return 0;
}

int LiveGetDeviceCount(void)
{
    int i = 0;
    LiveDevice *pd;

    TAILQ_FOREACH(pd, &live_devices, next) {
        i++;
    }

    return i;
}

static int LiveSafeDeviceName(const char *devname, char *newdevname, size_t destlen)
{
    const size_t devnamelen = strlen(devname);

    /* If we have to shorten the interface name */
    if (devnamelen > MAX_DEVNAME) {

        /* IF the dest length is over 10 chars long it will not do any
         * good for the shortening. The shortening is done due to the
         * max length of pthread names (15 chars) and we use 3 chars
         * for the threadname indicator eg. "W#-" and one-two chars for
         * the thread number. And if the destination buffer is under
         * 6 chars there is no point in shortening it since we must at
         * least enter two periods (.) into the string.
         */
        if ((destlen-1) > 10 || (destlen-1) < 6) {
            return 1;
        }

        ShortenString(devname, newdevname, destlen, '.');

        SCLogInfo("Shortening device name to: %s", newdevname);
    } else {
        strlcpy(newdevname, devname, destlen);
    }
    return 0;
}

int LiveBuildDeviceList(const char *runmode)
{
  return LiveBuildDeviceListCustom(runmode, "interface");
}

int LiveBuildDeviceListCustom(const char *runmode, const char *itemname)
{
  ConfNode *base = ConfGetNode(runmode);
  ConfNode *child;
  int i = 0;

  if (base == NULL)
    return 0;

  TAILQ_FOREACH(child, &base->head, next) {
    ConfNode *subchild;
    TAILQ_FOREACH(subchild, &child->head, next) {
      if ((!strcmp(subchild->name, itemname))) {
        if (!strcmp(subchild->val, "default"))
          break;
        SCLogConfig("Adding %s %s from config file",
                    itemname, subchild->val);
        LiveRegisterDeviceName(subchild->val);
        i++;
      }
    }
  }

  return i;
}

int LiveRegisterDeviceName(const char *dev)
{
  LiveDeviceName *pd = NULL;

  pd = calloc(1, sizeof(LiveDeviceName));
  if (unlikely(pd == NULL)) {
    return -1;
  }

  pd->dev = SCStrdup(dev);
  if (unlikely(pd->dev == NULL)) {
    SCFree(pd);
    return -1;
  }

  TAILQ_INSERT_TAIL(&pre_live_devices, pd, next);

  SCLogDebug("Device \"%s\" registered.", dev);
  return 0;
}

const char *LiveGetDeviceNameName(int number)
{
    int i = 0;
    LiveDeviceName *pd;

    TAILQ_FOREACH(pd, &pre_live_devices, next) {
        if (i == number) {
            return pd->dev;
        }

        i++;
    }

    return NULL;
}

int LiveGetDeviceNameCount(void)
{
    int i = 0;
    LiveDeviceName *pd;

    TAILQ_FOREACH(pd, &pre_live_devices, next) {
        i++;
    }

    return i;
}

LiveDevice *LiveGetDevice(const char *name)
{
    LiveDevice *pd;

    if (name == NULL) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "Name of device should not be null");
        return NULL;
    }

    TAILQ_FOREACH(pd, &live_devices, next) {
        if (!strcmp(name, pd->dev)) {
            return pd;
        }
    }

    return NULL;
}

void LiveDeviceFinalize(void)
{
    LiveDeviceName *ld, *pld;
    SCLogDebug("Finalize live device");
    /* Iter on devices and register them */
    TAILQ_FOREACH_SAFE(ld, &pre_live_devices, next, pld) {
        if (ld->dev) {
            LiveRegisterDevice(ld->dev);
            SCFree(ld->dev);
        }
        SCFree(ld);
    }
}