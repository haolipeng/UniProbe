#ifndef NET_THREAT_DETECT_UTIL_CONF_H
#define NET_THREAT_DETECT_UTIL_CONF_H

#include "conf.h"

ConfNode *ConfFindDeviceConfig(ConfNode *node, const char *iface);
const char *ConfigGetLogDirectory(void);
#endif //NET_THREAT_DETECT_UTIL_CONF_H
