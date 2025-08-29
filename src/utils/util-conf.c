#include <string.h>
#include "util-conf.h"

ConfNode *ConfFindDeviceConfig(ConfNode *node, const char *iface)
{
    ConfNode *if_node, *item;
    TAILQ_FOREACH(if_node, &node->head, next) {
        TAILQ_FOREACH(item, &if_node->head, next) {
            if (strcmp(item->name, "interface") == 0 &&
                strcmp(item->val, iface) == 0) {
                return if_node;
            }
        }
    }

    return NULL;
}

const char *ConfigGetLogDirectory(void)
{
    const char *log_dir = NULL;

    if (ConfGet("default-log-dir", &log_dir) != 1) {
        log_dir = DEFAULT_LOG_DIR;
    }

    return log_dir;
}