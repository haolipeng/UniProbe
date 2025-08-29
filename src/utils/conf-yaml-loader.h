#ifndef NET_THREAT_DETECT_CONF_YAML_LOADER_H
#define NET_THREAT_DETECT_CONF_YAML_LOADER_H

#include <stddef.h>

int ConfYamlLoadFile(const char *);
int ConfYamlLoadString(const char *, size_t );
int ConfYamlLoadFileWithPrefix(const char *filename, const char *prefix);

#endif //NET_THREAT_DETECT_CONF_YAML_LOADER_H
