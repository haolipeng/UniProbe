#ifndef NET_THREAT_DETECT_UTIL_MISC_H
#define NET_THREAT_DETECT_UTIL_MISC_H
#include <stdint.h>
#include <stddef.h>

#define WarnInvalidConfEntry(param_name, format, value) do {            \
        SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY,                    \
                     "Invalid conf entry found for "                    \
                     "\"%s\".  Using default value of \"" format "\".", \
                     param_name, value);                                \
    } while (0)

void ParseSizeInit(void);
void ParseSizeDeinit(void);

int ParseSizeStringU16(const char *, uint16_t *);
int ParseSizeStringU32(const char *, uint32_t *);
int ParseSizeStringU64(const char *size, uint64_t *res);

void ShortenString(const char *input,char *output, size_t output_size, char c);
#endif // NET_THREAT_DETECT_UTIL_MISC_H
