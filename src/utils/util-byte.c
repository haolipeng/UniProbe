#ifndef NET_THREAT_DETECT_UTIL_BYTE_H
#define NET_THREAT_DETECT_UTIL_BYTE_H

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

#include "util-debug.h"
#include "util-error.h"

int ByteExtractString(uint64_t *res, int base, uint16_t len, const char *str, bool strict)
{
  const char *ptr = str;
  char *endptr = NULL;

  /* 23 - This is the largest string (octal, with a zero prefix) that
     *      will not overflow uint64_t.  The only way this length
     *      could be over 23 and still not overflow is if it were zero
     *      prefixed and we only support 1 byte of zero prefix for octal.
     *
     * "01777777777777777777777" = 0xffffffffffffffff
   */
  char strbuf[24];

  if (len > 23) {
    SCLogDebug("len too large (23 max)");
    return -1;
  }

  if (len) {
    /* Extract out the string so it can be null terminated */
    memcpy(strbuf, str, len);
    strbuf[len] = '\0';
    ptr = strbuf;
  }

  errno = 0;
  *res = strtoull(ptr, &endptr, base);

  if (errno == ERANGE) {
    SCLogDebug("numeric value out of range");
    return -1;
    /* If there is no numeric value in the given string then strtoull(), makes
    endptr equals to ptr and return 0 as result */
  } else if (endptr == ptr && *res == 0) {
    SCLogDebug("no numeric value");
    return -1;
  } else if (endptr == ptr) {
    SCLogDebug("invalid numeric value");
    return -1;
  }
  else if (strict && *endptr != '\0') {
    SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "Extra characters following numeric value");
    return -1;
  }

  return (endptr - ptr);
}

int StringParseUint32(uint32_t *res, int base, uint16_t len, const char *str)
{
  uint64_t i64;

  int ret = ByteExtractString(&i64, base, len, str, true);
  if (ret <= 0) {
    return ret;
  }
  if (i64 > UINT32_MAX) {
    return -1;
  }

  *res = (uint32_t)i64;

  if ((uint64_t)(*res) != i64) {
    SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range ");
    return -1;
  }

  return ret;
}

int ByteExtractStringSigned(int64_t *res, int base, uint16_t len, const char *str, bool strict)
{
    const char *ptr = str;
    char *endptr;

    /* 23 - This is the largest string (octal, with a zero prefix) that
     *      will not overflow int64_t.  The only way this length
     *      could be over 23 and still not overflow is if it were zero
     *      prefixed and we only support 1 byte of zero prefix for octal.
     *
     * "-0777777777777777777777" = 0xffffffffffffffff
     */
    char strbuf[24];

    if (len > 23) {
        SCLogError(SC_ERR_ARG_LEN_LONG, "len too large (23 max)");
        return -1;
    }

    if (len) {
        /* Extract out the string so it can be null terminated */
        memcpy(strbuf, str, len);
        strbuf[len] = '\0';
        ptr = strbuf;
    }

    errno = 0;
    *res = strtoll(ptr, &endptr, base);

    if (errno == ERANGE) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range");
        return -1;
    } else if (endptr == str) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "Invalid numeric value");
        return -1;
    }
    else if (strict && len && *endptr != '\0') {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "Extra characters following numeric value");
        return -1;
    }

    //fprintf(stderr, "ByteExtractStringSigned: Extracted base %d: 0x%" PRIx64 "\n", base, *res);

    return (endptr - ptr);
}

int StringParseInt32(int32_t *res, int base, uint16_t len, const char *str)
{
    int64_t i64;
    int ret;

    ret = ByteExtractStringSigned(&i64, base, len, str, true);
    if (ret <= 0) {
        return ret;
    }
    if (i64 < INT32_MIN || i64 > INT32_MAX) {
        return -1;
    }

    *res = (int32_t)i64;

    if ((int64_t)(*res) != i64) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range "
                                                "(%" PRIi64 " > %" PRIiMAX ")\n", i64, (intmax_t)INT_MAX);
        return -1;
    }

    return ret;
}

#endif // NET_THREAT_DETECT_UTIL_BYTE_H
