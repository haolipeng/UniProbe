#include <errno.h>
#include <pcre.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "util-misc.h"
#include "util-debug.h"
#include "util-strlcatu.h"

#define PARSE_REGEX "^\\s*(\\d+(?:.\\d+)?)\\s*([a-zA-Z]{2})?\\s*$"
static pcre *parse_regex = NULL;
static pcre_extra *parse_regex_study = NULL;

void ParseSizeInit(void)
{
  const char *eb = NULL;
  int eo;
  int opts = 0;

  parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
  if (parse_regex == NULL) {
    //SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset "
    //                                "%" PRI32 ": %s", PARSE_REGEX, eo, eb);
    exit(EXIT_FAILURE);
  }
  parse_regex_study = pcre_study(parse_regex, 0, &eb);//api
  if (eb != NULL) {
    SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
    exit(EXIT_FAILURE);
  }
}

void ParseSizeDeinit(void)
{

  if (parse_regex != NULL)
    pcre_free(parse_regex);
  if (parse_regex_study != NULL)
    pcre_free_study(parse_regex_study);
}

static int ParseSizeString(const char *size, double *res)
{
#define MAX_SUBSTRINGS 30
  int pcre_exec_ret;
  int r;
  int ov[MAX_SUBSTRINGS];
  int retval = 0;
  char str[128];
  char str2[128];

  *res = 0;

  if (size == NULL) {
    SCLogError(SC_ERR_INVALID_ARGUMENTS,"invalid size argument - NULL. Valid size "
                                         "argument should be in the format - \n"
                                         "xxx <- indicates it is just bytes\n"
                                         "xxxkb or xxxKb or xxxKB or xxxkB <- indicates kilobytes\n"
                                         "xxxmb or xxxMb or xxxMB or xxxmB <- indicates megabytes\n"
                                         "xxxgb or xxxGb or xxxGB or xxxgB <- indicates gigabytes.\n"
    );
    retval = -2;
    goto end;
  }

  pcre_exec_ret = pcre_exec(parse_regex, parse_regex_study, size, strlen(size), 0, 0,
                            ov, MAX_SUBSTRINGS);
  if (!(pcre_exec_ret == 2 || pcre_exec_ret == 3)) {
    SCLogError(SC_ERR_PCRE_MATCH, "invalid size argument - %s. Valid size "
                                  "argument should be in the format - \n"
                                  "xxx <- indicates it is just bytes\n"
                                  "xxxkb or xxxKb or xxxKB or xxxkB <- indicates kilobytes\n"
                                  "xxxmb or xxxMb or xxxMB or xxxmB <- indicates megabytes\n"
                                  "xxxgb or xxxGb or xxxGB or xxxgB <- indicates gigabytes.\n",
               size);
    retval = -2;
    goto end;
  }

  r = pcre_copy_substring((char *)size, ov, MAX_SUBSTRINGS, 1,
                          str, sizeof(str));
  if (r < 0) {
    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
    retval = -2;
    goto end;
  }

  char *endptr, *str_ptr = str;
  errno = 0;
  *res = strtod(str_ptr, &endptr);
  if (errno == ERANGE) {
    SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range");
    retval = -1;
    goto end;
  } else if (endptr == str_ptr) {
    SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "Invalid numeric value");
    retval = -1;
    goto end;
  }

  if (pcre_exec_ret == 3) {
    r = pcre_copy_substring((char *)size, ov, MAX_SUBSTRINGS, 2,
                            str2, sizeof(str2));
    if (r < 0) {
      SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
      retval = -2;
      goto end;
    }

    if (strcasecmp(str2, "kb") == 0) {
      *res *= 1024;
    } else if (strcasecmp(str2, "mb") == 0) {
      *res *= 1024 * 1024;
    } else if (strcasecmp(str2, "gb") == 0) {
      *res *= 1024 * 1024 * 1024;
    } else {
      /* Bad unit. */
      retval = -1;
      goto end;
    }
  }

  retval = 0;
end:
  return retval;
}

int ParseSizeStringU16(const char *size, uint16_t *res)
{
    double temp_res = 0;

    *res = 0;
    int r = ParseSizeString(size, &temp_res);
    if (r < 0)
        return r;

    if (temp_res > UINT16_MAX)
        return -1;

    *res = temp_res;

    return 0;
}

int ParseSizeStringU32(const char *size, uint32_t *res)
{
    double temp_res = 0;

    *res = 0;
    int r = ParseSizeString(size, &temp_res);
    if (r < 0)
        return r;

    if (temp_res > UINT32_MAX)
        return -1;

    *res = temp_res;

    return 0;
}

int ParseSizeStringU64(const char *size, uint64_t *res)
{
  double temp_res = 0;

  *res = 0;
  int r = ParseSizeString(size, &temp_res);
  if (r < 0)
    return r;

  if (temp_res > (double) UINT64_MAX)
    return -1;

  *res = temp_res;

  return 0;
}

void ShortenString(const char *input,
                   char *output, size_t output_size, char c)
{
    const size_t str_len = strlen(input);
    size_t half = (output_size - 1) / 2;

    /* If the output size is an even number */
    if (half * 2 == (output_size - 1)) {
        half = half - 1;
    }

    size_t spaces = (output_size - 1) - (half * 2);

    /* Add the first half to the new string */
    snprintf(output, half+1, "%s", input);

    /* Add the amount of spaces wanted */
    size_t length = half;
    for (size_t i = half; i < half + spaces; i++) {
        char s[2] = "";
        snprintf(s, sizeof(s), "%c", c);
        length = strlcat(output, s, output_size);
    }

    snprintf(output + length, half + 1, "%s", input + (str_len - half));
}

