#ifndef __DP_BITS_H__
#define __DP_BITS_H__

#include <stdlib.h>
#include <string.h>

#define INDEX2MASK(index) (1 << (index))

#define BITMASK_ARRAY_INDEX(x) ((x) >> 3)
#define BITMASK_BIT(x) ((x) & 7)
#define BITMASK_MASK(x) (1 << BITMASK_BIT(x))
#define BITMASK_ARRAY_SIZE(x) BITMASK_ARRAY_INDEX((x) + 7)

#define BITMASK_DEFINE(var, bits) \
    uint8_t var[BITMASK_ARRAY_SIZE(bits)]

#endif
