#include "util-random.h"

static long int RandomGetClock(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  // coverity[dont_call : FALSE]
  srandom(ts.tv_nsec ^ ts.tv_sec);
  long int value = random();
  return value;
}

long int RandomGet(void)
{
  return RandomGetClock();
}