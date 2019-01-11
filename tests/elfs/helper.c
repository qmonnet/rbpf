
typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

extern void log(const char*);
extern void log_64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

#include "helper.h"

uint64_t helper_function(uint64_t x) {
  log(__func__);
  if (x) {
    entrypoint_helper_function(--x);
  }
  return x;
}
