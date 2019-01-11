typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

extern void log(const char*);
extern void log_64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

#include "helper.h"

uint64_t entrypoint_helper_function(uint64_t x) {
  log(__func__);
  if (x) {
    helper_function(--x);
  }
  return x;
}

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t x = (uint64_t)*input;
  log("Start");
  if (x) {
    x = helper_function(--x);
  }
  log("End");
  return x;
}
