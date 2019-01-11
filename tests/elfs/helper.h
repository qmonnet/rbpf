/**
 * @brief Example C-based BPF program that prints out the parameters
 * passed to it
 */

#pragma once

uint64_t helper_function(uint64_t x);
uint64_t entrypoint_helper_function(uint64_t x);
