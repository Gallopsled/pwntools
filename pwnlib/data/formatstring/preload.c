#include <signal.h>

__attribute__((naked))
void printf() { __builtin_trap(); }

__attribute__((naked))
void sprintf() { __builtin_trap(); }

__attribute__((naked))
void snprintf() { __builtin_trap(); }

__attribute__((naked))
void asprintf() { __builtin_trap(); }

__attribute__((naked))
void dprintf() { __builtin_trap(); }

__attribute__((naked))
void fprintf() { __builtin_trap(); }


