#include <signal.h>

void printf() { raise(SIGTRAP); }

void sprintf() { raise(SIGTRAP); }

void snprintf() { raise(SIGTRAP); }

void asprintf() { raise(SIGTRAP); }

void dprintf() { raise(SIGTRAP); }

void fprintf() { raise(SIGTRAP); }
