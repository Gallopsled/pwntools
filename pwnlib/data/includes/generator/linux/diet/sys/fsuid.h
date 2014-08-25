#ifndef __FSUID_H
#define __FSUID_H 1

#include <sys/types.h>

__BEGIN_DECLS

/* Linux only: */
int setfsuid(uid_t uid);
int setfsgid(gid_t gid);
int setfsuid32(uid32_t fsuid) __THROW;
int setfsgid32(gid32_t fsgid) __THROW;

__END_DECLS

#endif
