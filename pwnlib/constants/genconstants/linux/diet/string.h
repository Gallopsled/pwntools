#ifndef _STRING_H
#define _STRING_H

#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

char *strcpy(char* __restrict__ dest, const char* __restrict__ src) __THROW __nonnull((1,2));

void *memccpy(void* __restrict__ dest, const void* __restrict__ src, int c, size_t n) __THROW __nonnull((1,2));
void *memmove(void* dest, const void *src, size_t n) __THROW __nonnull((1,2));

int memccmp(const void* s1, const void* s2, int c, size_t n) __THROW __pure __nonnull((1,2));

void* memset(void* s, int c, size_t n) __THROW __nonnull((1));
int memcmp(const void* s1, const void* s2, size_t n) __THROW __pure __nonnull((1,2));
void* memcpy(void* __restrict__ dest, const void* __restrict__ src, size_t n) __THROW __nonnull((1,2));

char *strncpy(char* __restrict__ dest, const char* __restrict__ src, size_t n) __THROW __nonnull((1,2));
int strncmp(const char* s1, const char* s2, size_t n) __THROW __pure __nonnull((1,2));

char *strcat(char* __restrict__ dest, const char* __restrict__ src) __THROW __nonnull((1,2));
char *strncat(char* __restrict__ dest, const char* __restrict__ src, size_t n) __THROW __nonnull((1,2));

int strcmp(const char *s1, const char *s2) __THROW __pure __nonnull((1,2));

size_t strlen(const char *s) __THROW __pure __nonnull((1));
#ifdef _GNU_SOURCE
size_t strnlen(const char *s,size_t maxlen) __THROW __pure __nonnull((1));
#endif

char *strstr(const char *haystack, const char *needle) __THROW __pure __nonnull((1,2));

char *strdup(const char *s) __THROW __attribute_malloc__ __nonnull((1));

char *strchr(const char *s, int c) __THROW __pure __nonnull((1));
char *strrchr(const char *s, int c) __THROW __pure __nonnull((1));

size_t strspn(const char *s, const char *_accept) __THROW __nonnull((1,2));
size_t strcspn(const char *s, const char *reject) __THROW __nonnull((1,2));

char *strpbrk(const char *s, const char *_accept) __THROW __nonnull((1,2));
char *strsep(char ** __restrict__ stringp, const char * __restrict__ delim) __THROW __nonnull((1,2));

void* memchr(const void *s, int c, size_t n) __THROW __pure __nonnull((1));
#ifdef _GNU_SOURCE
void* memrchr(const void *s, int c, size_t n) __THROW __pure __nonnull((1));
#endif

/* I would like to make this const, but Paul Jarc points out it has to
 * be char* :-( */
char *strerror(int errnum) __THROW __attribute_const__;
/* work around b0rken GNU crapware like tar 1.13.19 */
#define strerror strerror
int strerror_r(int errnum,char* buf,size_t n) __THROW __attribute_dontuse__;

#ifdef _GNU_SOURCE
char *strsignal(int signum) __THROW __attribute_const__;
void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) __THROW __nonnull((1,3));

void* mempcpy(void* __restrict__ dest,const void* __restrict__ src,size_t n) __THROW __nonnull((1,2));

char *strndup(const char *s,size_t n) __THROW __attribute_malloc__ __nonnull((1));

#define strdupa(s) ({ const char* tmp=s; size_t l=strlen(tmp)+1; char* x=alloca(l); memcpy(x,tmp,l); })
#define strndupa(s,n) ({ const char* tmp=s; const char* y=memchr(tmp,0,(n)); size_t l=y?y-tmp:n; char* x=alloca(l+1); x[l]=0; memcpy(x,tmp,l); })
#endif

char *strtok(char * __restrict__ s, const char * __restrict__ delim) __THROW __nonnull((2));
char *strtok_r(char * __restrict__ s, const char * __restrict__ delim, char ** __restrict__ ptrptr) __THROW __nonnull((2,3));

size_t strlcpy(char * __restrict__ dst, const char * __restrict__ src, size_t size) __THROW __nonnull((1,2));
size_t strlcat(char * __restrict__ dst, const char * __restrict__ src, size_t size) __THROW __nonnull((1,2));

int strcoll(const char *s1, const char *s2) __THROW __nonnull((1,2));
size_t strxfrm(char *dest, const char * __restrict__ src, size_t n) __THROW __nonnull((1,2));

#ifdef _BSD_SOURCE
#include <strings.h>
#endif

char *stpcpy(char * __restrict__ dest, const char * __restrict__ src) __THROW __nonnull((1,2));
char* stpncpy(char* __restrict__ dest, const char* __restrict__ src, size_t n) __THROW __nonnull((1,2));

#ifdef _GNU_SOURCE
int ffsl(long i) __THROW __attribute_const__;
int ffsll(long long i) __THROW __attribute_const__;
#endif

__END_DECLS

#endif
