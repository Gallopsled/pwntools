#ifndef _SYS_TIME_H
#define _SYS_TIME_H	1

#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

struct timespec {
  time_t tv_sec;	/* seconds */
  long tv_nsec;		/* nanoseconds */
};

struct timeval {
  time_t tv_sec;	/* seconds */
  suseconds_t tv_usec;	/* microseconds */
};

struct timezone {
  int tz_minuteswest;	/* minutes west of Greenwich */
  int tz_dsttime;	/* type of dst correction */
};

#include <sys/select.h>

#define	ITIMER_REAL	0
#define	ITIMER_VIRTUAL	1
#define	ITIMER_PROF	2

struct itimerspec {
  struct timespec it_interval;	/* timer period */
  struct timespec it_value;	/* timer expiration */
};

struct itimerval {
  struct timeval it_interval;	/* timer interval */
  struct timeval it_value;	/* current value */
};

#if defined _GNU_SOURCE || defined _BSD_SOURCE
typedef struct timezone *__timezone_ptr_t;
#else
typedef void *__timezone_ptr_t;
#endif

int getitimer(int which, struct itimerval *value) __THROW;
int setitimer(int which, const struct itimerval *value, struct itimerval *ovalue) __THROW;

int gettimeofday(struct timeval *tv, struct timezone *tz) __THROW;
int settimeofday(const struct timeval *tv , const struct timezone *tz) __THROW;

extern int adjtime (const struct timeval *delta, struct timeval *olddelta) __THROW;

struct tm {
  int tm_sec;			/* Seconds.	[0-60] (1 leap second) */
  int tm_min;			/* Minutes.	[0-59] */
  int tm_hour;			/* Hours.	[0-23] */
  int tm_mday;			/* Day.		[1-31] */
  int tm_mon;			/* Month.	[0-11] */
  int tm_year;			/* Year - 1900. */
  int tm_wday;			/* Day of week.	[0-6] */
  int tm_yday;			/* Days in year.[0-365]	*/
  int tm_isdst;			/* DST.		[-1/0/1]*/

  long int tm_gmtoff;		/* Seconds east of UTC.  */
  const char *tm_zone;		/* Timezone abbreviation.  */
};

#ifdef _BSD_SOURCE
/* another wonderful BSD invention... :( */
#define timercmp(a,b,CMP) (((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_usec CMP (b)->tv_usec) : ((a)->tv_sec CMP (b)->tv_sec))
#define timerclear(x) ((x)->tv_sec=(x)->tv_usec=0)
#define timeradd(a,b,x) do { (x)->tv_sec=(a)->tv_sec+(b)->tv_sec; if (((x)->tv_usec=(a)->tv_usec+(b)->tv_usec)>=1000000) { ++(x)->tv_sec; (x)->tv_usec-=1000000; } } while (0)
#define timersub(a,b,x) do { (x)->tv_sec=(a)->tv_sec-(b)->tv_sec; if (((x)->tv_usec=(a)->tv_usec-(b)->tv_usec)<0) { --(x)->tv_sec; (x)->tv_usec+=1000000; } } while (0)
#define timerisset(x) ((x)->tv_sec || (x)->tv_usec)

int utimes(const char * filename, struct timeval * tvp);
#endif

__END_DECLS

#endif
