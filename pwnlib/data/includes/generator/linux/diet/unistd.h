#ifndef _UNISTD_H
#define _UNISTD_H

#include <sys/cdefs.h>
#include <sys/types.h>
#include <endian.h>
#include <sys/fsuid.h>
#include <sys/select.h>

__BEGIN_DECLS

extern int optind,opterr,optopt;
extern char *optarg;
__attribute__((__warn_unused_result__))
int getopt(int argc, char *const argv[], const char *options);

/* Values for the second argument to access.
   These may be OR'd together.  */
#define R_OK 4 /* Test for read permission.  */
#define W_OK 2 /* Test for write permission.  */
#define X_OK 1 /* Test for execute permission.  */
#define F_OK 0 /* Test for existence.  */

/* Test for access to NAME using the real UID and real GID.  */
__attribute__((__warn_unused_result__))
int access (const char *__name, int __type) __THROW;

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

#define STDIN_FILENO   0
#define STDOUT_FILENO  1
#define STDERR_FILENO  2

off_t lseek(int fildes, off_t offset, int whence) __THROW;
#if !defined(__OFF_T_MATCHES_OFF64_T)
loff_t lseek64(int fildes, loff_t offset, int whence) __THROW;
#if defined _FILE_OFFSET_BITS && _FILE_OFFSET_BITS == 64
#define lseek(fildes,offset,whence) lseek64(fildes,offset,whence)
#endif
#else
#define lseek64(fildes,offset,whence) lseek(fildes,offset,whence)
#endif

int chdir(const char *path) __THROW;
int fchdir(int fd) __THROW;
int rmdir(const char *pathname) __THROW;
__writememsz__(1,2)
__attribute__((__warn_unused_result__))
char *getcwd(char *buf, size_t size) __THROW;

#ifdef _GNU_SOURCE
__attribute__((__warn_unused_result__))
__attribute_dontuse__
char *get_current_dir_name (void) __THROW;

__attribute__((__warn_unused_result__))
int pipe2(int pipefd[2], int flags) __THROW;
#endif

__attribute__((__warn_unused_result__))
int open(const char* pathname,int flags, ...) __THROW;

__attribute__((__warn_unused_result__))
int open64(const char* pathname,int flags, ...) __THROW;

__attribute__((__warn_unused_result__))
int creat(const char* pathname,mode_t mode) __THROW;

__attribute__((__warn_unused_result__))
int creat64(const char* pathname,mode_t mode) __THROW;

__readmemsz__(2,3)
ssize_t write(int fd,const void* buf,size_t len) __THROW;

__attribute__((__warn_unused_result__))
__writememsz__(2,3)
ssize_t read(int fd,void* buf,size_t len) __THROW;

// technically this should be __warn_unused_result__ too because on NFS
// you only know that the data has actually reached the server if the
// close comes back successful. OTOH NFS is almost dead, and this would
// give a ton of annoying warnings.
int close(int fd) __THROW;

int unlink(const char *pathname) __THROW;

__attribute__((__warn_unused_result__))
__writememsz__(2,3)
ssize_t pread(int fd, void *buf, size_t count, off_t offset);

__readmemsz__(2,3)
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);

__attribute__((__warn_unused_result__))
__writememsz__(2,3)
ssize_t pread64(int fd, void *buf, size_t count, off64_t offset);

__readmemsz__(2,3)
ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t offset);

int execve(const char *filename, char *const argv [], char *const envp[]) __THROW;
int execlp(const char *file, const char *arg, ...) __THROW;
int execv(const char *path, char *const argv[]) __THROW;
int execvp(const char *file, char *const argv[]) __THROW;
int execl(const char *path, const char* arg, ...) __THROW;
int execle(const char *path, const char* arg, ...) __THROW;

__attribute__((__warn_unused_result__))
pid_t getpid(void) __THROW __pure;

__attribute__((__warn_unused_result__))
pid_t getppid(void) __THROW __pure;

int setpgid (pid_t pid,pid_t pgid) __THROW;
pid_t getpgid (pid_t pid) __THROW;

__attribute__((__warn_unused_result__))
int setpgrp (void) __THROW;

__attribute__((__warn_unused_result__))
pid_t getpgrp (void) __THROW;

__attribute__((__warn_unused_result__))
pid_t getsid(pid_t pid) __THROW;

__attribute__((__warn_unused_result__))
pid_t setsid (void) __THROW;

// even if you just closed an fd and know the new fd this could still
// fail because the file descriptor table is full and you need to check
// the result
__attribute__((__warn_unused_result__))
int dup (int oldfd) __THROW;

__attribute__((__warn_unused_result__))
int dup2 (int oldfd,int newfd) __THROW;

#ifdef _GNU_SOURCE
__attribute__((__warn_unused_result__))
int dup3(int oldfd, int newfd, int flags) __THROW;

/* flags for memfd_create(2) (unsigned int) */
#define MFD_CLOEXEC		0x0001U
#define MFD_ALLOW_SEALING	0x0002U

__attribute__((__warn_unused_result__))
int memfd_create(const char* name, unsigned int flags) __THROW;

int syncfs(int fd) __THROW;
#endif

struct dirent;
struct dirent64;

__attribute__((__warn_unused_result__))
int getdents(int fd, struct dirent *dirp, unsigned int count) __THROW;

__attribute__((__warn_unused_result__))
int getdents64(int fd, struct dirent64 *dirp, unsigned int count) __THROW;

__attribute__((__warn_unused_result__))
pid_t fork(void) __THROW;

__attribute__((__warn_unused_result__))
pid_t vfork(void) __THROW;

__attribute__((__warn_unused_result__))
__writememsz__(2,3)
int readlink(const char *path, char *buf, size_t bufsiz) __THROW;

__attribute__((__warn_unused_result__))
int symlink(const char *oldpath, const char *newpath) __THROW;

__attribute__((__warn_unused_result__))
int link(const char *oldpath, const char *newpath) __THROW;

__attribute__((__warn_unused_result__))
int chown(const char *path, uid_t owner, gid_t group) __THROW;

__attribute__((__warn_unused_result__))
int fchown(int fd, uid_t owner, gid_t group) __THROW;

__attribute__((__warn_unused_result__))
int lchown(const char *path, uid_t owner, gid_t group) __THROW;

// if you do not check the return value you might as well not call fsync
// in the first place
__attribute__((__warn_unused_result__))
int fsync(int fd) __THROW;

#define _POSIX_SYNCHRONIZED_IO
__attribute__((__warn_unused_result__))
int fdatasync(int fd) __THROW;

__attribute__((__warn_unused_result__))
int pipe(int filedes[2]) __THROW;

__attribute__((__warn_unused_result__))
char *ttyname (int desc) __THROW;

__attribute__((__warn_unused_result__))
int brk(void *end_data_segment) __THROW;

__attribute__((__warn_unused_result__))
void *sbrk(ptrdiff_t increment) __THROW;

__writememsz__(1,2)
int gethostname(char *name, size_t len) __THROW;

__attribute__((__warn_unused_result__))
__readmemsz__(1,2)
int sethostname(const char *name, size_t len) __THROW;

int usleep(unsigned long useconds) __THROW;
unsigned int sleep(unsigned int seconds) __THROW;

unsigned int alarm(unsigned int seconds) __THROW;
int sync(void) __THROW;

__attribute__((__warn_unused_result__))
int isatty(int desc) __THROW;

void _exit(int status) __THROW __attribute__((__noreturn__));

__attribute__((__warn_unused_result__))
int daemon(int nochdir,int noclose) __THROW;

int pause(void) __THROW;

__attribute__((__warn_unused_result__))
char* getlogin(void) __THROW;
/* warning: the diet libc getlogin() simply returns getenv("LOGNAME") */

__attribute__((__warn_unused_result__))
int chroot(const char *path) __THROW;

__attribute__((__warn_unused_result__))
uid_t getuid(void) __THROW;

__attribute__((__warn_unused_result__))
uid_t geteuid(void) __THROW;

__attribute__((__warn_unused_result__))
gid_t getgid(void) __THROW;

__attribute__((__warn_unused_result__))
gid_t getegid(void) __THROW;

__attribute__((__warn_unused_result__))
int setuid(uid_t uid) __THROW;

/* int seteuid(uid_t uid) __THROW; */
int setgid(gid_t gid) __THROW;
/* int setegid(gid_t gid) __THROW; */
__attribute__((__warn_unused_result__))
int setregid(gid_t rgid, gid_t egid) __THROW;

__attribute__((__warn_unused_result__))
int setreuid(uid_t ruid, uid_t euid) __THROW;
#define seteuid(euid) setreuid(-1,euid)
#define setegid(egid) setregid(-1,egid)

// if this is your file (you created it or have it open), use ftruncate instead
// otherwise you risk filesystem races with other processes
__attribute__((__warn_unused_result__))
int truncate(const char *path, off_t length) __THROW;

int ftruncate(int fd, off_t length) __THROW;

#if __WORDSIZE == 32
__attribute__((__warn_unused_result__))
int truncate64(const char *path, loff_t length) __THROW;
int ftruncate64(int fd, loff_t length) __THROW;
#endif

int nice(int inc) __THROW;

#ifdef _XOPEN_SOURCE
__attribute__((__warn_unused_result__))
char *crypt(const char *key, const char *salt) __THROW;

void encrypt(char block[64], int edflag) __THROW;
void setkey(const char *key) __THROW;
#endif

#ifdef _GNU_SOURCE
__attribute__((__warn_unused_result__))
char* md5crypt(const char* key, const char* salt) __THROW;

__attribute__((__warn_unused_result__))
char* sha256_crypt(const char* key, const char* salt) __THROW;

__attribute__((__warn_unused_result__))
char* sha512_crypt(const char* key, const char* salt) __THROW;
#endif

__attribute__((__warn_unused_result__))
int getpagesize(void) __THROW __attribute__((__const__));

__writememsz__(1,2)
int getdomainname(char *name, size_t len) __THROW;
__readmemsz__(1,2)
int setdomainname(const char *name, size_t len) __THROW;

__attribute__((__warn_unused_result__))
int getgroups(int size, gid_t list[]) __THROW;

__attribute__((__warn_unused_result__))
int getdtablesize(void) __THROW;

__attribute__((__warn_unused_result__))
char *getpass(const char * prompt) __THROW;

/* warning: linux specific: */
int llseek(int fildes, unsigned long hi, unsigned long lo, loff_t* result,int whence) __THROW;

/* include <linux/sysctl.h> to get all the definitions! */
struct __sysctl_args;
int _sysctl(struct __sysctl_args *args) __THROW;

#define _CS_PATH 1
__writememsz__(2,3)
size_t confstr(int name,char*buf,size_t len) __THROW;

#define _SC_CLK_TCK 1
#define _SC_ARG_MAX 2
#define _SC_NGROUPS_MAX 3
#define _SC_OPEN_MAX 4
#define _SC_PAGESIZE 5
#define _SC_NPROCESSORS_ONLN 6
#define _SC_NPROCESSORS_CONF _SC_NPROCESSORS_ONLN
#define _SC_PHYS_PAGES 7
#define _SC_GETPW_R_SIZE_MAX 8
#define _SC_GETGR_R_SIZE_MAX 9
__attribute__((__warn_unused_result__))
long sysconf(int name) __THROW;
#define _PC_PATH_MAX 1
#define _PC_VDISABLE 2

__attribute__((__warn_unused_result__))
pid_t tcgetpgrp(int fd) __THROW;

__attribute__((__warn_unused_result__))
int tcsetpgrp(int fd, pid_t pgrpid) __THROW;

__writememsz__(1,2)
int profil(unsigned short *buf, size_t bufsiz, size_t offset, unsigned int scale);

/* Linux only: */
int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) __THROW;
int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) __THROW;

// Note: there are cases where setresuid() can fail even when the caller
// is UID 0; it is a  grave  security  error  to omit checking for a
// failure return from setresuid().
__attribute__((__warn_unused_result__))
int setresuid(uid_t ruid, uid_t euid, uid_t suid) __THROW;

__attribute__((__warn_unused_result__))
int setresgid(gid_t rgid, gid_t egid, gid_t sgid) __THROW;

/* 32-bit uid support */
int chown32(const char *path, uid32_t owner, gid32_t group) __THROW;
int fchown32(int fd, uid32_t owner, gid32_t group) __THROW;
int lchown32(const char *path, uid32_t owner, gid32_t group) __THROW;

__attribute__((__warn_unused_result__))
uid32_t getuid32(void) __THROW;
__attribute__((__warn_unused_result__))
uid32_t geteuid32(void) __THROW;
__attribute__((__warn_unused_result__))
gid32_t getgid32(void) __THROW;
__attribute__((__warn_unused_result__))
gid32_t getegid32(void) __THROW;
__attribute__((__warn_unused_result__))
int setuid32(uid32_t uid) __THROW;
int setgid32(gid32_t gid) __THROW;
__attribute__((__warn_unused_result__))
int setreuid32(uid32_t ruid, uid32_t euid) __THROW;
int setregid32(gid32_t rgid, gid32_t egid) __THROW;
#define seteuid32(euid) setreuid32(-1,euid)
#define setegid32(egid) setregid32(-1,egid)
int getgroups32(int size, gid32_t list[]) __THROW;
int getresuid32(uid32_t *ruid, uid32_t *euid, uid32_t *suid);
int getresgid32(gid32_t *rgid, gid32_t *egid, gid32_t *sgid);
__attribute__((__warn_unused_result__))
int setresuid32(uid32_t ruid, uid32_t euid, uid32_t suid) __THROW;
int setresgid32(gid32_t rgid, gid32_t egid, gid32_t sgid) __THROW;

#ifdef _BSD_SOURCE
char *getusershell(void) __attribute_dontuse__;
void setusershell(void) __attribute_dontuse__;
void endusershell(void) __attribute_dontuse__;
#endif

/* this is so bad, we moved it to -lcompat */
#define   L_cuserid   17
char* cuserid(char * string); /* ugh! */

#define   _POSIX_VERSION  199506L

#define F_ULOCK 0	/* Unlock a previously locked region.  */
#define F_LOCK  1	/* Lock a region for exclusive use.  */
#define F_TLOCK 2	/* Test and lock a region for exclusive use.  */
#define F_TEST  3	/* Test a region for other processes locks.  */

int lockf (int __fd, int __cmd, off_t __len) __THROW;
int lockf64 (int __fd, int __cmd, off64_t __len) __THROW;

__writememsz__(2,3)
void swab(const void *src, void *dest, ssize_t nbytes) __THROW;

int vhangup(void) __THROW;

extern char **__environ;

#if __WORDSIZE == 32
#if defined _FILE_OFFSET_BITS && _FILE_OFFSET_BITS == 64
#define open open64
#define creat creat64
#define truncate truncate64
#define ftruncate ftruncate64
#define getdents getdents64
#endif
#endif

#if defined(_LINUX_SOURCE)
int pivot_root(const char *new_root, const char *put_old) __THROW;
/* Linux 2.6 module loading infrastructure:
 * init_module takes a buffer where you read the module file into */
long init_module(void *module, unsigned long len, const char *options) __THROW;
/* flags can be O_EXCL | O_NONBLOCK | O_TRUNC (forced unloading)
 * O_EXCL is there so the kernel can spot old rmmod versions */
long delete_module(const char* name,unsigned int flags) __THROW;
pid_t gettid(void) __THROW __pure;
int tkill(pid_t tid, int sig) __THROW;
int tgkill(pid_t tgid, pid_t tid, int sig) __THROW;
/* see linux/fadvise.h */
long fadvise64(int fd,off64_t offset,size_t len,int advice) __THROW;
long fadvise64_64(int fd,off64_t offset,off64_t len,int advice) __THROW;

#endif

#if defined(_ATFILE_SOURCE) || ((_XOPEN_SOURCE + 0) >= 700) || ((_POSIX_C_SOURCE + 0) >= 200809L)
/* also include fcntl.h for the AT_* constants */

__attribute__((__warn_unused_result__))
int faccessat(int dirfd, const char *pathname, int mode, int flags) __THROW;

__attribute__((__warn_unused_result__))
int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) __THROW;

__attribute__((__warn_unused_result__))
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) __THROW;

__attribute__((__warn_unused_result__))
__writememsz__(3,4)
int readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) __THROW;
#endif

#define _POSIX_MAPPED_FILES 200809L

__attribute__((__warn_unused_result__))
__writememsz__(1,2)
int getentropy(void* buf,size_t buflen) __THROW;

__END_DECLS

#endif
