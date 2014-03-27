#ifndef _SYS_SOCKET_H
#define _SYS_SOCKET_H

#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

/* For setsockopt(2) */
#if defined(__alpha__) || defined(__mips__)
#define SOL_SOCKET	0xffff

#define SO_DEBUG	0x0001
#define SO_REUSEADDR	0x0004
#define SO_TYPE		0x1008
#define SO_ERROR	0x1007
#define SO_DONTROUTE	0x0010
#define SO_BROADCAST	0x0020
#define SO_SNDBUF	0x1001
#define SO_RCVBUF	0x1002
#define SO_KEEPALIVE	0x0008
#define SO_OOBINLINE	0x0100
#define SO_NO_CHECK	11
#define SO_PRIORITY	12
#define SO_LINGER	0x0080
#define SO_BSDCOMPAT	14
/* To add :#define SO_REUSEPORT 15 */
#define SO_PASSCRED	17
#define SO_PEERCRED	18
#define SO_RCVLOWAT	0x1004
#define SO_SNDLOWAT	0x1003
#define SO_RCVTIMEO	0x1006
#define SO_SNDTIMEO	0x1005
#define SO_ACCEPTCONN	0x1009

#ifdef __alpha__
#define SO_SNDBUFFORCE	0x100a
#define SO_RCVBUFFORCE	0x100b
#else
#define SO_SNDBUFFORCE	31
#define SO_RCVBUFFORCE	33
#endif

#define SO_STYLE	SO_TYPE /* Synonym */

#elif defined(__hppa__)
#define SOL_SOCKET	0xffff

#define SO_DEBUG	0x0001
#define SO_REUSEADDR	0x0004
#define SO_KEEPALIVE	0x0008
#define SO_DONTROUTE	0x0010
#define SO_BROADCAST	0x0020
#define SO_LINGER	0x0080
#define SO_OOBINLINE	0x0100
/* To add :#define SO_REUSEPORT 0x0200 */
#define SO_SNDBUF	0x1001
#define SO_RCVBUF	0x1002
#define SO_SNDLOWAT	0x1003
#define SO_RCVLOWAT	0x1004
#define SO_SNDTIMEO	0x1005
#define SO_RCVTIMEO	0x1006
#define SO_ERROR	0x1007
#define SO_TYPE	0x1008
#define SO_SNDBUFFORCE	0x100a
#define SO_RCVBUFFORCE	0x100b

#define SO_PEERNAME	0x2000

#define SO_NO_CHECK	0x400b
#define SO_PRIORITY	0x400c
#define SO_BSDCOMPAT	0x400e
#define SO_PASSCRED	0x4010
#define SO_PEERCRED	0x4011
#define SO_TIMESTAMP	0x4012
#define SCM_TIMESTAMP   SO_TIMESTAMP

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION	0x4016
#define SO_SECURITY_ENCRYPTION_TRANSPORT	0x4017
#define SO_SECURITY_ENCRYPTION_NETWORK	0x4018

#define SO_BINDTODEVICE	0x4019

/* Socket filtering */
#define SO_ATTACH_FILTER	0x401a
#define SO_DETACH_FILTER	0x401b

#define SO_ACCEPTCONN	0x401c

#elif defined(__sparc__)
#define SOL_SOCKET	0xffff

#define SO_DEBUG	0x0001
#define SO_PASSCRED	0x0002
#define SO_REUSEADDR	0x0004
#define SO_KEEPALIVE	0x0008
#define SO_DONTROUTE	0x0010
#define SO_BROADCAST	0x0020
#define SO_PEERCRED	0x0040
#define SO_LINGER	0x0080
#define SO_OOBINLINE	0x0100
/* To add :#define SO_REUSEPORT 0x0200 */
#define SO_BSDCOMPAT	0x0400
#define SO_RCVLOWAT	0x0800
#define SO_SNDLOWAT	0x1000
#define SO_RCVTIMEO	0x2000
#define SO_SNDTIMEO	0x4000
#define SO_ACCEPTCONN	0x8000

#define SO_DONTLINGER	(~SO_LINGER)  /* Older SunOS compat. hack */

#define SO_SNDBUF	0x1001
#define SO_RCVBUF	0x1002
#define SO_SNDBUFFORCE	0x100a
#define SO_RCVBUFFORCE	0x100b

#define SO_ERROR	0x1007
#define SO_TYPE		0x1008

#define SO_ATTACH_FILTER	0x001a
#define SO_DETACH_FILTER	0x001b

#define SO_PEERNAME	0x001c
#define SO_TIMESTAMP	0x001d
#define SCM_TIMESTAMP	SO_TIMESTAMP

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION              0x5001
#define SO_SECURITY_ENCRYPTION_TRANSPORT        0x5002
#define SO_SECURITY_ENCRYPTION_NETWORK          0x5004

#else

#define SOL_SOCKET	1

#define SO_DEBUG	1
#define SO_REUSEADDR	2
#define SO_TYPE		3
#define SO_ERROR	4
#define SO_DONTROUTE	5
#define SO_BROADCAST	6
#define SO_SNDBUF	7
#define SO_RCVBUF	8
#define SO_KEEPALIVE	9
#define SO_OOBINLINE	10
#define SO_NO_CHECK	11
#define SO_PRIORITY	12
#define SO_LINGER	13
#define SO_BSDCOMPAT	14
/* To add :#define SO_REUSEPORT 15 */
#define SO_PASSCRED	16
#define SO_PEERCRED	17
#define SO_RCVLOWAT	18
#define SO_SNDLOWAT	19
#define SO_RCVTIMEO	20
#define SO_SNDTIMEO	21
#define SO_ACCEPTCONN	30
#define SO_SNDBUFFORCE	32
#define SO_RCVBUFFORCE	33

#endif

#if !defined(__hppa__) && !defined(__sparc__)
/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION		22
#define SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define SO_SECURITY_ENCRYPTION_NETWORK		24

#define SO_BINDTODEVICE	25

/* Socket filtering */
#define SO_ATTACH_FILTER        26
#define SO_DETACH_FILTER        27

#define SO_PEERNAME		28
#define SO_TIMESTAMP		29
#define SCM_TIMESTAMP		SO_TIMESTAMP
#endif

/* Socket types. */
#ifdef __mips__
#define SOCK_DGRAM	1		/* datagram (conn.less) socket	*/
#define SOCK_STREAM	2		/* stream (connection) socket	*/
#else
#define SOCK_STREAM	1		/* stream (connection) socket	*/
#define SOCK_DGRAM	2		/* datagram (conn.less) socket	*/
#endif
#define SOCK_RAW	3		/* raw socket			*/
#define SOCK_RDM	4		/* reliably-delivered message	*/
#define SOCK_SEQPACKET	5		/* sequential packet socket	*/
#define SOCK_PACKET	10		/* linux specific way of	*/
					/* getting packets at the dev	*/
					/* level.  For writing rarp and	*/
					/* other similar things on the	*/
					/* user level.			*/

struct sockaddr {
  sa_family_t sa_family;
  char sa_data[14];
};

struct linger {
  int32_t l_onoff;
  int32_t l_linger;
};

struct iovec {
  void* iov_base;	/* BSD uses caddr_t (1003.1g requires void *) */
  size_t iov_len;	/* Must be size_t (1003.1g) */
};

struct msghdr {
  void* msg_name;		/* Socket name */
  socklen_t msg_namelen;		/* Length of name */
  struct iovec* msg_iov;	/* Data blocks */
  size_t msg_iovlen;		/* Number of blocks */
  void* msg_control;		/* Per protocol magic (eg BSD file descriptor passing) */
  size_t msg_controllen;	/* Length of cmsg list */
  uint32_t msg_flags;
};

struct cmsghdr {
  size_t cmsg_len;	/* data byte count, including hdr */
  int32_t cmsg_level;	/* originating protocol */
  int32_t cmsg_type;	/* protocol-specific type */
};

#define UIO_FASTIOV	8
#define UIO_MAXIOV	1024

/* "Socket"-level control message types: */

#define SCM_RIGHTS	0x01	/* rw: access rights (array of int) */
#define SCM_CREDENTIALS	0x02	/* rw: struct ucred             */
#define SCM_CONNECT	0x03	/* rw: struct scm_connect       */

struct ucred {
  pid_t pid;
  uid_t uid;
  gid_t gid;
};

/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_ATMPVC	8	/* ATM PVCs			*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			*/
#define AF_ROSE		11	/* Amateur Radio X.25 PLP	*/
#define AF_DECnet	12	/* Reserved for DECnet project	*/
#define AF_NETBEUI	13	/* Reserved for 802.2LLC project*/
#define AF_SECURITY	14	/* Security callback pseudo AF */
#define AF_KEY		15      /* PF_KEY key management API */
#define AF_NETLINK	16
#define AF_ROUTE	AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET	17	/* Packet family		*/
#define AF_ASH		18	/* Ash				*/
#define AF_ECONET	19	/* Acorn Econet			*/
#define AF_ATMSVC	20	/* ATM SVCs			*/
#define AF_SNA		22	/* Linux SNA Project (nutters!) */
#define AF_IRDA		23	/* IRDA sockets			*/
#define AF_PPPOX	24	/* PPPoX sockets		*/
#define AF_WANPIPE	25	/* Wanpipe API Sockets */
#define AF_MAX		32	/* For now.. */

/* Protocol families, same as address families. */
#define PF_UNSPEC	AF_UNSPEC
#define PF_UNIX		AF_UNIX
#define PF_LOCAL	AF_LOCAL
#define PF_INET		AF_INET
#define PF_AX25		AF_AX25
#define PF_IPX		AF_IPX
#define PF_APPLETALK	AF_APPLETALK
#define	PF_NETROM	AF_NETROM
#define PF_BRIDGE	AF_BRIDGE
#define PF_ATMPVC	AF_ATMPVC
#define PF_X25		AF_X25
#define PF_INET6	AF_INET6
#define PF_ROSE		AF_ROSE
#define PF_DECnet	AF_DECnet
#define PF_NETBEUI	AF_NETBEUI
#define PF_SECURITY	AF_SECURITY
#define PF_KEY		AF_KEY
#define PF_NETLINK	AF_NETLINK
#define PF_ROUTE	AF_ROUTE
#define PF_PACKET	AF_PACKET
#define PF_ASH		AF_ASH
#define PF_ECONET	AF_ECONET
#define PF_ATMSVC	AF_ATMSVC
#define PF_SNA		AF_SNA
#define PF_IRDA		AF_IRDA
#define PF_PPPOX	AF_PPPOX
#define PF_WANPIPE	AF_WANPIPE
#define PF_MAX		AF_MAX

/* Maximum queue length specifiable by listen.  */
#define SOMAXCONN	128

/* Flags we can use with send/ and recv.
   Added those for 1003.1g not all are supported yet */
#define MSG_OOB		1
#define MSG_PEEK	2
#define MSG_DONTROUTE	4
#define MSG_TRYHARD     4       /* Synonym for MSG_DONTROUTE for DECnet */
#define MSG_CTRUNC	8
#define MSG_PROBE	0x10	/* Do not send. Only probe path f.e. for MTU */
#define MSG_TRUNC	0x20
#define MSG_DONTWAIT	0x40	/* Nonblocking io		 */
#define MSG_EOR         0x80	/* End of record */
#define MSG_WAITALL	0x100	/* Wait for a full request */
#define MSG_FIN         0x200
#define MSG_EOF         MSG_FIN
#define MSG_SYN		0x400
#define MSG_CONFIRM	0x800	/* Confirm path validity */
#define MSG_RST		0x1000
#define MSG_ERRQUEUE	0x2000	/* Fetch message from error queue */
#define MSG_NOSIGNAL	0x4000	/* Do not generate SIGPIPE */
#define MSG_MORE	0x8000	/* Sender will send more */

/* Setsockoptions(2) level. Thanks to BSD these must match IPPROTO_xxx */
#define SOL_IP		0
/* #define SOL_ICMP	1	No-no-no! Due to Linux :-) we cannot use SOL_ICMP=1 */
#define SOL_TCP		6
#define SOL_UDP		17
#define SOL_IPV6	41
#define SOL_ICMPV6	58
#define SOL_RAW		255
#define SOL_IPX		256
#define SOL_AX25	257
#define SOL_ATALK	258
#define SOL_NETROM	259
#define SOL_ROSE	260
#define SOL_DECNET	261
#define	SOL_X25		262
#define SOL_PACKET	263
#define SOL_ATM		264	/* ATM layer (cell level) */
#define SOL_AAL		265	/* ATM Adaption Layer (packet level) */
#define SOL_IRDA        266

/* IPX options */
#define IPX_TYPE	1

#define CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )
#define __CMSG_NXTHDR(ctl, len, cmsg) __cmsg_nxthdr((ctl),(len),(cmsg))
#define CMSG_NXTHDR(mhdr, cmsg) cmsg_nxthdr((mhdr), (cmsg))

static inline struct cmsghdr* __cmsg_nxthdr(void *__ctl, size_t __size, struct cmsghdr *__cmsg)
{
  struct cmsghdr * __ptr;
  __ptr = (struct cmsghdr*)(((unsigned char *) __cmsg) +  CMSG_ALIGN(__cmsg->cmsg_len));
  if ((unsigned long)((char*)(__ptr+1) - (char *) __ctl) > __size)
    return (struct cmsghdr *)0;
  return __ptr;
}

static inline struct cmsghdr* cmsg_nxthdr (struct msghdr *__msg, struct cmsghdr *__cmsg)
{
  return __cmsg_nxthdr(__msg->msg_control, __msg->msg_controllen, __cmsg);
}

#define CMSG_DATA(cmsg)	((void *)((char *)(cmsg) + CMSG_ALIGN(sizeof(struct cmsghdr))))
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))

#define __CMSG_FIRSTHDR(ctl,len) ((len) >= sizeof(struct cmsghdr) ? \
				  (struct cmsghdr *)(ctl) : \
				  (struct cmsghdr *)NULL)
#define CMSG_FIRSTHDR(msg)	__CMSG_FIRSTHDR((msg)->msg_control, (msg)->msg_controllen)

struct sockaddr_storage {
  sa_family_t  ss_family;
  uint32_t  __ss_align;
  char __ss_padding[(128  - (2 * sizeof (uint32_t ))) ];
};

#ifndef SOCK_DGRAM
/* the Linux kernel headers suck really badly on non-x86 */
#define SOCK_STREAM	1		/* stream (connection) socket	*/
#define SOCK_DGRAM	2		/* datagram (conn.less) socket	*/
#define SOCK_RAW	3		/* raw socket			*/
#define SOCK_RDM	4		/* reliably-delivered message	*/
#define SOCK_SEQPACKET	5		/* sequential packet socket	*/
#define SOCK_PACKET	10		/* linux specific way of	*/
#endif

int socket(int domain, int type, int protocol) __THROW;
int accept(int s, struct sockaddr *addr, socklen_t *addrlen) __THROW;
int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen) __THROW;
int bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen) __THROW;
int recv(int s, void *buf, size_t len, int flags) __THROW;
int recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen) __THROW;
int recvmsg(int s, struct msghdr *msg, int flags) __THROW;
int send(int s, const void *msg, size_t len, int flags) __THROW;
int sendto(int s, const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) __THROW;
int sendmsg(int s, const struct msghdr *msg, int flags) __THROW;

int getpeername(int s, struct sockaddr *name, socklen_t *namelen) __THROW;
int getsockname(int  s , struct sockaddr * name , socklen_t * namelen) __THROW;

int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen) __THROW;
int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen) __THROW;

int listen(int s, int backlog) __THROW;

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
int shutdown(int s, int how) __THROW;

int socketpair(int d, int type, int protocol, int sv[2]);

/* currently not supported: */
#define NI_NOFQDN 1

#define NI_NUMERICHOST 2
#define NI_NAMEREQD 4
#define NI_NUMERICSERV 8
#define NI_DGRAM 16

struct addrinfo {
  int     ai_flags;
  int     ai_family;
  int     ai_socktype;
  int     ai_protocol;
  size_t  ai_addrlen;
  struct sockaddr *ai_addr;
  char   *ai_canonname;
  struct addrinfo *ai_next;
};

int getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host,
		size_t hostlen, char *serv, size_t servlen, int flags) __THROW;
int getaddrinfo(const char *node, const char *service, const struct
		addrinfo *hints, struct addrinfo **res) __THROW;
void freeaddrinfo(struct addrinfo *res) __THROW;
const char *gai_strerror(int errcode) __THROW;

#define EAI_FAMILY -1
#define EAI_SOCKTYPE -2
#define EAI_BADFLAGS -3
#define EAI_NONAME -4
#define EAI_SERVICE -5
#define EAI_ADDRFAMILY -6
#define EAI_NODATA -7
#define EAI_MEMORY -8
#define EAI_FAIL -9
#define EAI_AGAIN -10
#define EAI_SYSTEM -11

#define AI_NUMERICHOST 1
#define AI_CANONNAME 2
#define AI_PASSIVE 4

/* Linux-specific socket ioctls */
#define SIOCINQ		FIONREAD
#define SIOCOUTQ	TIOCOUTQ

/* Routing table calls. */
#define SIOCADDRT	0x890B		/* add routing table entry	*/
#define SIOCDELRT	0x890C		/* delete routing table entry	*/
#define SIOCRTMSG	0x890D		/* call to routing system	*/

/* Socket configuration controls. */
#define SIOCGIFNAME	0x8910		/* get iface name		*/
#define SIOCSIFLINK	0x8911		/* set iface channel		*/
#define SIOCGIFCONF	0x8912		/* get iface list		*/
#define SIOCGIFFLAGS	0x8913		/* get flags			*/
#define SIOCSIFFLAGS	0x8914		/* set flags			*/
#define SIOCGIFADDR	0x8915		/* get PA address		*/
#define SIOCSIFADDR	0x8916		/* set PA address		*/
#define SIOCGIFDSTADDR	0x8917		/* get remote PA address	*/
#define SIOCSIFDSTADDR	0x8918		/* set remote PA address	*/
#define SIOCGIFBRDADDR	0x8919		/* get broadcast PA address	*/
#define SIOCSIFBRDADDR	0x891a		/* set broadcast PA address	*/
#define SIOCGIFNETMASK	0x891b		/* get network PA mask		*/
#define SIOCSIFNETMASK	0x891c		/* set network PA mask		*/
#define SIOCGIFMETRIC	0x891d		/* get metric			*/
#define SIOCSIFMETRIC	0x891e		/* set metric			*/
#define SIOCGIFMEM	0x891f		/* get memory address (BSD)	*/
#define SIOCSIFMEM	0x8920		/* set memory address (BSD)	*/
#define SIOCGIFMTU	0x8921		/* get MTU size			*/
#define SIOCSIFMTU	0x8922		/* set MTU size			*/
#define SIOCSIFNAME	0x8923		/* set interface name */
#define SIOCSIFHWADDR	0x8924		/* set hardware address 	*/
#define SIOCGIFENCAP	0x8925		/* get/set encapsulations       */
#define SIOCSIFENCAP	0x8926
#define SIOCGIFHWADDR	0x8927		/* Get hardware address		*/
#define SIOCGIFSLAVE	0x8929		/* Driver slaving support	*/
#define SIOCSIFSLAVE	0x8930
#define SIOCADDMULTI	0x8931		/* Multicast address lists	*/
#define SIOCDELMULTI	0x8932
#define SIOCGIFINDEX	0x8933		/* name -> if_index mapping	*/
#define SIOGIFINDEX	SIOCGIFINDEX	/* misprint compatibility :-)	*/
#define SIOCSIFPFLAGS	0x8934		/* set/get extended flags set	*/
#define SIOCGIFPFLAGS	0x8935
#define SIOCDIFADDR	0x8936		/* delete PA address		*/
#define SIOCSIFHWBROADCAST	0x8937	/* set hardware broadcast addr	*/
#define SIOCGIFCOUNT	0x8938		/* get number of devices */

#define SIOCGIFBR	0x8940		/* Bridging support		*/
#define SIOCSIFBR	0x8941		/* Set bridging options 	*/

#define SIOCGIFTXQLEN	0x8942		/* Get the tx queue length	*/
#define SIOCSIFTXQLEN	0x8943		/* Set the tx queue length 	*/

#define SIOCGIFDIVERT	0x8944		/* Frame diversion support */
#define SIOCSIFDIVERT	0x8945		/* Set frame diversion options */

#define SIOCETHTOOL	0x8946		/* Ethtool interface		*/

/* ARP cache control calls. */
		    /*  0x8950 - 0x8952  * obsolete calls, don't re-use */
#define SIOCDARP	0x8953		/* delete ARP table entry	*/
#define SIOCGARP	0x8954		/* get ARP table entry		*/
#define SIOCSARP	0x8955		/* set ARP table entry		*/

/* RARP cache control calls. */
#define SIOCDRARP	0x8960		/* delete RARP table entry	*/
#define SIOCGRARP	0x8961		/* get RARP table entry		*/
#define SIOCSRARP	0x8962		/* set RARP table entry		*/

/* Driver configuration calls */

#define SIOCGIFMAP	0x8970		/* Get device parameters	*/
#define SIOCSIFMAP	0x8971		/* Set device parameters	*/

/* DLCI configuration calls */

#define SIOCADDDLCI	0x8980		/* Create new DLCI device	*/
#define SIOCDELDLCI	0x8981		/* Delete DLCI device		*/

#define SIOCDEVPRIVATE	0x89F0		/* to 89FF */

#define _LINUX_SOCKET_H

__END_DECLS

#endif
