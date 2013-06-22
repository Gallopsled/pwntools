#ifndef _ERRNO_H
#define _ERRNO_H

#if defined(__alpha__)

#define EPERM		 1	/* Operation not permitted */
#define ENOENT		 2	/* No such file or directory */
#define ESRCH		 3	/* No such process */
#define EINTR		 4	/* Interrupted system call */
#define EIO		 5	/* I/O error */
#define ENXIO		 6	/* No such device or address */
#define E2BIG		 7	/* Arg list too long */
#define ENOEXEC		 8	/* Exec format error */
#define EBADF		 9	/* Bad file number */
#define ECHILD		10	/* No child processes */
#define EDEADLK		11	/* Resource deadlock would occur */
#define ENOMEM		12	/* Out of memory */
#define EACCES		13	/* Permission denied */
#define EFAULT		14	/* Bad address */
#define ENOTBLK		15	/* Block device required */
#define EBUSY		16	/* Device or resource busy */
#define EEXIST		17	/* File exists */
#define EXDEV		18	/* Cross-device link */
#define ENODEV		19	/* No such device */
#define ENOTDIR		20	/* Not a directory */
#define EISDIR		21	/* Is a directory */
#define EINVAL		22	/* Invalid argument */
#define ENFILE		23	/* File table overflow */
#define EMFILE		24	/* Too many open files */
#define ENOTTY		25	/* Not a typewriter */
#define ETXTBSY		26	/* Text file busy */
#define EFBIG		27	/* File too large */
#define ENOSPC		28	/* No space left on device */
#define ESPIPE		29	/* Illegal seek */
#define EROFS		30	/* Read-only file system */
#define EMLINK		31	/* Too many links */
#define EPIPE		32	/* Broken pipe */
#define EDOM		33	/* Math argument out of domain of func */
#define ERANGE		34	/* Math result not representable */
#define EAGAIN		35	/* Try again */
#define EWOULDBLOCK	EAGAIN	/* Operation would block */
#define EINPROGRESS	36	/* Operation now in progress */
#define EALREADY	37	/* Operation already in progress */
#define ENOTSOCK	38	/* Socket operation on non-socket */
#define EDESTADDRREQ	39	/* Destination address required */
#define EMSGSIZE	40	/* Message too long */
#define EPROTOTYPE	41	/* Protocol wrong type for socket */
#define ENOPROTOOPT	42	/* Protocol not available */
#define EPROTONOSUPPORT	43	/* Protocol not supported */
#define ESOCKTNOSUPPORT	44	/* Socket type not supported */
#define EOPNOTSUPP	45	/* Operation not supported on transport endpoint */
#define ENOTSUP		EOPNOTSUPP/* Operation not supported on transport endpoint */
#define EPFNOSUPPORT	46	/* Protocol family not supported */
#define EAFNOSUPPORT	47	/* Address family not supported by protocol */
#define EADDRINUSE	48	/* Address already in use */
#define EADDRNOTAVAIL	49	/* Cannot assign requested address */
#define ENETDOWN	50	/* Network is down */
#define ENETUNREACH	51	/* Network is unreachable */
#define ENETRESET	52	/* Network dropped connection because of reset */
#define ECONNABORTED	53	/* Software caused connection abort */
#define ECONNRESET	54	/* Connection reset by peer */
#define ENOBUFS		55	/* No buffer space available */
#define EISCONN		56	/* Transport endpoint is already connected */
#define ENOTCONN	57	/* Transport endpoint is not connected */
#define ESHUTDOWN	58	/* Cannot send after transport endpoint shutdown */
#define ETOOMANYREFS	59	/* Too many references: cannot splice */
#define ETIMEDOUT	60	/* Connection timed out */
#define ECONNREFUSED	61	/* Connection refused */
#define ELOOP		62	/* Too many symbolic links encountered */
#define ENAMETOOLONG	63	/* File name too long */
#define EHOSTDOWN	64	/* Host is down */
#define EHOSTUNREACH	65	/* No route to host */
#define ENOTEMPTY	66	/* Directory not empty */
#define EUSERS		68	/* Too many users */
#define EDQUOT		69	/* Quota exceeded */
#define ESTALE		70	/* Stale NFS file handle */
#define EREMOTE		71	/* Object is remote */
#define ENOLCK		77	/* No record locks available */
#define ENOSYS		78	/* Function not implemented */
#define ENOMSG		80	/* No message of desired type */
#define EIDRM		81	/* Identifier removed */
#define ENOSR		82	/* Out of streams resources */
#define ETIME		83	/* Timer expired */
#define EBADMSG		84	/* Not a data message */
#define EPROTO		85	/* Protocol error */
#define ENODATA		86	/* No data available */
#define ENOSTR		87	/* Device not a stream */
#define ENOPKG		92	/* Package not installed */
#define EILSEQ		116	/* Illegal byte sequence */
/* The following are just random noise.. */
#define ECHRNG		88	/* Channel number out of range */
#define EL2NSYNC	89	/* Level 2 not synchronized */
#define EL3HLT		90	/* Level 3 halted */
#define EL3RST		91	/* Level 3 reset */
#define ELNRNG		93	/* Link number out of range */
#define EUNATCH		94	/* Protocol driver not attached */
#define ENOCSI		95	/* No CSI structure available */
#define EL2HLT		96	/* Level 2 halted */
#define EBADE		97	/* Invalid exchange */
#define EBADR		98	/* Invalid request descriptor */
#define EXFULL		99	/* Exchange full */
#define ENOANO		100	/* No anode */
#define EBADRQC		101	/* Invalid request code */
#define EBADSLT		102	/* Invalid slot */
#define EDEADLOCK	EDEADLK
#define EBFONT		104	/* Bad font file format */
#define ENONET		105	/* Machine is not on the network */
#define ENOLINK		106	/* Link has been severed */
#define EADV		107	/* Advertise error */
#define ESRMNT		108	/* Srmount error */
#define ECOMM		109	/* Communication error on send */
#define EMULTIHOP	110	/* Multihop attempted */
#define EDOTDOT		111	/* RFS specific error */
#define EOVERFLOW	112	/* Value too large for defined data type */
#define ENOTUNIQ	113	/* Name not unique on network */
#define EBADFD		114	/* File descriptor in bad state */
#define EREMCHG		115	/* Remote address changed */
#define EUCLEAN		117	/* Structure needs cleaning */
#define ENOTNAM		118	/* Not a XENIX named type file */
#define ENAVAIL		119	/* No XENIX semaphores available */
#define EISNAM		120	/* Is a named type file */
#define EREMOTEIO	121	/* Remote I/O error */
#define ELIBACC		122	/* Can not access a needed shared library */
#define ELIBBAD		123	/* Accessing a corrupted shared library */
#define ELIBSCN		124	/* .lib section in a.out corrupted */
#define ELIBMAX		125	/* Attempting to link in too many shared libraries */
#define ELIBEXEC	126	/* Cannot exec a shared library directly */
#define ERESTART	127	/* Interrupted system call should be restarted */
#define ESTRPIPE	128	/* Streams pipe error */
#define ENOMEDIUM	129	/* No medium found */
#define EMEDIUMTYPE	130	/* Wrong medium type */
#define	ECANCELED	131	/* Operation Cancelled */
#define	ENOKEY		132	/* Required key not available */
#define	EKEYEXPIRED	133	/* Key has expired */
#define	EKEYREVOKED	134	/* Key has been revoked */
#define	EKEYREJECTED	135	/* Key was rejected by service */

#define __SYS_NERR  ((EKEYREJECTED) + 1)

#elif defined(__mips__)

#define EPERM		 1	/* Operation not permitted */
#define ENOENT		 2	/* No such file or directory */
#define ESRCH		 3	/* No such process */
#define EINTR		 4	/* Interrupted system call */
#define EIO		 5	/* I/O error */
#define ENXIO		 6	/* No such device or address */
#define E2BIG		 7	/* Arg list too long */
#define ENOEXEC		 8	/* Exec format error */
#define EBADF		 9	/* Bad file number */
#define ECHILD		10	/* No child processes */
#define EAGAIN		11	/* Try again */
#define ENOMEM		12	/* Out of memory */
#define EACCES		13	/* Permission denied */
#define EFAULT		14	/* Bad address */
#define ENOTBLK		15	/* Block device required */
#define EBUSY		16	/* Device or resource busy */
#define EEXIST		17	/* File exists */
#define EXDEV		18	/* Cross-device link */
#define ENODEV		19	/* No such device */
#define ENOTDIR		20	/* Not a directory */
#define EISDIR		21	/* Is a directory */
#define EINVAL		22	/* Invalid argument */
#define ENFILE		23	/* File table overflow */
#define EMFILE		24	/* Too many open files */
#define ENOTTY		25	/* Not a typewriter */
#define ETXTBSY		26	/* Text file busy */
#define EFBIG		27	/* File too large */
#define ENOSPC		28	/* No space left on device */
#define ESPIPE		29	/* Illegal seek */
#define EROFS		30	/* Read-only file system */
#define EMLINK		31	/* Too many links */
#define EPIPE		32	/* Broken pipe */
#define EDOM		33	/* Math argument out of domain of func */
#define ERANGE		34	/* Math result not representable */
#define ENOMSG		35	/* No message of desired type */
#define EIDRM		36	/* Identifier removed */
#define ECHRNG		37	/* Channel number out of range */
#define EL2NSYNC	38	/* Level 2 not synchronized */
#define EL3HLT		39	/* Level 3 halted */
#define EL3RST		40	/* Level 3 reset */
#define ELNRNG		41	/* Link number out of range */
#define EUNATCH		42	/* Protocol driver not attached */
#define ENOCSI		43	/* No CSI structure available */
#define EL2HLT		44	/* Level 2 halted */
#define EDEADLK		45	/* Resource deadlock would occur */
#define ENOLCK		46	/* No record locks available */
#define EBADE		50	/* Invalid exchange */
#define EBADR		51	/* Invalid request descriptor */
#define EXFULL		52	/* Exchange full */
#define ENOANO		53	/* No anode */
#define EBADRQC		54	/* Invalid request code */
#define EBADSLT		55	/* Invalid slot */
#define EDEADLOCK	56	/* File locking deadlock error */
#define EBFONT		59	/* Bad font file format */
#define ENOSTR		60	/* Device not a stream */
#define ENODATA		61	/* No data available */
#define ETIME		62	/* Timer expired */
#define ENOSR		63	/* Out of streams resources */
#define ENONET		64	/* Machine is not on the network */
#define ENOPKG		65	/* Package not installed */
#define EREMOTE		66	/* Object is remote */
#define ENOLINK		67	/* Link has been severed */
#define EADV		68	/* Advertise error */
#define ESRMNT		69	/* Srmount error */
#define ECOMM		70	/* Communication error on send */
#define EPROTO		71	/* Protocol error */
#define EDOTDOT		73	/* RFS specific error */
#define EMULTIHOP	74	/* Multihop attempted */
#define EBADMSG		77	/* Not a data message */
#define ENAMETOOLONG	78	/* File name too long */
#define EOVERFLOW	79	/* Value too large for defined data type */
#define ENOTUNIQ	80	/* Name not unique on network */
#define EBADFD		81	/* File descriptor in bad state */
#define EREMCHG		82	/* Remote address changed */
#define ELIBACC		83	/* Can not access a needed shared library */
#define ELIBBAD		84	/* Accessing a corrupted shared library */
#define ELIBSCN		85	/* .lib section in a.out corrupted */
#define ELIBMAX		86	/* Attempting to link in too many shared libraries */
#define ELIBEXEC	87	/* Cannot exec a shared library directly */
#define EILSEQ		88	/* Illegal byte sequence */
#define ENOSYS		89	/* Function not implemented */
#define ELOOP		90	/* Too many symbolic links encountered */
#define ERESTART	91	/* Interrupted system call should be restarted */
#define ESTRPIPE	92	/* Streams pipe error */
#define ENOTEMPTY	93	/* Directory not empty */
#define EUSERS		94	/* Too many users */
#define ENOTSOCK	95	/* Socket operation on non-socket */
#define EDESTADDRREQ	96	/* Destination address required */
#define EMSGSIZE	97	/* Message too long */
#define EPROTOTYPE	98	/* Protocol wrong type for socket */
#define ENOPROTOOPT	99	/* Protocol not available */
#define EPROTONOSUPPORT	120	/* Protocol not supported */
#define ESOCKTNOSUPPORT	121	/* Socket type not supported */
#define EOPNOTSUPP	122	/* Operation not supported on transport endpoint */
#define ENOTSUP		EOPNOTSUPP/* Operation not supported on transport endpoint */
#define EPFNOSUPPORT	123	/* Protocol family not supported */
#define EAFNOSUPPORT	124	/* Address family not supported by protocol */
#define EADDRINUSE	125	/* Address already in use */
#define EADDRNOTAVAIL	126	/* Cannot assign requested address */
#define ENETDOWN	127	/* Network is down */
#define ENETUNREACH	128	/* Network is unreachable */
#define ENETRESET	129	/* Network dropped connection because of reset */
#define ECONNABORTED	130	/* Software caused connection abort */
#define ECONNRESET	131	/* Connection reset by peer */
#define ENOBUFS		132	/* No buffer space available */
#define EISCONN		133	/* Transport endpoint is already connected */
#define ENOTCONN	134	/* Transport endpoint is not connected */
#define EUCLEAN		135	/* Structure needs cleaning */
#define ENOTNAM		137	/* Not a XENIX named type file */
#define ENAVAIL		138	/* No XENIX semaphores available */
#define EISNAM		139	/* Is a named type file */
#define EREMOTEIO	140	/* Remote I/O error */
#define EINIT		141	/* Reserved */
#define EREMDEV		142	/* Error 142 */
#define ESHUTDOWN	143	/* Cannot send after transport endpoint shutdown */
#define ETOOMANYREFS	144	/* Too many references: cannot splice */
#define ETIMEDOUT	145	/* Connection timed out */
#define ECONNREFUSED	146	/* Connection refused */
#define EHOSTDOWN	147	/* Host is down */
#define EHOSTUNREACH	148	/* No route to host */
#define EWOULDBLOCK	EAGAIN	/* Operation would block */
#define EALREADY	149	/* Operation already in progress */
#define EINPROGRESS	150	/* Operation now in progress */
#define ESTALE		151	/* Stale NFS file handle */
#define ECANCELED	158	/* AIO operation canceled */
#define ENOMEDIUM	159	/* No medium found */
#define EMEDIUMTYPE	160	/* Wrong medium type */
#define	ENOKEY		161	/* Required key not available */
#define	EKEYEXPIRED	162	/* Key has expired */
#define	EKEYREVOKED	163	/* Key has been revoked */
#define	EKEYREJECTED	164	/* Key was rejected by service */
#define EDQUOT		1133	/* Quota exceeded */

#define __SYS_NERR  ((EKEYREJECTED) + 1)

#elif defined(__sparc__)

#define EPERM		 1	/* Operation not permitted */
#define ENOENT		 2	/* No such file or directory */
#define ESRCH		 3	/* No such process */
#define EINTR		 4	/* Interrupted system call */
#define EIO		 5	/* I/O error */
#define ENXIO		 6	/* No such device or address */
#define E2BIG		 7	/* Arg list too long */
#define ENOEXEC		 8	/* Exec format error */
#define EBADF		 9	/* Bad file number */
#define ECHILD		10	/* No child processes */
#define EAGAIN		11	/* Try again */
#define ENOMEM		12	/* Out of memory */
#define EACCES		13	/* Permission denied */
#define EFAULT		14	/* Bad address */
#define ENOTBLK		15	/* Block device required */
#define EBUSY		16	/* Device or resource busy */
#define EEXIST		17	/* File exists */
#define EXDEV		18	/* Cross-device link */
#define ENODEV		19	/* No such device */
#define ENOTDIR		20	/* Not a directory */
#define EISDIR		21	/* Is a directory */
#define EINVAL		22	/* Invalid argument */
#define ENFILE		23	/* File table overflow */
#define EMFILE		24	/* Too many open files */
#define ENOTTY		25	/* Not a typewriter */
#define ETXTBSY		26	/* Text file busy */
#define EFBIG		27	/* File too large */
#define ENOSPC		28	/* No space left on device */
#define ESPIPE		29	/* Illegal seek */
#define EROFS		30	/* Read-only file system */
#define EMLINK		31	/* Too many links */
#define EPIPE		32	/* Broken pipe */
#define EDOM		33	/* Math argument out of domain of func */
#define ERANGE		34	/* Math result not representable */
#define EWOULDBLOCK	EAGAIN	/* Operation would block */
#define EINPROGRESS	36	/* Operation now in progress */
#define EALREADY	37	/* Operation already in progress */
#define ENOTSOCK	38	/* Socket operation on non-socket */
#define EDESTADDRREQ	39	/* Destination address required */
#define EMSGSIZE	40	/* Message too long */
#define EPROTOTYPE	41	/* Protocol wrong type for socket */
#define ENOPROTOOPT	42	/* Protocol not available */
#define EPROTONOSUPPORT	43	/* Protocol not supported */
#define ESOCKTNOSUPPORT	44	/* Socket type not supported */
#define EOPNOTSUPP	45	/* Op not supported on transport endpoint */
#define ENOTSUP		EOPNOTSUPP/* Operation not supported on transport endpoint */
#define EPFNOSUPPORT	46	/* Protocol family not supported */
#define EAFNOSUPPORT	47	/* Address family not supported by protocol */
#define EADDRINUSE	48	/* Address already in use */
#define EADDRNOTAVAIL	49	/* Cannot assign requested address */
#define ENETDOWN	50	/* Network is down */
#define ENETUNREACH	51	/* Network is unreachable */
#define ENETRESET	52	/* Net dropped connection because of reset */
#define ECONNABORTED	53	/* Software caused connection abort */
#define ECONNRESET	54	/* Connection reset by peer */
#define ENOBUFS		55	/* No buffer space available */
#define EISCONN		56	/* Transport endpoint is already connected */
#define ENOTCONN	57	/* Transport endpoint is not connected */
#define ESHUTDOWN	58	/* No send after transport endpoint shutdown */
#define ETOOMANYREFS	59	/* Too many references: cannot splice */
#define ETIMEDOUT	60	/* Connection timed out */
#define ECONNREFUSED	61	/* Connection refused */
#define ELOOP		62	/* Too many symbolic links encountered */
#define ENAMETOOLONG	63	/* File name too long */
#define EHOSTDOWN	64	/* Host is down */
#define EHOSTUNREACH	65	/* No route to host */
#define ENOTEMPTY	66	/* Directory not empty */
#define EPROCLIM	67	/* SUNOS: Too many processes */
#define EUSERS		68	/* Too many users */
#define EDQUOT		69	/* Quota exceeded */
#define ESTALE		70	/* Stale NFS file handle */
#define EREMOTE		71	/* Object is remote */
#define ENOSTR		72	/* Device not a stream */
#define ETIME		73	/* Timer expired */
#define ENOSR		74	/* Out of streams resources */
#define ENOMSG		75	/* No message of desired type */
#define EBADMSG		76	/* Not a data message */
#define EIDRM		77	/* Identifier removed */
#define EDEADLK		78	/* Resource deadlock would occur */
#define ENOLCK		79	/* No record locks available */
#define ENONET		80	/* Machine is not on the network */
#define ERREMOTE	81	/* SunOS: Too many lvls of remote in path */
#define ENOLINK		82	/* Link has been severed */
#define EADV		83	/* Advertise error */
#define ESRMNT		84	/* Srmount error */
#define ECOMM		85	/* Communication error on send */
#define EPROTO		86	/* Protocol error */
#define EMULTIHOP	87	/* Multihop attempted */
#define EDOTDOT		88	/* RFS specific error */
#define EREMCHG		89	/* Remote address changed */
#define ENOSYS		90	/* Function not implemented */
#define ESTRPIPE	91	/* Streams pipe error */
#define EOVERFLOW	92	/* Value too large for defined data type */
#define EBADFD		93	/* File descriptor in bad state */
#define ECHRNG		94	/* Channel number out of range */
#define EL2NSYNC	95	/* Level 2 not synchronized */
#define EL3HLT		96	/* Level 3 halted */
#define EL3RST		97	/* Level 3 reset */
#define ELNRNG		98	/* Link number out of range */
#define EUNATCH		99	/* Protocol driver not attached */
#define ENOCSI		100	/* No CSI structure available */
#define EL2HLT		101	/* Level 2 halted */
#define EBADE		102	/* Invalid exchange */
#define EBADR		103	/* Invalid request descriptor */
#define EXFULL		104	/* Exchange full */
#define ENOANO		105	/* No anode */
#define EBADRQC		106	/* Invalid request code */
#define EBADSLT		107	/* Invalid slot */
#define EDEADLOCK	108	/* File locking deadlock error */
#define EBFONT		109	/* Bad font file format */
#define ELIBEXEC	110	/* Cannot exec a shared library directly */
#define ENODATA		111	/* No data available */
#define ELIBBAD		112	/* Accessing a corrupted shared library */
#define ENOPKG		113	/* Package not installed */
#define ELIBACC		114	/* Can not access a needed shared library */
#define ENOTUNIQ	115	/* Name not unique on network */
#define ERESTART	116	/* Interrupted syscall should be restarted */
#define EUCLEAN		117	/* Structure needs cleaning */
#define ENOTNAM		118	/* Not a XENIX named type file */
#define ENAVAIL		119	/* No XENIX semaphores available */
#define EISNAM		120	/* Is a named type file */
#define EREMOTEIO	121	/* Remote I/O error */
#define EILSEQ		122	/* Illegal byte sequence */
#define ELIBMAX		123	/* Atmpt to link in too many shared libs */
#define ELIBSCN		124	/* .lib section in a.out corrupted */
#define ENOMEDIUM	125	/* No medium found */
#define EMEDIUMTYPE	126	/* Wrong medium type */
#define	ECANCELED	127	/* Operation Cancelled */
#define	ENOKEY		128	/* Required key not available */
#define	EKEYEXPIRED	129	/* Key has expired */
#define	EKEYREVOKED	130	/* Key has been revoked */
#define	EKEYREJECTED	131	/* Key was rejected by service */

#define __SYS_NERR  ((EKEYREJECTED) + 1)

#elif defined(__hppa__)

#define	EPERM		 1	/* Operation not permitted */
#define	ENOENT		 2	/* No such file or directory */
#define	ESRCH		 3	/* No such process */
#define	EINTR		 4	/* Interrupted system call */
#define	EIO		 5	/* I/O error */
#define	ENXIO		 6	/* No such device or address */
#define	E2BIG		 7	/* Argument list too long */
#define	ENOEXEC		 8	/* Exec format error */
#define	EBADF		 9	/* Bad file number */
#define	ECHILD		10	/* No child processes */
#define	EAGAIN		11	/* Try again */
#define	ENOMEM		12	/* Out of memory */
#define	EACCES		13	/* Permission denied */
#define	EFAULT		14	/* Bad address */
#define	ENOTBLK		15	/* Block device required */
#define	EBUSY		16	/* Device or resource busy */
#define	EEXIST		17	/* File exists */
#define	EXDEV		18	/* Cross-device link */
#define	ENODEV		19	/* No such device */
#define	ENOTDIR		20	/* Not a directory */
#define	EISDIR		21	/* Is a directory */
#define	EINVAL		22	/* Invalid argument */
#define	ENFILE		23	/* File table overflow */
#define	EMFILE		24	/* Too many open files */
#define	ENOTTY		25	/* Not a typewriter */
#define	ETXTBSY		26	/* Text file busy */
#define	EFBIG		27	/* File too large */
#define	ENOSPC		28	/* No space left on device */
#define	ESPIPE		29	/* Illegal seek */
#define	EROFS		30	/* Read-only file system */
#define	EMLINK		31	/* Too many links */
#define	EPIPE		32	/* Broken pipe */
#define	EDOM		33	/* Math argument out of domain of func */
#define	ERANGE		34	/* Math result not representable */
#define	ENOMSG		35	/* No message of desired type */
#define	EIDRM		36	/* Identifier removed */
#define	ECHRNG		37	/* Channel number out of range */
#define	EL2NSYNC	38	/* Level 2 not synchronized */
#define	EL3HLT		39	/* Level 3 halted */
#define	EL3RST		40	/* Level 3 reset */
#define	ELNRNG		41	/* Link number out of range */
#define	EUNATCH		42	/* Protocol driver not attached */
#define	ENOCSI		43	/* No CSI structure available */
#define	EL2HLT		44	/* Level 2 halted */
#define	EDEADLK		45	/* Resource deadlock would occur */
#define	EDEADLOCK	EDEADLK
#define	ENOLCK		46	/* No record locks available */
#define	EILSEQ		47	/* Illegal byte sequence */

#define	ENONET		50	/* Machine is not on the network */
#define	ENODATA		51	/* No data available */
#define	ETIME		52	/* Timer expired */
#define	ENOSR		53	/* Out of streams resources */
#define	ENOSTR		54	/* Device not a stream */
#define	ENOPKG		55	/* Package not installed */

#define	ENOLINK		57	/* Link has been severed */
#define	EADV		58	/* Advertise error */
#define	ESRMNT		59	/* Srmount error */
#define	ECOMM		60	/* Communication error on send */
#define	EPROTO		61	/* Protocol error */

#define	EMULTIHOP	64	/* Multihop attempted */

#define	EDOTDOT		66	/* RFS specific error */
#define	EBADMSG		67	/* Not a data message */
#define	EUSERS		68	/* Too many users */
#define	EDQUOT		69	/* Quota exceeded */
#define	ESTALE		70	/* Stale NFS file handle */
#define	EREMOTE		71	/* Object is remote */
#define	EOVERFLOW	72	/* Value too large for defined data type */

/* these errnos are defined by Linux but not HPUX. */

#define	EBADE		160	/* Invalid exchange */
#define	EBADR		161	/* Invalid request descriptor */
#define	EXFULL		162	/* Exchange full */
#define	ENOANO		163	/* No anode */
#define	EBADRQC		164	/* Invalid request code */
#define	EBADSLT		165	/* Invalid slot */
#define	EBFONT		166	/* Bad font file format */
#define	ENOTUNIQ	167	/* Name not unique on network */
#define	EBADFD		168	/* File descriptor in bad state */
#define	EREMCHG		169	/* Remote address changed */
#define	ELIBACC		170	/* Can not access a needed shared library */
#define	ELIBBAD		171	/* Accessing a corrupted shared library */
#define	ELIBSCN		172	/* .lib section in a.out corrupted */
#define	ELIBMAX		173	/* Attempting to link in too many shared libraries */
#define	ELIBEXEC	174	/* Cannot exec a shared library directly */
#define	ERESTART	175	/* Interrupted system call should be restarted */
#define	ESTRPIPE	176	/* Streams pipe error */
#define	EUCLEAN		177	/* Structure needs cleaning */
#define	ENOTNAM		178	/* Not a XENIX named type file */
#define	ENAVAIL		179	/* No XENIX semaphores available */
#define	EISNAM		180	/* Is a named type file */
#define	EREMOTEIO	181	/* Remote I/O error */
#define	ENOMEDIUM	182	/* No medium found */
#define	EMEDIUMTYPE	183	/* Wrong medium type */
#define	ENOKEY		184	/* Required key not available */
#define	EKEYEXPIRED	185	/* Key has expired */
#define	EKEYREVOKED	186	/* Key has been revoked */
#define	EKEYREJECTED	187	/* Key was rejected by service */

/* We now return you to your regularly scheduled HPUX. */

#define ENOSYM		215	/* symbol does not exist in executable */
#define	ENOTSOCK	216	/* Socket operation on non-socket */
#define	EDESTADDRREQ	217	/* Destination address required */
#define	EMSGSIZE	218	/* Message too long */
#define	EPROTOTYPE	219	/* Protocol wrong type for socket */
#define	ENOPROTOOPT	220	/* Protocol not available */
#define	EPROTONOSUPPORT	221	/* Protocol not supported */
#define	ESOCKTNOSUPPORT	222	/* Socket type not supported */
#define	EOPNOTSUPP	223	/* Operation not supported on transport endpoint */
#define	EPFNOSUPPORT	224	/* Protocol family not supported */
#define	EAFNOSUPPORT	225	/* Address family not supported by protocol */
#define	EADDRINUSE	226	/* Address already in use */
#define	EADDRNOTAVAIL	227	/* Cannot assign requested address */
#define	ENETDOWN	228	/* Network is down */
#define	ENETUNREACH	229	/* Network is unreachable */
#define	ENETRESET	230	/* Network dropped connection because of reset */
#define	ECONNABORTED	231	/* Software caused connection abort */
#define	ECONNRESET	232	/* Connection reset by peer */
#define	ENOBUFS		233	/* No buffer space available */
#define	EISCONN		234	/* Transport endpoint is already connected */
#define	ENOTCONN	235	/* Transport endpoint is not connected */
#define	ESHUTDOWN	236	/* Cannot send after transport endpoint shutdown */
#define	ETOOMANYREFS	237	/* Too many references: cannot splice */
#define EREFUSED	ECONNREFUSED	/* for HP's NFS apparently */
#define	ETIMEDOUT	238	/* Connection timed out */
#define	ECONNREFUSED	239	/* Connection refused */
#define EREMOTERELEASE	240	/* Remote peer released connection */
#define	EHOSTDOWN	241	/* Host is down */
#define	EHOSTUNREACH	242	/* No route to host */

#define	EALREADY	244	/* Operation already in progress */
#define	EINPROGRESS	245	/* Operation now in progress */
#define	EWOULDBLOCK	246	/* Operation would block (Linux returns EAGAIN) */
#define	ENOTEMPTY	247	/* Directory not empty */
#define	ENAMETOOLONG	248	/* File name too long */
#define	ELOOP		249	/* Too many symbolic links encountered */
#define	ENOSYS		251	/* Function not implemented */

#define ENOTSUP		252	/* Function not implemented (POSIX.4 / HPUX) */
#define ECANCELLED	253	/* aio request was canceled before complete (POSIX.4 / HPUX) */

#define __SYS_NERR  ((ECANCELLED) + 1)

#else

/* i386, arm, ppc, x86_64, ia64 */

#define EPERM		 1	/* Operation not permitted */
#define ENOENT		 2	/* No such file or directory */
#define ESRCH		 3	/* No such process */
#define EINTR		 4	/* Interrupted system call */
#define EIO		 5	/* I/O error */
#define ENXIO		 6	/* No such device or address */
#define E2BIG		 7	/* Arg list too long */
#define ENOEXEC		 8	/* Exec format error */
#define EBADF		 9	/* Bad file number */
#define ECHILD		10	/* No child processes */
#define EAGAIN		11	/* Try again */
#define ENOMEM		12	/* Out of memory */
#define EACCES		13	/* Permission denied */
#define EFAULT		14	/* Bad address */
#define ENOTBLK		15	/* Block device required */
#define EBUSY		16	/* Device or resource busy */
#define EEXIST		17	/* File exists */
#define EXDEV		18	/* Cross-device link */
#define ENODEV		19	/* No such device */
#define ENOTDIR		20	/* Not a directory */
#define EISDIR		21	/* Is a directory */
#define EINVAL		22	/* Invalid argument */
#define ENFILE		23	/* File table overflow */
#define EMFILE		24	/* Too many open files */
#define ENOTTY		25	/* Not a typewriter */
#define ETXTBSY		26	/* Text file busy */
#define EFBIG		27	/* File too large */
#define ENOSPC		28	/* No space left on device */
#define ESPIPE		29	/* Illegal seek */
#define EROFS		30	/* Read-only file system */
#define EMLINK		31	/* Too many links */
#define EPIPE		32	/* Broken pipe */
#define EDOM		33	/* Math argument out of domain of func */
#define ERANGE		34	/* Math result not representable */
#define EDEADLK		35	/* Resource deadlock would occur */
#define ENAMETOOLONG	36	/* File name too long */
#define ENOLCK		37	/* No record locks available */
#define ENOSYS		38	/* Function not implemented */
#define ENOTEMPTY	39	/* Directory not empty */
#define ELOOP		40	/* Too many symbolic links encountered */
#define EWOULDBLOCK	EAGAIN	/* Operation would block */
#define ENOMSG		42	/* No message of desired type */
#define EIDRM		43	/* Identifier removed */
#define ECHRNG		44	/* Channel number out of range */
#define EL2NSYNC	45	/* Level 2 not synchronized */
#define EL3HLT		46	/* Level 3 halted */
#define EL3RST		47	/* Level 3 reset */
#define ELNRNG		48	/* Link number out of range */
#define EUNATCH		49	/* Protocol driver not attached */
#define ENOCSI		50	/* No CSI structure available */
#define EL2HLT		51	/* Level 2 halted */
#define EBADE		52	/* Invalid exchange */
#define EBADR		53	/* Invalid request descriptor */
#define EXFULL		54	/* Exchange full */
#define ENOANO		55	/* No anode */
#define EBADRQC		56	/* Invalid request code */
#define EBADSLT		57	/* Invalid slot */
#define EDEADLOCK	EDEADLK
#define EBFONT		59	/* Bad font file format */
#define ENOSTR		60	/* Device not a stream */
#define ENODATA		61	/* No data available */
#define ETIME		62	/* Timer expired */
#define ENOSR		63	/* Out of streams resources */
#define ENONET		64	/* Machine is not on the network */
#define ENOPKG		65	/* Package not installed */
#define EREMOTE		66	/* Object is remote */
#define ENOLINK		67	/* Link has been severed */
#define EADV		68	/* Advertise error */
#define ESRMNT		69	/* Srmount error */
#define ECOMM		70	/* Communication error on send */
#define EPROTO		71	/* Protocol error */
#define EMULTIHOP	72	/* Multihop attempted */
#define EDOTDOT		73	/* RFS specific error */
#define EBADMSG		74	/* Not a data message */
#define EOVERFLOW	75	/* Value too large for defined data type */
#define ENOTUNIQ	76	/* Name not unique on network */
#define EBADFD		77	/* File descriptor in bad state */
#define EREMCHG		78	/* Remote address changed */
#define ELIBACC		79	/* Can not access a needed shared library */
#define ELIBBAD		80	/* Accessing a corrupted shared library */
#define ELIBSCN		81	/* .lib section in a.out corrupted */
#define ELIBMAX		82	/* Attempting to link in too many shared libraries */
#define ELIBEXEC	83	/* Cannot exec a shared library directly */
#define EILSEQ		84	/* Illegal byte sequence */
#define ERESTART	85	/* Interrupted system call should be restarted */
#define ESTRPIPE	86	/* Streams pipe error */
#define EUSERS		87	/* Too many users */
#define ENOTSOCK	88	/* Socket operation on non-socket */
#define EDESTADDRREQ	89	/* Destination address required */
#define EMSGSIZE	90	/* Message too long */
#define EPROTOTYPE	91	/* Protocol wrong type for socket */
#define ENOPROTOOPT	92	/* Protocol not available */
#define EPROTONOSUPPORT	93	/* Protocol not supported */
#define ESOCKTNOSUPPORT	94	/* Socket type not supported */
#define EOPNOTSUPP	95	/* Operation not supported on transport endpoint */
#define ENOTSUP		EOPNOTSUPP/* Operation not supported on transport endpoint */
#define EPFNOSUPPORT	96	/* Protocol family not supported */
#define EAFNOSUPPORT	97	/* Address family not supported by protocol */
#define EADDRINUSE	98	/* Address already in use */
#define EADDRNOTAVAIL	99	/* Cannot assign requested address */
#define ENETDOWN	100	/* Network is down */
#define ENETUNREACH	101	/* Network is unreachable */
#define ENETRESET	102	/* Network dropped connection because of reset */
#define ECONNABORTED	103	/* Software caused connection abort */
#define ECONNRESET	104	/* Connection reset by peer */
#define ENOBUFS		105	/* No buffer space available */
#define EISCONN		106	/* Transport endpoint is already connected */
#define ENOTCONN	107	/* Transport endpoint is not connected */
#define ESHUTDOWN	108	/* Cannot send after transport endpoint shutdown */
#define ETOOMANYREFS	109	/* Too many references: cannot splice */
#define ETIMEDOUT	110	/* Connection timed out */
#define ECONNREFUSED	111	/* Connection refused */
#define EHOSTDOWN	112	/* Host is down */
#define EHOSTUNREACH	113	/* No route to host */
#define EALREADY	114	/* Operation already in progress */
#define EINPROGRESS	115	/* Operation now in progress */
#define ESTALE		116	/* Stale NFS file handle */
#define EUCLEAN		117	/* Structure needs cleaning */
#define ENOTNAM		118	/* Not a XENIX named type file */
#define ENAVAIL		119	/* No XENIX semaphores available */
#define EISNAM		120	/* Is a named type file */
#define EREMOTEIO	121	/* Remote I/O error */
#define EDQUOT		122	/* Quota exceeded */
#define ENOMEDIUM	123	/* No medium found */
#define EMEDIUMTYPE	124	/* Wrong medium type */
#define	ECANCELED	125	/* Operation Canceled */
#define	ENOKEY		126	/* Required key not available */
#define	EKEYEXPIRED	127	/* Key has expired */
#define	EKEYREVOKED	128	/* Key has been revoked */
#define	EKEYREJECTED	129	/* Key was rejected by service */
#define __SYS_NERR  ((EKEYREJECTED) + 1)
#endif

#ifndef __ASSEMBLER__

#include <sys/cdefs.h>

__BEGIN_DECLS

#ifndef _REENTRANT
extern int errno;
#else
#define errno (*__errno_location())
#endif

extern int *__errno_location(void);

#define __set_errno(x) errno=(x)

#ifdef _BSD_SOURCE
/* don't use, use strerror() instead! */
extern const char *const sys_errlist[] __attribute_dontuse__;
extern int sys_nerr __attribute_dontuse__;
#endif

#ifdef _GNU_SOURCE
extern char* program_invocation_name __attribute_dontuse__;
extern char* program_invocation_short_name __attribute_dontuse__;
#endif

__END_DECLS

#endif

#endif
