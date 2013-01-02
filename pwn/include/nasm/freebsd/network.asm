        ;; From /usr/include/sys/socket.h
        %define SOCK_STREAM     1               ; stream socket
        %define SOCK_DGRAM      2               ; datagram socket
        %define SOCK_RAW        3               ; raw-protocol interface
        %define SOCK_RDM        4               ; reliably-delivered message
        %define SOCK_SEQPACKET  5               ; sequenced packet stream
        %define SO_DEBUG        0x0001          ; turn on debugging info recording
        %define SO_ACCEPTCONN   0x0002          ; socket has had listen()
        %define SO_REUSEADDR    0x0004          ; allow local address reuse
        %define SO_KEEPALIVE    0x0008          ; keep connections alive
        %define SO_DONTROUTE    0x0010          ; just use interface addresses
        %define SO_BROADCAST    0x0020          ; permit sending of broadcast msgs
        %define SO_USELOOPBACK  0x0040          ; bypass hardware when possible
        %define SO_LINGER       0x0080          ; linger on close if data present
        %define SO_OOBINLINE    0x0100          ; leave received OOB data in line
        %define SO_REUSEPORT    0x0200          ; allow local address & port reuse
        %define SO_TIMESTAMP    0x0400          ; timestamp received dgram traffic
        %define SO_NOSIGPIPE    0x0800          ; no SIGPIPE from EPIPE
        %define SO_ACCEPTFILTER 0x1000          ; there is an accept filter
        %define SO_BINTIME      0x2000          ; timestamp received dgram traffic
        %define SO_NO_OFFLOAD   0x4000          ; socket cannot be offloaded
        %define SO_NO_DDP       0x8000          ; disable direct data placement
        %define SO_SNDBUF       0x1001          ; send buffer size
        %define SO_RCVBUF       0x1002          ; receive buffer size
        %define SO_SNDLOWAT     0x1003          ; send low-water mark
        %define SO_RCVLOWAT     0x1004          ; receive low-water mark
        %define SO_SNDTIMEO     0x1005          ; send timeout
        %define SO_RCVTIMEO     0x1006          ; receive timeout
        %define SO_ERROR        0x1007          ; get error status and clear
        %define SO_TYPE         0x1008          ; get socket type
        %define SO_LABEL        0x1009          ; socket's MAC label
        %define SO_PEERLABEL    0x1010          ; socket's peer's MAC label
        %define SO_LISTENQLIMIT 0x1011          ; socket's backlog limit
        %define SO_LISTENQLEN   0x1012          ; socket's complete queue length
        %define SO_LISTENINCQLEN        0x1013  ; socket's incomplete queue length
        %define SO_SETFIB       0x1014          ; use this FIB to route
        %define SO_USER_COOKIE  0x1015          ; user cookie (dummynet etc.)
        %define SOL_SOCKET      0xffff          ; options for socket level
        %define AF_UNSPEC       0               ; unspecified
        %define AF_LOCAL        AF_UNIX         ; local to host (pipes, portals)
        %define AF_UNIX         1               ; standardized name for AF_LOCAL
        %define AF_INET         2               ; internetwork: UDP, TCP, etc.
        %define AF_IMPLINK      3               ; arpanet imp addresses
        %define AF_PUP          4               ; pup protocols: e.g. BSP
        %define AF_CHAOS        5               ; mit CHAOS protocols
        %define AF_NETBIOS      6               ; SMB protocols
        %define AF_ISO          7               ; ISO protocols
        %define AF_OSI          AF_ISO
        %define AF_ECMA         8               ; European computer manufacturers
        %define AF_DATAKIT      9               ; datakit protocols
        %define AF_CCITT        10              ; CCITT protocols, X.25 etc
        %define AF_SNA          11              ; IBM SNA
        %define AF_DECnet       12              ; DECnet
        %define AF_DLI          13              ; DEC Direct data link interface
        %define AF_LAT          14              ; LAT
        %define AF_HYLINK       15              ; NSC Hyperchannel
        %define AF_APPLETALK    16              ; Apple Talk
        %define AF_ROUTE        17              ; Internal Routing Protocol
        %define AF_LINK         18              ; Link layer interface
        %define pseudo_AF_XTP   19              ; eXpress Transfer Protocol (no AF)
        %define AF_COIP         20              ; connection-oriented IP, aka ST II
        %define AF_CNT          21              ; Computer Network Technology
        %define pseudo_AF_RTIP  22              ; Help Identify RTIP packets
        %define AF_IPX          23              ; Novell Internet Protocol
        %define AF_SIP          24              ; Simple Internet Protocol
        %define pseudo_AF_PIP   25              ; Help Identify PIP packets
        %define AF_ISDN         26              ; Integrated Services Digital Network
        %define AF_E164         AF_ISDN         ; CCITT E.164 recommendation
        %define pseudo_AF_KEY   27              ; Internal key-management function
        %define AF_INET6        28              ; IPv6
        %define AF_NATM         29              ; native ATM access
        %define AF_ATM          30              ; ATM
        %define AF_NETGRAPH     32              ; Netgraph sockets
        %define AF_SLOW         33              ; 802.3ad slow protocol
        %define AF_SCLUSTER     34              ; Sitara cluster protocol
        %define AF_ARP          35
        %define AF_BLUETOOTH    36              ; Bluetooth sockets
        %define AF_IEEE80211    37              ; IEEE 802.11 protocol
        %define AF_MAX          38
        %define AF_VENDOR00 39
        %define AF_VENDOR01 41
        %define AF_VENDOR02 43
        %define AF_VENDOR03 45
        %define AF_VENDOR04 47
        %define AF_VENDOR05 49
        %define AF_VENDOR06 51
        %define AF_VENDOR07 53
        %define AF_VENDOR08 55
        %define AF_VENDOR09 57
        %define AF_VENDOR10 59
        %define AF_VENDOR11 61
        %define AF_VENDOR12 63
        %define AF_VENDOR13 65
        %define AF_VENDOR14 67
        %define AF_VENDOR15 69
        %define AF_VENDOR16 71
        %define AF_VENDOR17 73
        %define AF_VENDOR18 75
        %define AF_VENDOR19 77
        %define AF_VENDOR20 79
        %define AF_VENDOR21 81
        %define AF_VENDOR22 83
        %define AF_VENDOR23 85
        %define AF_VENDOR24 87
        %define AF_VENDOR25 89
        %define AF_VENDOR26 91
        %define AF_VENDOR27 93
        %define AF_VENDOR28 95
        %define AF_VENDOR29 97
        %define AF_VENDOR30 99
        %define AF_VENDOR31 101
        %define AF_VENDOR32 103
        %define AF_VENDOR33 105
        %define AF_VENDOR34 107
        %define AF_VENDOR35 109
        %define AF_VENDOR36 111
        %define AF_VENDOR37 113
        %define AF_VENDOR38 115
        %define AF_VENDOR39 117
        %define AF_VENDOR40 119
        %define AF_VENDOR41 121
        %define AF_VENDOR42 123
        %define AF_VENDOR43 125
        %define AF_VENDOR44 127
        %define AF_VENDOR45 129
        %define AF_VENDOR46 131
        %define AF_VENDOR47 133
        %define SOCK_MAXADDRLEN 255             ; longest possible addresses
        %define PF_UNSPEC       AF_UNSPEC
        %define PF_LOCAL        AF_LOCAL
        %define PF_UNIX         PF_LOCAL        ; backward compatibility
        %define PF_INET         AF_INET
        %define PF_IMPLINK      AF_IMPLINK
        %define PF_PUP          AF_PUP
        %define PF_CHAOS        AF_CHAOS
        %define PF_NETBIOS      AF_NETBIOS
        %define PF_ISO          AF_ISO
        %define PF_OSI          AF_ISO
        %define PF_ECMA         AF_ECMA
        %define PF_DATAKIT      AF_DATAKIT
        %define PF_CCITT        AF_CCITT
        %define PF_SNA          AF_SNA
        %define PF_DECnet       AF_DECnet
        %define PF_DLI          AF_DLI
        %define PF_LAT          AF_LAT
        %define PF_HYLINK       AF_HYLINK
        %define PF_APPLETALK    AF_APPLETALK
        %define PF_ROUTE        AF_ROUTE
        %define PF_LINK         AF_LINK
        %define PF_XTP          pseudo_AF_XTP   ; really just proto family, no AF
        %define PF_COIP         AF_COIP
        %define PF_CNT          AF_CNT
        %define PF_SIP          AF_SIP
        %define PF_IPX          AF_IPX
        %define PF_RTIP         pseudo_AF_RTIP  ; same format as AF_INET
        %define PF_PIP          pseudo_AF_PIP
        %define PF_ISDN         AF_ISDN
        %define PF_KEY          pseudo_AF_KEY
        %define PF_INET6        AF_INET6
        %define PF_NATM         AF_NATM
        %define PF_ATM          AF_ATM
        %define PF_NETGRAPH     AF_NETGRAPH
        %define PF_SLOW         AF_SLOW
        %define PF_SCLUSTER     AF_SCLUSTER
        %define PF_ARP          AF_ARP
        %define PF_BLUETOOTH    AF_BLUETOOTH
        %define PF_MAX          AF_MAX
        %define NET_MAXID       AF_MAX
        %define NET_RT_DUMP     1               ; dump; may limit to a.f.
        %define NET_RT_FLAGS    2               ; by flags, e.g. RESOLVING
        %define NET_RT_IFLIST   3               ; survey interface list
        %define NET_RT_IFMALIST 4               ; return multicast address list
        %define NET_RT_MAXID    5
        %define SOMAXCONN       128
        %define MSG_OOB         0x1             ; process out-of-band data
        %define MSG_PEEK        0x2             ; peek at incoming message
        %define MSG_DONTROUTE   0x4             ; send without using routing tables
        %define MSG_EOR         0x8             ; data completes record
        %define MSG_TRUNC       0x10            ; data discarded before delivery
        %define MSG_CTRUNC      0x20            ; control data lost before delivery
        %define MSG_WAITALL     0x40            ; wait for full request or error
        %define MSG_NOTIFICATION 0x2000         ; SCTP notification
        %define MSG_DONTWAIT    0x80            ; this message should be nonblocking
        %define MSG_EOF         0x100           ; data completes connection
        %define MSG_NBIO        0x4000          ; FIONBIO mode, used by fifofs
        %define MSG_COMPAT      0x8000          ; used in sendit()
        %define MSG_SOCALLBCK   0x10000         ; for use by socket callbacks - soreceive (TCP)
        %define MSG_NOSIGNAL    0x20000         ; do not generate SIGPIPE on EOF

        ;; From /usr/include/netinet/in.h
        ; Protocols common to RFC 1700, POSIX, and X/Open.
        %define IPPROTO_IP              0               ; dummy for IP
        %define IPPROTO_ICMP            1               ; control message protocol
        %define IPPROTO_TCP             6               ; tcp
        %define IPPROTO_UDP             17              ; user datagram protocol
        %define INADDR_ANY              0x00000000
        %define INADDR_BROADCAST        0xffffffff   ; must be masked
        ; Internet address (a structure for historical reasons).
        ; Socket address, internet style.
        %define IPPROTO_RAW             255             ; raw IP packet
        %define INET_ADDRSTRLEN         16
        %define IPPROTO_HOPOPTS         0               ; IP6 hop-by-hop options
        %define IPPROTO_IGMP            2               ; group mgmt protocol
        %define IPPROTO_GGP             3               ; gateway^2 (deprecated)
        %define IPPROTO_IPV4            4               ; IPv4 encapsulation
        %define IPPROTO_IPIP            IPPROTO_IPV4    ; for compatibility
        %define IPPROTO_ST              7               ; Stream protocol II
        %define IPPROTO_EGP             8               ; exterior gateway protocol
        %define IPPROTO_PIGP            9               ; private interior gateway
        %define IPPROTO_RCCMON          10              ; BBN RCC Monitoring
        %define IPPROTO_NVPII           11              ; network voice protocol
        %define IPPROTO_PUP             12              ; pup
        %define IPPROTO_ARGUS           13              ; Argus
        %define IPPROTO_EMCON           14              ; EMCON
        %define IPPROTO_XNET            15              ; Cross Net Debugger
        %define IPPROTO_CHAOS           16              ; Chaos
        %define IPPROTO_MUX             18              ; Multiplexing
        %define IPPROTO_MEAS            19              ; DCN Measurement Subsystems
        %define IPPROTO_HMP             20              ; Host Monitoring
        %define IPPROTO_PRM             21              ; Packet Radio Measurement
        %define IPPROTO_IDP             22              ; xns idp
        %define IPPROTO_TRUNK1          23              ; Trunk-1
        %define IPPROTO_TRUNK2          24              ; Trunk-2
        %define IPPROTO_LEAF1           25              ; Leaf-1
        %define IPPROTO_LEAF2           26              ; Leaf-2
        %define IPPROTO_RDP             27              ; Reliable Data
        %define IPPROTO_IRTP            28              ; Reliable Transaction
        %define IPPROTO_TP              29              ; tp-4 w/ class negotiation
        %define IPPROTO_BLT             30              ; Bulk Data Transfer
        %define IPPROTO_NSP             31              ; Network Services
        %define IPPROTO_INP             32              ; Merit Internodal
        %define IPPROTO_SEP             33              ; Sequential Exchange
        %define IPPROTO_3PC             34              ; Third Party Connect
        %define IPPROTO_IDPR            35              ; InterDomain Policy Routing
        %define IPPROTO_XTP             36              ; XTP
        %define IPPROTO_DDP             37              ; Datagram Delivery
        %define IPPROTO_CMTP            38              ; Control Message Transport
        %define IPPROTO_TPXX            39              ; TP++ Transport
        %define IPPROTO_IL              40              ; IL transport protocol
        %define IPPROTO_IPV6            41              ; IP6 header
        %define IPPROTO_SDRP            42              ; Source Demand Routing
        %define IPPROTO_ROUTING         43              ; IP6 routing header
        %define IPPROTO_FRAGMENT        44              ; IP6 fragmentation header
        %define IPPROTO_IDRP            45              ; InterDomain Routing
        %define IPPROTO_RSVP            46              ; resource reservation
        %define IPPROTO_GRE             47              ; General Routing Encap.
        %define IPPROTO_MHRP            48              ; Mobile Host Routing
        %define IPPROTO_BHA             49              ; BHA
        %define IPPROTO_ESP             50              ; IP6 Encap Sec. Payload
        %define IPPROTO_AH              51              ; IP6 Auth Header
        %define IPPROTO_INLSP           52              ; Integ. Net Layer Security
        %define IPPROTO_SWIPE           53              ; IP with encryption
        %define IPPROTO_NHRP            54              ; Next Hop Resolution
        %define IPPROTO_MOBILE          55              ; IP Mobility
        %define IPPROTO_TLSP            56              ; Transport Layer Security
        %define IPPROTO_SKIP            57              ; SKIP
        %define IPPROTO_ICMPV6          58              ; ICMP6
        %define IPPROTO_NONE            59              ; IP6 no next header
        %define IPPROTO_DSTOPTS         60              ; IP6 destination option
        %define IPPROTO_AHIP            61              ; any host internal protocol
        %define IPPROTO_CFTP            62              ; CFTP
        %define IPPROTO_HELLO           63              ; "hello" routing protocol
        %define IPPROTO_SATEXPAK        64              ; SATNET/Backroom EXPAK
        %define IPPROTO_KRYPTOLAN       65              ; Kryptolan
        %define IPPROTO_RVD             66              ; Remote Virtual Disk
        %define IPPROTO_IPPC            67              ; Pluribus Packet Core
        %define IPPROTO_ADFS            68              ; Any distributed FS
        %define IPPROTO_SATMON          69              ; Satnet Monitoring
        %define IPPROTO_VISA            70              ; VISA Protocol
        %define IPPROTO_IPCV            71              ; Packet Core Utility
        %define IPPROTO_CPNX            72              ; Comp. Prot. Net. Executive
        %define IPPROTO_CPHB            73              ; Comp. Prot. HeartBeat
        %define IPPROTO_WSN             74              ; Wang Span Network
        %define IPPROTO_PVP             75              ; Packet Video Protocol
        %define IPPROTO_BRSATMON        76              ; BackRoom SATNET Monitoring
        %define IPPROTO_ND              77              ; Sun net disk proto (temp.)
        %define IPPROTO_WBMON           78              ; WIDEBAND Monitoring
        %define IPPROTO_WBEXPAK         79              ; WIDEBAND EXPAK
        %define IPPROTO_EON             80              ; ISO cnlp
        %define IPPROTO_VMTP            81              ; VMTP
        %define IPPROTO_SVMTP           82              ; Secure VMTP
        %define IPPROTO_VINES           83              ; Banyon VINES
        %define IPPROTO_TTP             84              ; TTP
        %define IPPROTO_IGP             85              ; NSFNET-IGP
        %define IPPROTO_DGP             86              ; dissimilar gateway prot.
        %define IPPROTO_TCF             87              ; TCF
        %define IPPROTO_IGRP            88              ; Cisco/GXS IGRP
        %define IPPROTO_OSPFIGP         89              ; OSPFIGP
        %define IPPROTO_SRPC            90              ; Strite RPC protocol
        %define IPPROTO_LARP            91              ; Locus Address Resoloution
        %define IPPROTO_MTP             92              ; Multicast Transport
        %define IPPROTO_AX25            93              ; AX.25 Frames
        %define IPPROTO_IPEIP           94              ; IP encapsulated in IP
        %define IPPROTO_MICP            95              ; Mobile Int.ing control
        %define IPPROTO_SCCSP           96              ; Semaphore Comm. security
        %define IPPROTO_ETHERIP         97              ; Ethernet IP encapsulation
        %define IPPROTO_ENCAP           98              ; encapsulation header
        %define IPPROTO_APES            99              ; any private encr. scheme
        %define IPPROTO_GMTP            100             ; GMTP
        %define IPPROTO_IPCOMP          108             ; payload compression (IPComp)
        %define IPPROTO_SCTP            132             ; SCTP
        %define IPPROTO_MH              135             ; IPv6 Mobility Header
        ; 101-254: Partly Unassigned
        %define IPPROTO_PIM             103             ; Protocol Independent Mcast
        %define IPPROTO_CARP            112             ; CARP
        %define IPPROTO_PGM             113             ; PGM
        %define IPPROTO_PFSYNC          240             ; PFSYNC
        ; 255: Reserved
        ; BSD Private, local use, namespace incursion, no longer used
        %define IPPROTO_OLD_DIVERT      254             ; OLD divert pseudo-proto
        %define IPPROTO_MAX             256
        ; last return value of *_input(), meaning "all job for this pkt is done".
        %define IPPROTO_DONE            257
        ; Only used internally, so can be outside the range of valid IP protocols.
        %define IPPROTO_DIVERT          258             ; divert pseudo-protocol
        %define IPPROTO_SEND            259             ; SeND pseudo-protocol
        %define IPPROTO_SPACER          32767           ; spacer for loadable protos
        %define IPPORT_RESERVED         1024
        %define IPPORT_EPHEMERALFIRST   10000
        %define IPPORT_EPHEMERALLAST    65535
        %define IPPORT_HIFIRSTAUTO      49152
        %define IPPORT_HILASTAUTO       65535
        %define IPPORT_RESERVEDSTART    600
        %define IPPORT_MAX              65535
        %define IN_CLASSA_NET           0xff000000
        %define IN_CLASSA_NSHIFT        24
        %define IN_CLASSA_HOST          0x00ffffff
        %define IN_CLASSA_MAX           128
        %define IN_CLASSB_NET           0xffff0000
        %define IN_CLASSB_NSHIFT        16
        %define IN_CLASSB_HOST          0x0000ffff
        %define IN_CLASSB_MAX           65536
        %define IN_CLASSC_NET           0xffffff00
        %define IN_CLASSC_NSHIFT        8
        %define IN_CLASSC_HOST          0x000000ff
        %define IN_CLASSD_NET           0xf0000000      ; These ones aren't really
        %define IN_CLASSD_NSHIFT        28              ; net and host fields, but
        %define IN_CLASSD_HOST          0x0fffffff      ; routing needn't know.
        %define INADDR_LOOPBACK         0x7f000001
        %define INADDR_NONE             0xffffffff              ; -1 return
        %define INADDR_UNSPEC_GROUP     0xe0000000   ; 224.0.0.0
        %define INADDR_ALLHOSTS_GROUP   0xe0000001   ; 224.0.0.1
        %define INADDR_ALLRTRS_GROUP    0xe0000002   ; 224.0.0.2
        %define INADDR_ALLRPTS_GROUP    0xe0000016   ; 224.0.0.22, IGMPv3
        %define INADDR_CARP_GROUP       0xe0000012   ; 224.0.0.18
        %define INADDR_PFSYNC_GROUP     0xe00000f0   ; 224.0.0.240
        %define INADDR_ALLMDNS_GROUP    0xe00000fb   ; 224.0.0.251
        %define INADDR_MAX_LOCAL_GROUP  0xe00000ff   ; 224.0.0.255
        %define IN_LOOPBACKNET          127                     ; official!
        %define IN_RFC3021_MASK         0xfffffffe
        %define IP_OPTIONS              1    ; buf/ip_opts; set/get IP options
        %define IP_HDRINCL              2    ; int; header is included with data
        %define IP_TOS                  3    ; int; IP type of service and preced.
        %define IP_TTL                  4    ; int; IP time to live
        %define IP_RECVOPTS             5    ; bool; receive all IP opts w/dgram
        %define IP_RECVRETOPTS          6    ; bool; receive IP opts for response
        %define IP_RECVDSTADDR          7    ; bool; receive IP dst addr w/dgram
        %define IP_SENDSRCADDR          IP_RECVDSTADDR ; cmsg_type to set src addr
        %define IP_RETOPTS              8    ; ip_opts; set/get IP options
        %define IP_MULTICAST_IF         9    ; struct in_addr *or* struct ip_mreqn; set/get IP multicast i/f
        %define IP_MULTICAST_TTL        10   ; u_char; set/get IP multicast ttl
        %define IP_MULTICAST_LOOP       11   ; u_char; set/get IP multicast loopback
        %define IP_ADD_MEMBERSHIP       12   ; ip_mreq; add an IP group membership
        %define IP_DROP_MEMBERSHIP      13   ; ip_mreq; drop an IP group membership
        %define IP_MULTICAST_VIF        14   ; set/get IP mcast virt. iface
        %define IP_RSVP_ON              15   ; enable RSVP in kernel
        %define IP_RSVP_OFF             16   ; disable RSVP in kernel
        %define IP_RSVP_VIF_ON          17   ; set RSVP per-vif socket
        %define IP_RSVP_VIF_OFF         18   ; unset RSVP per-vif socket
        %define IP_PORTRANGE            19   ; int; range to choose for unspec port
        %define IP_RECVIF               20   ; bool; receive reception if w/dgram
        ; for IPSEC
        %define IP_IPSEC_POLICY         21   ; int; set/get security policy
        %define IP_FAITH                22   ; bool; accept FAITH'ed connections
        %define IP_ONESBCAST            23   ; bool: send all-ones broadcast
        %define IP_BINDANY              24   ; bool: allow bind to any address
        %define IP_FW_TABLE_ADD         40   ; add entry
        %define IP_FW_TABLE_DEL         41   ; delete entry
        %define IP_FW_TABLE_FLUSH       42   ; flush table
        %define IP_FW_TABLE_GETSIZE     43   ; get table size
        %define IP_FW_TABLE_LIST        44   ; list table contents
        %define IP_FW3                  48   ; generic ipfw v.3 sockopts
        %define IP_DUMMYNET3            49   ; generic dummynet v.3 sockopts
        %define IP_FW_ADD               50   ; add a firewall rule to chain
        %define IP_FW_DEL               51   ; delete a firewall rule from chain
        %define IP_FW_FLUSH             52   ; flush firewall rule chain
        %define IP_FW_ZERO              53   ; clear single/all firewall counter(s)
        %define IP_FW_GET               54   ; get entire firewall rule chain
        %define IP_FW_RESETLOG          55   ; reset logging counters
        %define IP_FW_NAT_CFG           56   ; add/config a nat rule
        %define IP_FW_NAT_DEL           57   ; delete a nat rule
        %define IP_FW_NAT_GET_CONFIG    58   ; get configuration of a nat rule
        %define IP_FW_NAT_GET_LOG       59   ; get log of a nat rule
        %define IP_DUMMYNET_CONFIGURE   60   ; add/configure a dummynet pipe
        %define IP_DUMMYNET_DEL         61   ; delete a dummynet pipe from chain
        %define IP_DUMMYNET_FLUSH       62   ; flush dummynet
        %define IP_DUMMYNET_GET         64   ; get entire dummynet pipes
        %define IP_RECVTTL              65   ; bool; receive IP TTL w/dgram
        %define IP_MINTTL               66   ; minimum TTL for packet or drop
        %define IP_DONTFRAG             67   ; don't fragment packet
        ; IPv4 Source Filter Multicast API [RFC3678]
        %define IP_ADD_SOURCE_MEMBERSHIP        70   ; join a source-specific group
        %define IP_DROP_SOURCE_MEMBERSHIP       71   ; drop a single source
        %define IP_BLOCK_SOURCE                 72   ; block a source
        %define IP_UNBLOCK_SOURCE               73   ; unblock a source
        ; The following option is private; do not use it from user applications.
        %define IP_MSFILTER                     74   ; set/get filter list
        ; Protocol Independent Multicast API [RFC3678]
        %define MCAST_JOIN_GROUP                80   ; join an any-source group
        %define MCAST_LEAVE_GROUP               81   ; leave all sources for group
        %define MCAST_JOIN_SOURCE_GROUP         82   ; join a source-specific group
        %define MCAST_LEAVE_SOURCE_GROUP        83   ; leave a single source
        %define MCAST_BLOCK_SOURCE              84   ; block a source
        %define MCAST_UNBLOCK_SOURCE            85   ; unblock a source
        %define IP_DEFAULT_MULTICAST_TTL  1     ; normally limit m'casts to 1 hop
        %define IP_DEFAULT_MULTICAST_LOOP 1     ; normally hear sends if a member
        %define IP_MIN_MEMBERSHIPS      31
        %define IP_MAX_MEMBERSHIPS      4095
        %define IP_MAX_SOURCE_FILTER    1024    ; XXX to be unused
        %define IP_MAX_GROUP_SRC_FILTER         512     ; sources per group
        %define IP_MAX_SOCK_SRC_FILTER          128     ; sources per socket/group
        %define IP_MAX_SOCK_MUTE_FILTER         128     ; XXX no longer used
        %define MCAST_UNDEFINED 0       ; fmode: not yet defined
        %define MCAST_INCLUDE   1       ; fmode: include these source(s)
        %define MCAST_EXCLUDE   2       ; fmode: exclude these source(s)
        %define IP_PORTRANGE_DEFAULT    0       ; default range
        %define IP_PORTRANGE_HIGH       1       ; "high" - request firewall bypass
        %define IP_PORTRANGE_LOW        2       ; "low" - vouchsafe security
        %define IPPROTO_MAXID   (IPPROTO_AH + 1)        ; don't list to IPPROTO_MAX
        %define IPCTL_FORWARDING        1       ; act as router
        %define IPCTL_SENDREDIRECTS     2       ; may send redirects when forwarding
        %define IPCTL_DEFTTL            3       ; default TTL
        %define IPCTL_DEFMTU            4       ; default MTU
        %define IPCTL_RTEXPIRE          5       ; cloned route expiration time
        %define IPCTL_RTMINEXPIRE       6       ; min value for expiration time
        %define IPCTL_RTMAXCACHE        7       ; trigger level for dynamic expire
        %define IPCTL_SOURCEROUTE       8       ; may perform source routes
        %define IPCTL_DIRECTEDBROADCAST 9       ; may re-broadcast received packets
        %define IPCTL_INTRQMAXLEN       10      ; max length of netisr queue
        %define IPCTL_INTRQDROPS        11      ; number of netisr q drops
        %define IPCTL_STATS             12      ; ipstat structure
        %define IPCTL_ACCEPTSOURCEROUTE 13      ; may accept source routed packets
        %define IPCTL_FASTFORWARDING    14      ; use fast IP forwarding code
        %define IPCTL_KEEPFAITH         15      ; FAITH IPv4->IPv6 translater ctl
        %define IPCTL_GIF_TTL           16      ; default TTL for gif encap packet
        %define IPCTL_MAXID             17
