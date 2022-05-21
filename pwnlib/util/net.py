from __future__ import absolute_import
from __future__ import division

import ctypes
import ctypes.util
import socket

from pwnlib.util.packing import p16
from pwnlib.util.packing import p32
from pwnlib.util.packing import pack

__all__ = ['getifaddrs', 'interfaces', 'interfaces4', 'interfaces6', 'sockaddr']

# /usr/src/linux-headers-3.12-1-common/include/uapi/linux/socket.h
sa_family_t = ctypes.c_ushort

# /usr/src/linux-headers-3.12-1-common/include/linux/socket.h
class struct_sockaddr(ctypes.Structure):
    _fields_ = [
        ('sa_family', sa_family_t)       ,
        ('sa_data'  , ctypes.c_char * 14),
        ]

# /usr/src/linux-headers-3.12-1-common/include/uapi/linux/in.h
struct_in_addr = ctypes.c_uint8 * 4
class struct_sockaddr_in(ctypes.Structure):
    _fields_ = [
        ('sin_family', sa_family_t)    ,
        ('sin_port'  , ctypes.c_uint16),
        ('sin_addr'  , struct_in_addr) ,
        ]

# /usr/src/linux-headers-3.12-1-common/include/uapi/linux/in6.h
struct_in6_addr = ctypes.c_uint8 * 16
class struct_sockaddr_in6(ctypes.Structure):
    _fields_ = [
        ('sin6_family'  , ctypes.c_ushort),
        ('sin6_port'    , ctypes.c_uint16),
        ('sin6_flowinfo', ctypes.c_uint32),
        ('sin6_addr'    , struct_in6_addr),
        ('sin6_scope_id', ctypes.c_uint32),
        ]

# /usr/include/ifaddrs.h
class union_ifa_ifu(ctypes.Union):
    _fields_ = [
        ('ifu_broadaddr', ctypes.POINTER(struct_sockaddr)),
        ('ifu_dstaddr'  , ctypes.POINTER(struct_sockaddr)),
        ]
class struct_ifaddrs(ctypes.Structure):
    pass # recursively defined
struct_ifaddrs._fields_ = [
    ('ifa_next'   , ctypes.POINTER(struct_ifaddrs)) ,
    ('ifa_name'   , ctypes.c_char_p)                ,
    ('ifa_flags'  , ctypes.c_uint)                  ,
    ('ifa_addr'   , ctypes.POINTER(struct_sockaddr)),
    ('ifa_netmask', ctypes.POINTER(struct_sockaddr)),
    ('ifa_ifu'    , union_ifa_ifu)                  ,
    ('ifa_data'   , ctypes.c_void_p)                ,
    ]

AddressFamily = getattr(socket, 'AddressFamily', int)

def sockaddr_fixup(saptr):
    family = AddressFamily(saptr.contents.sa_family)
    addr = {}
    if   family == socket.AF_INET:
        sa = ctypes.cast(saptr, ctypes.POINTER(struct_sockaddr_in)).contents
        addr['port'] = socket.ntohs(sa.sin_port)
        addr['addr'] = socket.inet_ntop(family, sa.sin_addr)
    elif family == socket.AF_INET6:
        sa = ctypes.cast(saptr, ctypes.POINTER(struct_sockaddr_in6)).contents
        addr['port'] = socket.ntohs(sa.sin6_port)
        addr['flowinfo'] = socket.ntohl(sa.sin6_flowinfo)
        addr['addr'] = socket.inet_ntop(family, sa.sin6_addr)
        addr['scope_id'] = sa.sin6_scope_id
    return family, addr

def getifaddrs():
    """getifaddrs() -> dict list

    A wrapper for libc's ``getifaddrs``.

    Arguments:
      None

    Returns:
      list of dictionaries each representing a `struct ifaddrs`. The
      dictionaries have the fields `name`, `flags`, `family`, `addr` and
      `netmask`.  Refer to `getifaddrs(3)` for details.  The fields `addr` and
      `netmask` are themselves dictionaries.  Their structure depend on
      `family`.  If `family` is not :const:`socket.AF_INET` or
      :const:`socket.AF_INET6` they will be empty.
    """
    libc = ctypes.CDLL(ctypes.util.find_library('c'))
    getifaddrs = libc.getifaddrs
    getifaddrs.restype = ctypes.c_int
    getifaddrs.argtpes = [ctypes.POINTER(ctypes.POINTER(struct_ifaddrs))]
    freeifaddrs = libc.freeifaddrs
    freeifaddrs.restype = None
    freeifaddrs.argtypes = [ctypes.POINTER(struct_ifaddrs)]
    ifaptr = ctypes.POINTER(struct_ifaddrs)()
    result = getifaddrs(ctypes.pointer(ifaptr))
    if result == -1:
        raise OSError(ctypes.get_errno())
    del result
    try:
        ifas = []
        while ifaptr:
            ifac = ifaptr.contents
            ifa = {'name' : ifac.ifa_name,
                   'flags': ifac.ifa_flags,
                   }
            if ifac.ifa_addr:
                ifa['family'], ifa['addr'] = sockaddr_fixup(ifac.ifa_addr)
            else:
                ifa['family'], ifa['addr'] = None, None
            if ifac.ifa_netmask:
                _, ifa['netmask'] = sockaddr_fixup(ifac.ifa_netmask)
            else:
                ifa['network'] = None
            ifas.append(ifa)
            ifaptr = ifac.ifa_next
        return ifas
    finally:
        freeifaddrs(ifaptr)

def interfaces(all = False):
    """interfaces(all = False) -> dict

    Arguments:
      all (bool): Whether to include interfaces with not associated address.
      Default: :const:`False`.

    Returns:
      A dictionary mapping each of the hosts interfaces to a list of it's
      addresses.  Each entry in the list is a tuple ``(family, addr)``, and
      `family` is either :const:`socket.AF_INET` or :const:`socket.AF_INET6`.
    """
    out = {}
    for ifa in getifaddrs():
        name = ifa['name']
        if name not in out:
            out[name] = []
        if not ifa['addr']:
            continue
        family = ifa['family']
        addr = ifa['addr']['addr']
        out[name].append((family, addr))
    if not all:
        out = {k: v for k, v in out.items() if v}
    return out

def interfaces4(all = False):
    """interfaces4(all = False) -> dict

    As :func:`interfaces` but only includes IPv4 addresses and the lists in the
    dictionary only contains the addresses not the family.

    Arguments:
      all (bool): Whether to include interfaces with not associated address.
      Default: :const:`False`.

    Returns:
      A dictionary mapping each of the hosts interfaces to a list of it's
      IPv4 addresses.

    Examples:
        >>> interfaces4(all=True) # doctest: +ELLIPSIS
        {...'127.0.0.1'...}
    """
    out = {}
    for name, addrs in interfaces(all = all).items():
        addrs = [addr for fam, addr in addrs if fam == socket.AF_INET]
        if addrs or all:
            out[name] = addrs
    return out

def interfaces6(all = False):
    """interfaces6(all = False) -> dict

    As :func:`interfaces` but only includes IPv6 addresses and the lists in the
    dictionary only contains the addresses not the family.

    Arguments:
      all (bool): Whether to include interfaces with not associated address.
      Default: :const:`False`.

    Returns:
      A dictionary mapping each of the hosts interfaces to a list of it's
      IPv6 addresses.

    Examples:
        >>> interfaces6() # doctest: +ELLIPSIS
        {...'::1'...}
    """
    out = {}
    for name, addrs in interfaces(all = all).items():
        addrs = [addr for fam, addr in addrs if fam == socket.AF_INET6]
        if addrs or all:
            out[name] = addrs
    return out

def sockaddr(host, port, network = 'ipv4'):
    """sockaddr(host, port, network = 'ipv4') -> (data, length, family)

    Creates a sockaddr_in or sockaddr_in6 memory buffer for use in shellcode.

    Arguments:
      host (str): Either an IP address or a hostname to be looked up.
      port (int): TCP/UDP port.
      network (str): Either 'ipv4' or 'ipv6'.

    Returns:
      A tuple containing the sockaddr buffer, length, and the address family.
    """
    address_family = {'ipv4':socket.AF_INET,'ipv6':socket.AF_INET6}[network]

    for family, _, _, _, ip in socket.getaddrinfo(host, None, address_family):
        ip = ip[0]
        if family == address_family:
            break
    else:
        log.error("Could not find %s address for %r" % (network, host))

    info = socket.getaddrinfo(host, None, address_family)
    host = socket.inet_pton(address_family, ip)
    sockaddr  = p16(address_family)
    sockaddr += pack(port, word_size = 16, endianness = 'big') #Port should be big endian = network byte order
    length    = 0

    if network == 'ipv4':
        sockaddr += host
        length    = 16 # Save ten bytes by skipping two 'push 0'
    else:
        sockaddr += p32(0xffffffff) # Save three bytes 'push -1' vs 'push 0'
        sockaddr += host
        length    = len(sockaddr) + 4 # Save five bytes 'push 0'
    return (sockaddr, length, getattr(address_family, "name", address_family))

def sock_match(local, remote, fam=socket.AF_UNSPEC, typ=0):
    """
    Given two addresses, returns a function comparing address pairs from
    psutil library against these two.  Useful for filtering done in
    :func:`pwnlib.util.proc.pidof`.
    """
    def sockinfos(addr, f, t):
        if not addr:
            return set()
        if f not in (socket.AF_UNSPEC, socket.AF_INET, socket.AF_INET6):
            return {addr}
        infos = set(socket.getaddrinfo(addr[0], addr[1], f, t))

        # handle mixed IPv4-to-IPv6 and the other way round connections
        for f, t, proto, _canonname, sockaddr in tuple(infos):
            if f == socket.AF_INET and t != socket.SOCK_RAW:
                infos |= set(socket.getaddrinfo(sockaddr[0], sockaddr[1], socket.AF_INET6, t, proto, socket.AI_V4MAPPED))
        return infos

    if local is not None:
        local = sockinfos(local, fam, typ)
    remote = sockinfos(remote, fam, typ)

    def match(c):
        laddrs = sockinfos(c.laddr, c.family, c.type)
        raddrs = sockinfos(c.raddr, c.family, c.type)
        if not (raddrs & remote):
            return False
        if local is None:
            return True
        return bool(laddrs & local)

    return match
