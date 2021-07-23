# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division

import collections
import random
import re
import string

from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util.fiddling import hexdump

log = getLogger(__name__)

class Encoder(object):
    _encoders = collections.defaultdict(lambda: [])

    #: Architecture which this encoder works on
    arch = None

    #: Blacklist of bytes which are known not to be supported
    blacklist = set()

    def __init__(self):
        """Shellcode encoder class

        Implements an architecture-specific shellcode encoder
        """
        Encoder._encoders[self.arch].append(self)

    def __call__(self, raw_bytes, avoid, pcreg):
        """avoid(raw_bytes, avoid)

        Arguments:
            raw_bytes(str):
                String of bytes to encode
            avoid(set):
                Set of bytes to avoid
            pcreg(str):
                Register which contains the address of the shellcode.
                May be necessary for some shellcode.
        """
        raise NotImplementedError()


@LocalContext
def encode(raw_bytes, avoid=None, expr=None, force=0, pcreg=''):
    """encode(raw_bytes, avoid, expr, force) -> str

    Encode shellcode ``raw_bytes`` such that it does not contain
    any bytes in ``avoid`` or ``expr``.

    Arguments:

        raw_bytes(str): Sequence of shellcode bytes to encode.
        avoid(str):     Bytes to avoid
        expr(str):      Regular expression which matches bad characters.
        force(bool):    Force re-encoding of the shellcode, even if it
                        doesn't contain any bytes in ``avoid``.
    """
    orig_avoid = avoid

    avoid = set(avoid or '')

    if expr:
        for char in all_chars:
            if re.search(expr, char):
                avoid.add(char)

    if not (force or avoid & set(raw_bytes)):
        return raw_bytes

    encoders = Encoder._encoders[context.arch]
    random.shuffle(encoders)

    for encoder in encoders:
        if encoder.blacklist & avoid:
            continue

        try:
            v = encoder(raw_bytes, bytes(avoid), pcreg)
        except NotImplementedError:
            continue

        if avoid & set(v):
            log.warning_once("Encoder %s did not succeed" % encoder)
            continue

        return v


    avoid_errmsg = ''
    if orig_avoid and expr:
        avoid_errmsg = '%r and %r' % (orig_avoid, expr)
    elif expr:
        avoid_errmsg = repr(expr)
    else:
        avoid_errmsg = repr(bytes(avoid))

    args = (context.arch, avoid_errmsg, hexdump(raw_bytes))
    msg = "No encoders for %s which can avoid %s for\n%s" % args
    msg = msg.replace('%', '%%')
    log.error(msg)

all_chars        = list(chr(i) for i in range(256))
re_alphanumeric  = r'[^A-Za-z0-9]'
re_printable     = r'[^\x21-\x7e]'
re_whitespace    = r'\s'
re_null          = r'\x00'
re_line          = r'[\s\x00]'

@LocalContext
def null(raw_bytes, *a, **kw):
    """null(raw_bytes) -> str

    Encode the shellcode ``raw_bytes`` such that it does not
    contain any NULL bytes.

    Accepts the same arguments as :func:`encode`.
    """
    return encode(raw_bytes, expr=re_null, *a, **kw)

@LocalContext
def line(raw_bytes, *a, **kw):
    """line(raw_bytes) -> str

    Encode the shellcode ``raw_bytes`` such that it does not
    contain any NULL bytes or whitespace.

    Accepts the same arguments as :func:`encode`.
    """
    return encode(raw_bytes, expr=re_whitespace, *a, **kw)

@LocalContext
def alphanumeric(raw_bytes, *a, **kw):
    """alphanumeric(raw_bytes) -> str

    Encode the shellcode ``raw_bytes`` such that it does not
    contain any bytes except for [A-Za-z0-9].

    Accepts the same arguments as :func:`encode`.
    """
    return encode(raw_bytes, expr=re_alphanumeric, *a, **kw)

@LocalContext
def printable(raw_bytes, *a, **kw):
    """printable(raw_bytes) -> str

    Encode the shellcode ``raw_bytes`` such that it only contains
    non-space printable bytes.

    Accepts the same arguments as :func:`encode`.
    """
    return encode(raw_bytes, expr=re_printable, *a, **kw)

@LocalContext
def scramble(raw_bytes, *a, **kw):
    """scramble(raw_bytes) -> str

    Encodes the input data with a random encoder.

    Accepts the same arguments as :func:`encode`.
    """
    return encode(raw_bytes, force=1, *a, **kw)
