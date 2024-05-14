# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division

import random
import re

from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.encoders.encoder_class import Encoder
from pwnlib.log import getLogger
from pwnlib.util.fiddling import hexdump
from pwnlib.util.misc import byteset

log = getLogger(__name__)

@LocalContext
def encode(raw_bytes, avoid=None, expr=None, force=0, pcreg=''):
    """encode(raw_bytes, avoid, expr, force) -> str

    Encode shellcode ``raw_bytes`` such that it does not contain
    any bytes in ``avoid`` or ``expr``.

    Arguments:

        raw_bytes(bytes): Sequence of shellcode bytes to encode.
        avoid(bytes):     Bytes to avoid
        expr(bytes):      Regular expression which matches bad characters.
        force(bool):      Force re-encoding of the shellcode, even if it
                          doesn't contain any bytes in ``avoid``.
    """
    orig_avoid = avoid

    avoid = byteset(avoid or b'')

    if expr:
        for char in all_chars:
            if re.search(expr, char):
                avoid.add(char)

    if not (force or avoid & byteset(raw_bytes)):
        return raw_bytes

    encoders = Encoder._encoders[context.arch]

    if context.randomize:
        random.shuffle(encoders)

    for encoder in encoders:
        if encoder.blacklist & avoid:
            continue

        log.debug('Selected encoder %r', encoder)

        bytes_avoid = b''.join(avoid)

        try:
            v = encoder(raw_bytes, bytes_avoid, pcreg)
        except NotImplementedError:
            continue

        if avoid & byteset(v):
            log.warning_once("Encoder %s did not succeed" % encoder)
            continue

        return v


    avoid_errmsg = ''
    if orig_avoid and expr:
        avoid_errmsg = '%r and %r' % (orig_avoid, expr)
    elif expr:
        avoid_errmsg = repr(expr)
    else:
        avoid_errmsg = repr(b''.join(avoid))

    args = (context.arch, avoid_errmsg, hexdump(raw_bytes))
    msg = "No encoders for %s which can avoid %s for\n%s" % args
    msg = msg.replace('%', '%%')
    log.error(msg)

all_chars        = list(bytes([i]) for i in range(256))
re_alphanumeric  = br'[^A-Za-z0-9]'
re_printable     = br'[^\x21-\x7e]'
re_whitespace    = br'\s'
re_null          = br'\x00'
re_line          = br'[\s\x00]'

@LocalContext
def null(raw_bytes, *a, **kw):
    """null(raw_bytes) -> bytes

    Encode the shellcode ``raw_bytes`` such that it does not
    contain any NULL bytes.

    Accepts the same arguments as :func:`encode`.
    """
    return encode(raw_bytes, expr=re_null, *a, **kw)

@LocalContext
def line(raw_bytes, *a, **kw):
    """line(raw_bytes) -> bytes

    Encode the shellcode ``raw_bytes`` such that it does not
    contain any NULL bytes or whitespace.

    Accepts the same arguments as :func:`encode`.
    """
    return encode(raw_bytes, expr=re_whitespace, *a, **kw)

@LocalContext
def alphanumeric(raw_bytes, *a, **kw):
    """alphanumeric(raw_bytes) -> bytes

    Encode the shellcode ``raw_bytes`` such that it does not
    contain any bytes except for [A-Za-z0-9].

    Accepts the same arguments as :func:`encode`.
    """
    return encode(raw_bytes, expr=re_alphanumeric, *a, **kw)

@LocalContext
def printable(raw_bytes, *a, **kw):
    """printable(raw_bytes) -> bytes

    Encode the shellcode ``raw_bytes`` such that it only contains
    non-space printable bytes.

    Accepts the same arguments as :func:`encode`.
    """
    return encode(raw_bytes, expr=re_printable, *a, **kw)

@LocalContext
def scramble(raw_bytes, *a, **kw):
    """scramble(raw_bytes) -> bytes

    Encodes the input data with a random encoder.

    Accepts the same arguments as :func:`encode`.
    """
    return encode(raw_bytes, force=1, *a, **kw)
