from __future__ import annotations

import random
import re
import string
from collections import defaultdict
from enum import Enum

from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.exception import PwnlibException
from pwnlib.log import getLogger
from pwnlib.util.fiddling import hexdump

log = getLogger(__name__)


class EncoderConstraint(str, Enum):
    """Output constraints understood by :func:`encode`."""

    ALPHABETIC = 'alphabetic'
    ALPHANUMERIC = 'alphanumeric'
    ASCII = 'ascii'
    UTF8MB3 = 'utf8mb3'
    UTF8 = 'utf8'


class EncoderError(PwnlibException):
    """An expected rejection from a shellcode encoder."""


_constraint_rank = {
    EncoderConstraint.ALPHABETIC: 0,
    EncoderConstraint.ALPHANUMERIC: 1,
    EncoderConstraint.ASCII: 2,
    EncoderConstraint.UTF8MB3: 3,
    EncoderConstraint.UTF8: 4,
}

_constraint_alphabet = {
    EncoderConstraint.ALPHABETIC: frozenset(map(ord, string.ascii_letters)),
    EncoderConstraint.ALPHANUMERIC: frozenset(map(ord, string.ascii_letters + string.digits)),
    EncoderConstraint.ASCII: frozenset(range(0x21, 0x7f)),
}


def _byte_values(value, name):
    if value is None:
        return frozenset()
    if isinstance(value, str):
        try:
            value = value.encode('latin-1')
        except UnicodeEncodeError as error:
            raise ValueError('%s must only contain byte-valued characters' % name) from error
        return frozenset(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return frozenset(bytes(value))
    if isinstance(value, int):
        raise TypeError('%s must be an iterable of byte values, not an integer' % name)

    result = set()
    try:
        values = iter(value)
    except TypeError as error:
        raise TypeError('%s must be bytes-like or an iterable of byte values' % name) from error
    for item in values:
        if isinstance(item, str):
            if len(item) != 1 or ord(item) > 0xff:
                raise ValueError('%s must only contain byte-valued characters' % name)
            item = ord(item)
        elif isinstance(item, (bytes, bytearray, memoryview)):
            item = bytes(item)
            if len(item) != 1:
                raise ValueError('%s byte strings must have length one' % name)
            item = item[0]
        if not isinstance(item, int):
            raise TypeError('%s must contain integers or byte-valued characters' % name)
        if not 0 <= item <= 0xff:
            raise ValueError('%s byte values must be in range(256)' % name)
        result.add(item)
    return frozenset(result)


def _normalize_constraint(constraint):
    if constraint is None or isinstance(constraint, EncoderConstraint):
        return constraint
    try:
        return EncoderConstraint(constraint)
    except (TypeError, ValueError) as error:
        values = ', '.join(item.value for item in EncoderConstraint)
        raise ValueError('constraint must be one of: %s' % values) from error


def _constraint_avoid(constraint):
    alphabet = _constraint_alphabet.get(constraint)
    if alphabet is None:
        return frozenset()
    return frozenset(range(256)) - alphabet


def _satisfies_constraint(value, constraint):
    if constraint is None:
        return True
    if constraint in _constraint_alphabet:
        return set(value) <= _constraint_alphabet[constraint]
    try:
        value.decode('utf-8')
    except UnicodeDecodeError:
        return False
    if constraint == EncoderConstraint.UTF8MB3:
        return not any(byte >= 0xf0 for byte in value)
    return True


class Encoder:
    _encoders: defaultdict[str, list[Encoder]] = defaultdict(lambda: [])

    #: Architecture retained for compatibility with third-party encoders.
    arch: str | None = None

    #: Architectures supported by this encoder.
    architectures: frozenset[str] = frozenset()

    #: Lower values are attempted first.
    priority = 100

    #: Bytes which are necessarily present in the decoder stub.
    unavoidable_bytes: frozenset[int] = frozenset()

    #: Higher-order output constraints this encoder is designed to satisfy.
    supported_constraints: frozenset[EncoderConstraint] = frozenset()

    #: Whether identical inputs produce identical output under the default context.
    is_deterministic = False

    #: Opt-in encoders are considered only when a constraint requests them.
    enabled_by_default = True

    #: Deprecated compatibility alias for ``unavoidable_bytes``.
    blacklist: set[str] = set()

    def __init__(self):
        """Shellcode encoder class."""
        architectures = self.architectures
        if not architectures and self.arch is not None:
            architectures = frozenset((self.arch,))
        self.architectures = architectures
        for architecture in architectures:
            Encoder._encoders[architecture].append(self)

    def __call__(self, raw_bytes, avoid, pcreg):
        """Encode ``raw_bytes`` while avoiding the requested bytes."""
        raise NotImplementedError()

    def required_bytes(self):
        """Return byte values that make this encoder incompatible with ``avoid``."""
        if self.unavoidable_bytes:
            return self.unavoidable_bytes
        return _byte_values(self.blacklist, 'blacklist')

    def selection_rank(self):
        """Return a stable best-to-worst candidate rank."""
        quality = min(
            (_constraint_rank[item] for item in self.supported_constraints),
            default=len(_constraint_rank),
        )
        return quality, self.priority, self.__class__.__module__, self.__class__.__name__


def _encode(raw_bytes, avoid=None, expr=None, force=False, pcreg='', constraint=None, shuffle=False):
    raw_bytes = bytes(raw_bytes)
    orig_avoid = avoid
    constraint = _normalize_constraint(constraint)
    avoid = set(_byte_values(avoid, 'avoid'))

    if expr:
        for char in all_chars:
            if re.search(expr, char):
                avoid.add(ord(char))

    avoid.update(_constraint_avoid(constraint))

    if not (force or avoid & set(raw_bytes) or not _satisfies_constraint(raw_bytes, constraint)):
        return raw_bytes

    candidates = []
    for encoder in Encoder._encoders[context.arch]:
        if constraint is None:
            if not encoder.enabled_by_default:
                continue
        elif constraint not in encoder.supported_constraints:
            continue
        if encoder.required_bytes() & avoid:
            continue
        candidates.append(encoder)

    if shuffle:
        random.shuffle(candidates)
    else:
        candidates.sort(key=lambda candidate: candidate.selection_rank())

    for encoder in candidates:
        try:
            encoded = encoder(raw_bytes, bytes(sorted(avoid)), pcreg)
        except (EncoderError, NotImplementedError):
            continue

        if encoded is None:
            log.warning_once('Encoder %s returned no result' % encoder)
            continue

        encoded = bytes(encoded)
        if avoid & set(encoded) or not _satisfies_constraint(encoded, constraint):
            log.warning_once('Encoder %s did not succeed' % encoder)
            continue
        return encoded

    if orig_avoid and expr:
        avoid_errmsg = '%r and %r' % (orig_avoid, expr)
    elif expr:
        avoid_errmsg = repr(expr)
    else:
        avoid_errmsg = repr(bytes(sorted(avoid)))

    if constraint is not None:
        avoid_errmsg += ' with %s output' % constraint.value
    args = (context.arch, avoid_errmsg, hexdump(raw_bytes))
    msg = 'No encoders for %s which can avoid %s for\n%s' % args
    log.error(msg.replace('%', '%%'))


@LocalContext
def encode(raw_bytes, avoid=None, expr=None, force=False, pcreg='', constraint=None):
    """encode(raw_bytes, avoid, expr, force, pcreg, constraint) -> bytes

    Encode shellcode ``raw_bytes`` such that it does not contain any bytes in
    ``avoid`` or ``expr``. ``constraint`` can request ``alphabetic``,
    ``alphanumeric``, printable ``ascii``, ``utf8mb3``, or ``utf8`` output.
    Candidates are tried in a stable best-to-worst order. Only expected
    :class:`EncoderError` rejections trigger fallback.

    ``avoid`` accepts bytes-like values and byte-valued strings.

        >>> pwnlib.encoders.encoder._byte_values('A\xff', 'avoid') == frozenset((0x41, 0xff))
        True
        >>> pwnlib.encoders.encoder._byte_values({'A', b'B', 0x43}, 'avoid') == frozenset(b'ABC')
        True
        >>> pwnlib.encoders.encoder._normalize_constraint('ascii') is EncoderConstraint.ASCII
        True
        >>> pwnlib.encoders.encoder._satisfies_constraint(b'Az09', EncoderConstraint.ALPHANUMERIC)
        True
        >>> pwnlib.encoders.encoder._satisfies_constraint(b'A_', EncoderConstraint.ALPHANUMERIC)
        False
        >>> pwnlib.encoders.encoder._satisfies_constraint(b'Az', EncoderConstraint.ALPHABETIC)
        True
        >>> pwnlib.encoders.encoder._satisfies_constraint(b'A9', EncoderConstraint.ALPHABETIC)
        False
        >>> pwnlib.encoders.encoder._satisfies_constraint('snowman: \N{SNOWMAN}'.encode(), EncoderConstraint.UTF8MB3)
        True
        >>> pwnlib.encoders.encoder._satisfies_constraint('\N{GRINNING FACE}'.encode(), EncoderConstraint.UTF8MB3)
        False
        >>> pwnlib.encoders.encoder._satisfies_constraint('\N{GRINNING FACE}'.encode(), EncoderConstraint.UTF8)
        True
        >>> encode(b'', constraint='ascii')
        b''
        >>> from unittest import mock
        >>> attempts = []
        >>> class RejectingEncoder(Encoder):
        ...     priority = 10
        ...     def __call__(self, raw_bytes, avoid, pcreg):
        ...         attempts.append('reject')
        ...         raise EncoderError('not representable')
        >>> class FallbackEncoder(Encoder):
        ...     priority = 20
        ...     def __call__(self, raw_bytes, avoid, pcreg):
        ...         attempts.append('fallback')
        ...         return b'A'
        >>> candidates = [FallbackEncoder(), RejectingEncoder()]
        >>> with context.local(arch='i386'), mock.patch.dict(Encoder._encoders, {'i386': candidates}):
        ...     encode(b'\\x00', avoid=b'\\x00')
        b'A'
        >>> attempts
        ['reject', 'fallback']
        >>> class BrokenEncoder(Encoder):
        ...     def __call__(self, raw_bytes, avoid, pcreg):
        ...         raise ValueError('internal bug')
        >>> with context.local(arch='i386'), mock.patch.dict(Encoder._encoders, {'i386': [BrokenEncoder()]}):
        ...     encode(b'\\x00', avoid=b'\\x00')
        Traceback (most recent call last):
          ...
        ValueError: internal bug
    """
    return _encode(raw_bytes, avoid, expr, force, pcreg, constraint)


all_chars = list(chr(i) for i in range(256))
re_alphanumeric = r'[^A-Za-z0-9]'
re_printable = r'[^\x21-\x7e]'
re_whitespace = r'\s'
re_null = r'\x00'
re_line = r'[\s\x00]'


@LocalContext
def null(raw_bytes, *a, **kw):
    """Encode ``raw_bytes`` without NULL bytes."""
    return encode(raw_bytes, expr=re_null, *a, **kw)


@LocalContext
def line(raw_bytes, *a, **kw):
    """Encode ``raw_bytes`` without NULL bytes or whitespace."""
    return encode(raw_bytes, expr=re_whitespace, *a, **kw)


@LocalContext
def alphanumeric(raw_bytes, *a, **kw):
    """Encode ``raw_bytes`` using only ASCII letters and digits."""
    return encode(raw_bytes, constraint=EncoderConstraint.ALPHANUMERIC, *a, **kw)


@LocalContext
def printable(raw_bytes, *a, **kw):
    """Encode ``raw_bytes`` using only non-space printable ASCII bytes."""
    return encode(raw_bytes, constraint=EncoderConstraint.ASCII, *a, **kw)


@LocalContext
def scramble(raw_bytes, *a, **kw):
    """Encode ``raw_bytes`` with a randomly selected compatible encoder."""
    return _encode(raw_bytes, force=True, shuffle=True, *a, **kw)
