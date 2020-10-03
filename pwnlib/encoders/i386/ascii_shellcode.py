""" Encoder to convert shellcode to shellcode that contains only ascii
characters """
# https://github.com/Gallopsled/pwntools/pull/1667

from __future__ import absolute_import

from itertools import product

import six

from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.encoders.encoder import Encoder
from pwnlib.encoders.encoder import all_chars
from pwnlib.util.iters import group
from pwnlib.util.packing import *


class AsciiShellcodeEncoder(Encoder):
    """ Pack shellcode into only ascii characters that unpacks itself and
    executes (on the stack)

    The original paper this encoder is based on:
    http://julianor.tripod.com/bc/bypass-msb.txt

    A more visual explanation as well as an implementation in C:
    https://github.com/VincentDary/PolyAsciiShellGen/blob/master/README.md#mechanism
    """

    def __init__(self, slop=20, max_subs=4):
        """ Init

        Args:
            slop (int, optional): The amount esp will be increased by in the
                allocation phase (In addition to the length of the packed
                shellcode) as well as defines the size of the NOP sled (you can
                increase/ decrease the size of the NOP sled by adding/removing
                b'P'-s to/ from the end of the packed shellcode).
                Defaults to 20.
            max_subs (int, optional): The maximum amount of subtractions
                allowed to be taken. This may be increased if you have a
                relatively  restrictive ``avoid`` set. The more subtractions
                there are, the bigger the packed shellcode will be.
                Defaults to 4.
        """
        if six.PY2:
            super(AsciiShellcodeEncoder, self).__init__()
        elif six.PY3:
            super().__init__()
        self.slop = slop
        self.max_subs = max_subs

    @LocalContext
    def __call__(self, raw_bytes, avoid=None, pcreg=None):
        r""" Pack shellcode into only ascii characters that unpacks itself and
        executes (on the stack)

        Args:
            raw_bytes (bytes): The shellcode to be packed
            avoid (set, optional): Characters to avoid. Defaults to allow
                printable ascii (0x21-0x7e).
            pcreg (NoneType, optional): Ignored

        Raises:
            RuntimeError: A required character is in ``avoid`` (required
                characters are characters which assemble into assembly
                instructions and are used to unpack the shellcode onto the
                stack, more details in the paper linked above ``\ - % T X P``).
            RuntimeError: Not supported architecture
            ArithmeticError: The allowed character set does not contain
                two characters that when they are bitwise-anded with eachother
                their result is 0
            ArithmeticError: Could not find a correct subtraction sequence
                to get to the the desired target value with the given ``avoid``
                parameter

        Returns:
            bytes: The packed shellcode

        Examples:

            >>> context.update(arch='i386', os='linux')
            >>> sc = b"\x83\xc4\x181\xc01\xdb\xb0\x06\xcd\x80Sh/ttyh/dev\x89\xe31\xc9f\xb9\x12'\xb0\x05\xcd\x80j\x17X1\xdb\xcd\x80j.XS\xcd\x801\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\x99\xb0\x0b\xcd\x80"
            >>> encoders.i386.ascii_shellcode.encode(sc)
            b'TX-!!!!-"_``-~~~~P\\%!!!!%@@@@-!6!!-V~!!-~~<-P-!mha-a~~~P-!!L`-a^~~-~~~~P-!!if-9`~~P-!!!!-aOaf-~~~~P-!&!<-!~`~--~~~P-!!!!-!!H^-+A~~P-U!![-~A1~P-,<V!-~~~!-~~~GP-!2!8-j~O~P-!]!!-!~!r-y~w~P-c!!!-~<(+P-N!_W-~1~~P-!!]!-Mn~!-~~~<P-!<!!-r~!P-~~x~P-fe!$-~~S~-~~~~P-!!\'$-%z~~P-A!!!-~!#!-~*~=P-!7!!-T~!!-~~E^PPPPPPPPPPPPPPPPPPPPP'
            >>> avoid = {'\x00', '\x83', '\x04', '\x87', '\x08', '\x8b', '\x0c', '\x8f', '\x10', '\x93', '\x14', '\x97', '\x18', '\x9b', '\x1c', '\x9f', ' ', '\xa3', '\xa7', '\xab', '\xaf', '\xb3', '\xb7', '\xbb', '\xbf', '\xc3', '\xc7', '\xcb', '\xcf', '\xd3', '\xd7', '\xdb', '\xdf', '\xe3', '\xe7', '\xeb', '\xef', '\xf3', '\xf7', '\xfb', '\xff', '\x80', '\x03', '\x84', '\x07', '\x88', '\x0b', '\x8c', '\x0f', '\x90', '\x13', '\x94', '\x17', '\x98', '\x1b', '\x9c', '\x1f', '\xa0', '\xa4', '\xa8', '\xac', '\xb0', '\xb4', '\xb8', '\xbc', '\xc0', '\xc4', '\xc8', '\xcc', '\xd0', '\xd4', '\xd8', '\xdc', '\xe0', '\xe4', '\xe8', '\xec', '\xf0', '\xf4', '\xf8', '\xfc', '\x7f', '\x81', '\x02', '\x85', '\x06', '\x89', '\n', '\x8d', '\x0e', '\x91', '\x12', '\x95', '\x16', '\x99', '\x1a', '\x9d', '\x1e', '\xa1', '\xa5', '\xa9', '\xad', '\xb1', '\xb5', '\xb9', '\xbd', '\xc1', '\xc5', '\xc9', '\xcd', '\xd1', '\xd5', '\xd9', '\xdd', '\xe1', '\xe5', '\xe9', '\xed', '\xf1', '\xf5', '\xf9', '\xfd', '\x01', '\x82', '\x05', '\x86', '\t', '\x8a', '\r', '\x8e', '\x11', '\x92', '\x15', '\x96', '\x19', '\x9a', '\x1d', '\x9e', '\xa2', '\xa6', '\xaa', '\xae', '\xb2', '\xb6', '\xba', '\xbe', '\xc2', '\xc6', '\xca', '\xce', '\xd2', '\xd6', '\xda', '\xde', '\xe2', '\xe6', '\xea', '\xee', '\xf2', '\xf6', '\xfa', '\xfe'}
            >>> sc = shellcraft.echo("Hello world") + shellcraft.exit()
            >>> ascii = encoders.i386.ascii_shellcode.encode(asm(sc), avoid)
            >>> ascii += asm('jmp esp') # just for testing, the unpacker should also run on the stack
            >>> ELF.from_bytes(ascii).process().recvall()
            b'Hello world'
        """
        if not avoid:
            vocab = bytearray(
                b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")
        else:
            required_chars = set('\\-%TXP')
            allowed = set(all_chars)
            if avoid.intersection(required_chars):
                raise RuntimeError(
                    '''These characters ({}) are required because they assemble
                    into instructions used to unpack the shellcode'''.format(
                        str(required_chars, 'ascii')))
            allowed.difference_update(avoid)
            vocab = bytearray(map(ord, allowed))

        if context.arch != 'i386' or context.bits != 32:
            raise RuntimeError('Only 32-bit i386 is currently supported')

        int_size = context.bytes

        # Prepend with NOPs for the NOP sled
        shellcode = bytearray(b'\x90'*int_size + raw_bytes)
        subtractions = self._get_subtractions(shellcode, vocab)
        allocator = self._get_allocator(len(subtractions) + self.slop, vocab)
        nop_sled = b'P' * self.slop  # push eax
        return bytes(allocator + subtractions + nop_sled)

    @LocalContext
    def _get_allocator(self, size, vocab):
        r""" Allocate enough space on the stack for the shellcode

        int_size is taken from the context

        Args:
            size (int): The allocation size
            vocab (bytearray): Allowed characters

        Returns:
            bytearray: The allocator shellcode

        Examples:

            >>> context.update(arch='i386', os='linux')
            >>> vocab = bytearray(b'!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~')
            >>> encoders.i386.ascii_shellcode.encode._get_allocator(300, vocab)
            bytearray(b'TX-!!!!-!_``-t~~~P\\%!!!!%@@@@')
        """
        size += 0x1e  # add typical allocator size
        int_size = context.bytes
        # Use eax for subtractions because sub esp, X doesn't assemble to ascii
        result = bytearray(b'TX')  # push esp; pop eax
        # Set target to the `size` arg
        target = bytearray(pack(size))
        # All we are doing here is adding (subtracting) `size`
        # to esp (to allocate space on the stack), so we don't care
        # about esp's actual value. That's why the `last` parameter
        # for `calc_subtractions` can just be zero
        for subtraction in self._calc_subtractions(
                bytearray(int_size), target, vocab):
            # sub eax, subtraction
            result += b'-' + subtraction
        result += b'P\\'  # push eax, pop esp
        # Zero out eax for the unpacking part
        pos, neg = self._find_negatives(vocab)
        # and eax, pos; and eax, neg ; (0b00010101 & 0b00101010 = 0b0)
        result += flat((b'%', pos, b'%', neg))
        return result

    @LocalContext
    def _find_negatives(self, vocab):
        r""" Find two bitwise negatives in the vocab so that when they are
        and-ed the result is 0.

        int_size is taken from the context

        Args:
            vocab (bytearray): Allowed characters

        Returns:
            Tuple[int, int]: value A, value B

        Raises:
            ArithmeticError: The allowed character set does not contain
                two characters that when they are bitwise-and-ed with eachother
                the result is 0

        Examples:

            >>> context.update(arch='i386', os='linux')
            >>> vocab = bytearray(b'!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~')
            >>> a, b = encoders.i386.ascii_shellcode.encode._find_negatives(vocab)
            >>> a & b
            0
        """
        int_size = context.bytes
        for products in product(vocab, vocab):
            if products[0] & products[1] == 0:
                return tuple(
                    # pylint: disable=undefined-variable
                    unpack(p8(x)*int_size)  # noqa: F405
                    for x in bytearray(products)
                )
        else:
            raise ArithmeticError(
                'Could not find two bitwise negatives in the provided vocab')

    @LocalContext
    def _get_subtractions(self, shellcode, vocab):
        r""" Covert the sellcode to sub eax and posh eax instructions

        int_size is taken from the context

        Args:
            shellcode (bytearray): The shellcode to pack
            vocab (bytearray): Allowed characters

        Returns:
            bytearray: packed shellcode

        Examples:

            >>> context.update(arch='i386', os='linux')
            >>> sc = bytearray(b'ABCDEFGHIGKLMNOPQRSTUVXYZ')
            >>> vocab = bytearray(b'!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~')
            >>> encoders.i386.ascii_shellcode.encode._get_subtractions(sc, vocab)
            bytearray(b'-(!!!-~NNNP-!=;:-f~~~-~~~~P-!!!!-edee-~~~~P-!!!!-eddd-~~~~P-!!!!-egdd-~~~~P-!!!!-eadd-~~~~P-!!!!-eddd-~~~~P')
        """
        int_size = context.bytes
        result = bytearray()
        last = bytearray(int_size)
        # Group the shellcode into bytes of stack cell size, pad with NOPs
        # if the shellcode does not divide into stack cell size and reverse.
        # The shellcode will be reversed again back to it's original order once
        # it's pushed onto the stack
        sc = tuple(group(int_size, shellcode, 0x90))[::-1]
        # Pack the shellcode to a sub/push sequence
        for x in sc:
            for subtraction in self._calc_subtractions(last, x, vocab):
                result += b'-' + subtraction  # sub eax, ...
            last = x
            result += b'P'  # push eax
        return result

    @LocalContext
    def _calc_subtractions(self, last, target, vocab):
        r""" Given `target` and `last`, return a list of integers that when
         subtracted from `last` will equal `target` while only constructing
         integers from bytes in `vocab`

        int_size is taken from the context

        Args:
            last (bytearray): Original value
            target (bytearray): Desired value
            vocab (bytearray): Allowed characters

        Raises:
            ArithmeticError: If a sequence of subtractions could not be found

        Returns:
            List[bytearray]: List of numbers that would need to be subtracted
            from `last` to get to `target`

        Examples:

            >>> context.update(arch='i386', os='linux')
            >>> vocab = bytearray(b'!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~')
            >>> print(encoders.i386.ascii_shellcode.encode._calc_subtractions(bytearray(b'\x10'*4), bytearray(b'\x11'*4), vocab))
            [bytearray(b'!!!!'), bytearray(b'`___'), bytearray(b'~~~~')]
            >>> print(encoders.i386.ascii_shellcode.encode._calc_subtractions(bytearray(b'\x11\x12\x13\x14'), bytearray(b'\x15\x16\x17\x18'), vocab))
            [bytearray(b'~}}}'), bytearray(b'~~~~')]
        """
        int_size = context.bytes
        subtractions = [bytearray(int_size)]
        for sub in range(self.max_subs):
            carry = success_count = 0
            for byte in range(int_size):
                # Try all combinations of all the characters in vocab of
                # `subtraction` characters in each combination. So if
                # `max_subs` is 4 and we're on the second subtraction attempt,
                # products will equal
                # [\, ", #, %, ...], [\, ", #, %, ...], (0,), (0,)
                for products in product(
                    *[x <= sub and vocab or (0,) for x in range(self.max_subs)]
                ):
                    # Sum up all the products, carry from last byte and
                    # the target
                    attempt = target[byte] + carry + sum(products)
                    # If the attempt equals last, we've found the combination
                    if last[byte] == attempt & 0xff:
                        carry = (attempt & 0xff00) >> 8
                        # Update the result with the current `products`
                        for p, i in zip(products, range(sub + 1)):
                            subtractions[i][byte] = p
                        success_count += 1
                        break
            if success_count == int_size:
                return subtractions
            else:
                subtractions.append(bytearray(int_size))
        else:
            raise ArithmeticError(
                str.format(
                    '''Could not find the correct subtraction sequence
                to get the the desired target ({}) from ({})''',
                    target[byte], last[byte]))


encode = AsciiShellcodeEncoder()
