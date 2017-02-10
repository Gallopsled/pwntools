#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Routines here are for getting any NULL-terminated sequence of bytes evaluated
intact by any shell.  This includes all variants of quotes, whitespace, and
non-printable characters.

Supported Shells
----------------

The following shells have been evaluated:

- Ubuntu (dash/sh)
- MacOS (GNU Bash)
- Zsh
- FreeBSD (sh)
- OpenBSD (sh)
- NetBSD (sh)

Debian Almquist shell (Dash)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ubuntu 14.04 and 16.04 use the Dash shell, and /bin/sh is actually just a
symlink to /bin/dash.  The feature set supported when invoked as "sh" instead
of "dash" is different, and we focus exclusively on the "/bin/sh" implementation.

From the `Ubuntu Man Pages`_, every character except for single-quote
can be wrapped in single-quotes, and a backslash can be used to escape unquoted
single-quotes.

::

    Quoting
      Quoting is used to remove the special meaning of certain characters or
      words to the shell, such as operators, whitespace, or keywords.  There
      are three types of quoting: matched single quotes, matched double quotes,
      and backslash.

    Backslash
      A backslash preserves the literal meaning of the following character,
      with the exception of ⟨newline⟩.  A backslash preceding a ⟨newline⟩ is
      treated as a line continuation.

    Single Quotes
      Enclosing characters in single quotes preserves the literal meaning of
      all the characters (except single quotes, making it impossible to put
      single-quotes in a single-quoted string).

    Double Quotes
      Enclosing characters within double quotes preserves the literal meaning
      of all characters except dollarsign ($), backquote (`), and backslash
      (\).  The backslash inside double quotes is historically weird, and
      serves to quote only the following characters:
            $ ` " \ <newline>.
      Otherwise it remains literal.

GNU Bash
~~~~~~~~

The Bash shell is default on many systems, though it is not generally the default
system-wide shell (i.e., the `system` syscall does not generally invoke it).

That said, its prevalence suggests that it also be addressed.

From the `GNU Bash Manual`_, every character except for single-quote
can be wrapped in single-quotes, and a backslash can be used to escape unquoted
single-quotes.

::

    3.1.2.1 Escape Character

    A non-quoted backslash ‘\’ is the Bash escape character. It preserves the
    literal value of the next character that follows, with the exception of
    newline. If a ``\\newline`` pair appears, and the backslash itself is not
    quoted, the ``\\newline`` is treated as a line continuation (that is, it
    is removed from the input stream and effectively ignored).

    3.1.2.2 Single Quotes

    Enclosing characters in single quotes (‘'’) preserves the literal value of
    each character within the quotes. A single quote may not occur between single
    uotes, even when preceded by a backslash.

    3.1.2.3 Double Quotes

    Enclosing characters in double quotes (‘"’) preserves the literal value of a
    ll characters within the quotes, with the exception of ‘$’, ‘`’, ‘\’, and,
    when history expansion is enabled, ‘!’. The characters ‘$’ and ‘`’ retain their
    pecial meaning within double quotes (see Shell Expansions). The backslash retains
    its special meaning only when followed by one of the following characters:
    ‘$’, ‘`’, ‘"’, ‘\’, or newline. Within double quotes, backslashes that are
    followed by one of these characters are removed. Backslashes preceding
    characters without a special meaning are left unmodified. A double quote may
    be quoted within double quotes by preceding it with a backslash. If enabled,
    history expansion will be performed unless an ‘!’ appearing in double quotes
    is escaped using a backslash. The backslash preceding the ‘!’ is not removed.

    The special parameters ‘*’ and ‘@’ have special meaning when in double quotes
    see Shell Parameter Expansion).

Z Shell
~~~~~~~

The Z shell is also a relatively common user shell, even though it's not generally
the default system-wide shell.

From the `Z Shell Manual`_, every character except for single-quote
can be wrapped in single-quotes, and a backslash can be used to escape unquoted
single-quotes.

::

    A character may be quoted (that is, made to stand for itself) by preceding
    it with a ‘\’. ‘\’ followed by a newline is ignored.

    A string enclosed between ‘$'’ and ‘'’ is processed the same way as the
    string arguments of the print builtin, and the resulting string is considered
    o be entirely quoted. A literal ‘'’ character can be included in the string
    by using the ‘\\'’ escape.

    All characters enclosed between a pair of single quotes ('') that is not
    preceded by a ‘$’ are quoted. A single quote cannot appear within single
    quotes unless the option RC_QUOTES is set, in which case a pair of single
    quotes are turned into a single quote. For example,

    print ''''
    outputs nothing apart from a newline if RC_QUOTES is not set, but one single
    quote if it is set.

    Inside double quotes (""), parameter and command substitution occur, and
    ‘\’ quotes the characters ‘\’, ‘`’, ‘"’, and ‘$’.

FreeBSD Shell
~~~~~~~~~~~~~

Compatibility with the FreeBSD shell is included for completeness.

From the `FreeBSD man pages`_, every character except for single-quote
can be wrapped in single-quotes, and a backslash can be used to escape unquoted
single-quotes.

::

     Quoting is used to remove the special meaning of certain characters or
     words to the shell, such as operators, whitespace, keywords, or alias
     names.

     There are four types of quoting: matched single quotes, dollar-single
     quotes, matched double quotes, and backslash.

     Single Quotes
         Enclosing characters in single quotes preserves the literal mean-
         ing of all the characters (except single quotes, making it impos-
         sible to put single-quotes in a single-quoted string).

     Dollar-Single Quotes
         Enclosing characters between $' and ' preserves the literal mean-
         ing of all characters except backslashes and single quotes.  A
         backslash introduces a C-style escape sequence:

         ...

     Double Quotes
         Enclosing characters within double quotes preserves the literal
         meaning of all characters except dollar sign (`$'), backquote
         (``'), and backslash (`\\').  The backslash inside double quotes
         is historically weird.  It remains literal unless it precedes the
         following characters, which it serves to quote:

           $     `     "     \     \\n

     Backslash
         A backslash preserves the literal meaning of the following char-
         acter, with the exception of the newline character (`\\n').  A
         backslash preceding a newline is treated as a line continuation.

OpenBSD Shell
~~~~~~~~~~~~~

From the `OpenBSD Man Pages`_, every character except for single-quote
can be wrapped in single-quotes, and a backslash can be used to escape unquoted
single-quotes.

::

    A backslash (\) can be used to quote any character except a newline.
    If a newline follows a backslash the shell removes them both, effectively
    making the following line part of the current one.

    A group of characters can be enclosed within single quotes (') to quote
    every character within the quotes.

    A group of characters can be enclosed within double quotes (") to quote
    every character within the quotes except a backquote (`) or a dollar
    sign ($), both of which retain their special meaning. A backslash (\)
    within double quotes retains its special meaning, but only when followed
    by a backquote, dollar sign, double quote, or another backslash.
    An at sign (@) within double quotes has a special meaning
    (see SPECIAL PARAMETERS, below).

NetBSD Shell
~~~~~~~~~~~~

The NetBSD shell's documentation is identical to the Dash documentation.

Android Shells
~~~~~~~~~~~~~~

Android has gone through some number of shells.

- Mksh, a Korn shell, was used with Toolbox releases (5.0 and prior)
- Toybox, also derived from the Almquist Shell (6.0 and newer)

Notably, the Toolbox implementation is not POSIX compliant
as it lacks a "printf" builtin (e.g. Android 5.0 emulator images).

Toybox Shell
~~~~~~~~~~~~

Android 6.0 (and possibly other versions) use a shell based on ``toybox``.

While it does not include a ``printf`` builtin, ``toybox`` itself includes
a POSIX-compliant ``printf`` binary.

The Ash shells should be feature-compatible with ``dash``.

BusyBox Shell
~~~~~~~~~~~~~

`BusyBox's Wikipedia page`_ claims to use an ``ash``-compliant shell,
and should therefore be compatible with ``dash``.


.. _Ubuntu Man Pages: http://manpages.ubuntu.com/manpages/trusty/man1/dash.1.html
.. _GNU Bash Manual: https://www.gnu.org/software/bash/manual/bash.html#Quoting
.. _Z Shell Manual: http://zsh.sourceforge.net/Doc/Release/Shell-Grammar.html#Quoting
.. _FreeBSD man pages: https://www.freebsd.org/cgi/man.cgi?query=sh
.. _OpenBSD Man Pages: http://man.openbsd.org/cgi-bin/man.cgi?query=sh#SHELL_GRAMMAR
.. _BusyBox's Wikipedia page: https://en.wikipedia.org/wiki/BusyBox#Features
"""
from __future__ import absolute_import

import string
import subprocess

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.tubes.process import process
from pwnlib.util import fiddling
from pwnlib.util.misc import which

log = getLogger(__name__)

def test_all():
    test('a')
    test('ab')
    test('a b')
    test(r"a\'b")
    everything_1 = ''.join(chr(c) for c in range(1,256))
    for s in everything_1:
        test(s)
        test(s*4)
        test(s * 2 + 'X')
        test('X' + s * 2)
        test((s*2 + 'X') * 2)
        test(s + 'X' + s)
        test(s*2 + 'X' + s*2)
        test('X' + s*2 + 'X')
    test(everything_1)
    test(everything_1 * 2)
    test(everything_1 * 4)
    everything_2 = ''.join(chr(c) * 2 for c in range(1,256))
    test(everything_2)

    test(randoms(1000, everything_1))


def test(original):
    r"""Tests the output provided by a shell interpreting a string

    >>> test('foobar')
    >>> test('foo bar')
    >>> test('foo bar\n')
    >>> test("foo'bar")
    >>> test("foo\\\\bar")
    >>> test("foo\\\\'bar")
    >>> test("foo\\x01'bar")
    >>> test('\n')
    >>> test('\xff')
    >>> test(os.urandom(16 * 1024).replace('\x00', ''))
    """
    input = sh_string(original)

    cmdstr = '/bin/echo %s' % input

    SUPPORTED_SHELLS = [
        ['ash', '-c', cmdstr],
        ['bash', '-c', cmdstr],
        ['bash', '-o', 'posix', '-c', cmdstr],
        ['ksh', '-c', cmdstr],
        ['busybox', 'ash', '-c', cmdstr],
        ['busybox', 'sh', '-c', cmdstr],
        ['zsh', '-c', cmdstr],
        ['posh', '-c', cmdstr],
        ['dash', '-c', cmdstr],
        ['mksh', '-c', cmdstr],
        ['sh', '-c', cmdstr],
        # ['adb', 'exec-out', cmdstr]
    ]

    for shell in SUPPORTED_SHELLS:
        binary = shell[0]

        if not which(binary):
            log.warn_once('Shell %r is not available' % binary)
            continue

        progress = log.progress('%s: %r' % (binary, original))

        with context.quiet:
            with process(shell) as p:
                data = p.recvall(timeout=2)
                p.kill()

        # Remove exactly one trailing newline added by echo
        # We cannot assume "echo -n" exists.
        data = data[:-1]

        if data != original:
            for i,(a,b) in enumerate(zip(data, original)):
                if a == b:
                    continue
                log.error(('Shell %r failed\n' +
                          'Expect %r\n' +
                          'Sent   %r\n' +
                          'Output %r\n' +
                          'Mismatch @ %i: %r vs %r') \
                        % (binary, original, input, data, i, a, b))

        progress.success()



SINGLE_QUOTE = "'"
ESCAPED_SINGLE_QUOTE = r"\'"

ESCAPED = {
    # The single quote itself must be escaped, outside of single quotes.
    "'": "\\'",

    # Slashes must themselves be escaped
    #
    # Additionally, some shells coalesce any number N>1 of '\' into
    # a single backslash literal.
    # '\\': '"\\\\\\\\"'
}

def sh_string(s):
    r"""Outputs a string in a format that will be understood by /bin/sh.

    If the string does not contain any bad characters, it will simply be
    returned, possibly with quotes. If it contains bad characters, it will
    be escaped in a way which is compatible with most known systems.

    Warning:
        This does not play along well with the shell's built-in "echo".
        It works exactly as expected to set environment variables and
        arguments, **unless** it's the shell-builtin echo.

    Argument:
        s(str): String to escape.

    Examples:

        >>> sh_string('foobar')
        'foobar'
        >>> sh_string('foo bar')
        "'foo bar'"
        >>> sh_string("foo'bar")
        "'foo'\\''bar'"
        >>> sh_string("foo\\\\bar")
        "'foo\\\\bar'"
        >>> sh_string("foo\\\\'bar")
        "'foo\\\\'\\''bar'"
        >>> sh_string("foo\\x01'bar")
        "'foo\\x01'\\''bar'"
    """
    if '\x00' in s:
        log.error("sh_string(): Cannot create a null-byte")

    if s == '':
        return "''"

    chars = set(s)
    very_good = set(string.ascii_letters + string.digits + "_+.,/")

    # Alphanumeric can always just be used verbatim.
    if chars <= very_good:
        return s

    # If there are no single-quotes, the entire thing can be single-quoted
    if not (chars & set(ESCAPED)):
        return "'%s'" % s

    # If there are single-quotes, we can single-quote around them, and simply
    # escape the single-quotes.
    quoted_string = ''
    quoted = False
    for char in s:
        if char not in ESCAPED:
            if not quoted:
                quoted_string += SINGLE_QUOTE
                quoted = True
            quoted_string += char
        else:
            if quoted:
                quoted = False
                quoted_string += SINGLE_QUOTE
            quoted_string += ESCAPED[char]

    if quoted:
        quoted_string += SINGLE_QUOTE

    return quoted_string

def sh_prepare(variables, export = False):
    r"""Outputs a posix compliant shell command that will put the data specified
    by the dictionary into the environment.

    It is assumed that the keys in the dictionary are valid variable names that
    does not need any escaping.

    Arguments:
      variables(dict): The variables to set.
      export(bool): Should the variables be exported or only stored in the shell environment?
      output(str): A valid posix shell command that will set the given variables.

    It is assumed that `var` is a valid name for a variable in the shell.

    Examples:

        >>> sh_prepare({'X': 'foobar'})
        'X=foobar'
        >>> r = sh_prepare({'X': 'foobar', 'Y': 'cookies'})
        >>> r == 'X=foobar;Y=cookies' or r == 'Y=cookies;X=foobar'
        True
        >>> sh_prepare({'X': 'foo bar'})
        "X='foo bar'"
        >>> sh_prepare({'X': "foo'bar"})
        "X='foo'\\''bar'"
        >>> sh_prepare({'X': "foo\\\\bar"})
        "X='foo\\\\bar'"
        >>> sh_prepare({'X': "foo\\\\'bar"})
        "X='foo\\\\'\\''bar'"
        >>> sh_prepare({'X': "foo\\x01'bar"})
        "X='foo\\x01'\\''bar'"
        >>> sh_prepare({'X': "foo\\x01'bar"}, export = True)
        "export X='foo\\x01'\\''bar'"
        >>> sh_prepare({'X': "foo\\x01'bar\\n"})
        "X='foo\\x01'\\''bar\\n'"
        >>> sh_prepare({'X': "foo\\x01'bar\\n"})
        "X='foo\\x01'\\''bar\\n'"
        >>> sh_prepare({'X': "foo\\x01'bar\\n"}, export = True)
        "export X='foo\\x01'\\''bar\\n'"
    """

    out = []
    export = 'export ' if export else ''

    for k, v in variables.items():
        out.append('%s%s=%s' % (export, k, sh_string(v)))

    return ';'.join(out)

def sh_command_with(f, *args):
    r"""sh_command_with(f, arg0, ..., argN) -> command

    Returns a command create by evaluating `f(new_arg0, ..., new_argN)`
    whenever `f` is a function and `f % (new_arg0, ..., new_argN)` otherwise.

    If the arguments are purely alphanumeric, then they are simply passed to
    function. If they are simple to escape, they will be escaped and passed to
    the function.

    If the arguments contain trailing newlines, then it is hard to use them
    directly because of a limitation in the posix shell. In this case the
    output from `f` is prepended with a bit of code to create the variables.

    Examples:

        >>> sh_command_with(lambda: "echo hello")
        'echo hello'
        >>> sh_command_with(lambda x: "echo " + x, "hello")
        'echo hello'
        >>> sh_command_with(lambda x: "/bin/echo " + x, "\\x01")
        "/bin/echo '\\x01'"
        >>> sh_command_with(lambda x: "/bin/echo " + x, "\\x01\\n")
        "/bin/echo '\\x01\\n'"
        >>> sh_command_with("/bin/echo %s", "\\x01\\n")
        "/bin/echo '\\x01\\n'"
    """

    args = list(args)
    out = []

    for n in range(len(args)):
        args[n] = sh_string(args[n])
    if hasattr(f, '__call__'):
        out.append(f(*args))
    else:
        out.append(f % tuple(args))
    return ';'.join(out)
