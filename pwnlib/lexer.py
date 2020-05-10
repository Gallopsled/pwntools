from __future__ import division

import re

from pygments.lexer import DelegatingLexer
from pygments.lexer import RegexLexer
from pygments.lexer import bygroups
from pygments.lexer import include
from pygments.lexer import using
from pygments.lexers.c_cpp import CLexer
from pygments.lexers.c_cpp import CppLexer
from pygments.lexers.d import DLexer
from pygments.token import Comment
from pygments.token import Keyword
from pygments.token import Name
from pygments.token import Number
from pygments.token import Operator
from pygments.token import Other
from pygments.token import Punctuation
from pygments.token import String
from pygments.token import Text

__all__ = ['GasLexer', 'ObjdumpLexer', 'DObjdumpLexer', 'CppObjdumpLexer',
           'CObjdumpLexer', 'LlvmLexer', 'NasmLexer', 'NasmObjdumpLexer',
           'Ca65Lexer']


class PwntoolsLexer(RegexLexer):
    """
    For Gas (AT&T) assembly code.
    """
    name = 'GAS'
    aliases = ['gas', 'asm']
    filenames = ['*.s', '*.S', '*.asm']
    mimetypes = ['text/x-gas']

    #: optional Comment or Whitespace
    string = r'"(\\"|[^"])*"'
    char = r'[\w$.@-]'
    identifier = r'(?:[a-zA-Z$_]' + char + r'*|\.' + char + '+|or)'
    number = r'(?:0[xX][a-zA-Z0-9]+|\d+)'
    memory = r'(?:[\]\[])'
    bad = r'(?:\(bad\))'

    tokens = {
        'root': [
            include('whitespace'),
            (identifier + ':', Name.Label),
            (r'\.' + identifier, Name.Attribute, 'directive-args'),
            (r'lock|rep(n?z)?|data\d+', Name.Attribute),
            (identifier, Name.Function, 'instruction-args'),
            (r'[\r\n]+', Text),
            (bad, Text)
        ],

        'directive-args': [
            (identifier, Name.Constant),
            (string, String),
            ('@' + identifier, Name.Attribute),
            (number, Number.Integer),
            (r'[\r\n]+', Text, '#pop'),

            (r'#.*?$', Comment, '#pop'),

            include('punctuation'),
            include('whitespace')
        ],
        'instruction-args': [
            # For objdump-disassembled code, shouldn't occur in
            # actual assembler input
            ('([a-z0-9]+)( )(<)('+identifier+')(>)',
                bygroups(Number.Hex, Text, Punctuation, Name.Constant,
                         Punctuation)),
            ('([a-z0-9]+)( )(<)('+identifier+')([-+])('+number+')(>)',
                bygroups(Number.Hex, Text, Punctuation, Name.Constant,
                         Punctuation, Number.Integer, Punctuation)),

            # Fun things
            (r'([\]\[]|BYTE|DWORD|PTR|\+|\-|}|{|\^|>>|<<|&)', Text),

            # Address constants
            (identifier, Name.Constant),
            (number, Number.Integer),
            # Registers
            ('%' + identifier, Name.Variable),
            ('$' + identifier, Name.Variable),
            # Numeric constants
            ('$'+number, Number.Integer),
            ('#'+number, Number.Integer),
            (r"$'(.|\\')'", String.Char),
            (r'[\r\n]+', Text, '#pop'),
            include('punctuation'),
            include('whitespace')
        ],
        'whitespace': [
            (r'\n', Text),
            (r'\s+', Text),
            (r'/\*.*?\*/', Comment),
            (r';.*$', Comment)
        ],
        'punctuation': [
            (r'[-*,.():]+', Punctuation)
        ]
    }

    def analyse_text(text):
        if re.match(r'^\.(text|data|section)', text, re.M):
            return True
        elif re.match(r'^\.\w+', text, re.M):
            return 0.1
