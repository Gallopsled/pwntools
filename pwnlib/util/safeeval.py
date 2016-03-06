_const_codes = [
    'POP_TOP','ROT_TWO','ROT_THREE','ROT_FOUR','DUP_TOP',
    'BUILD_LIST','BUILD_MAP','BUILD_TUPLE',
    'LOAD_CONST','RETURN_VALUE','STORE_SUBSCR', 'STORE_MAP'
    ]

_expr_codes = _const_codes + [
    'UNARY_POSITIVE','UNARY_NEGATIVE','UNARY_NOT',
    'UNARY_INVERT','BINARY_POWER','BINARY_MULTIPLY',
    'BINARY_DIVIDE','BINARY_FLOOR_DIVIDE','BINARY_TRUE_DIVIDE',
    'BINARY_MODULO','BINARY_ADD','BINARY_SUBTRACT',
    'BINARY_LSHIFT','BINARY_RSHIFT','BINARY_AND','BINARY_XOR',
    'BINARY_OR',
    ]

_values_codes = _expr_codes + ['LOAD_NAME']

def _get_opcodes(codeobj):
    """_get_opcodes(codeobj) -> [opcodes]

    Extract the actual opcodes as a list from a code object

    >>> c = compile("[1 + 2, (1,2)]", "", "eval")
    >>> _get_opcodes(c)
    [100, 100, 103, 83]
    """
    import dis
    i = 0
    opcodes = []
    s = codeobj.co_code
    while i < len(s):
        code = ord(s[i])
        opcodes.append(code)
        if code >= dis.HAVE_ARGUMENT:
            i += 3
        else:
            i += 1
    return opcodes

def test_expr(expr, allowed_codes):
    """test_expr(expr, allowed_codes) -> codeobj

    Test that the expression contains only the listed opcodes.
    If the expression is valid and contains only allowed codes,
    return the compiled code object. Otherwise raise a ValueError
    """
    import dis
    allowed_codes = [dis.opmap[c] for c in allowed_codes]
    try:
        c = compile(expr, "", "eval")
    except SyntaxError:
        raise ValueError("%s is not a valid expression" % expr)
    codes = _get_opcodes(c)
    for code in codes:
        if code not in allowed_codes:
            raise ValueError("opcode %s not allowed" % dis.opname[code])
    return c

def const(expr):
    """const(expression) -> value

    Safe Python constant evaluation

    Evaluates a string that contains an expression describing
    a Python constant. Strings that are not valid Python expressions
    or that contain other code besides the constant raise ValueError.

    Examples:

        >>> const("10")
        10
        >>> const("[1,2, (3,4), {'foo':'bar'}]")
        [1, 2, (3, 4), {'foo': 'bar'}]
        >>> const("[1]+[2]")
        Traceback (most recent call last):
        ...
        ValueError: opcode BINARY_ADD not allowed
    """

    c = test_expr(expr, _const_codes)
    return eval(c)

def expr(expr):
    """expr(expression) -> value

    Safe Python expression evaluation

    Evaluates a string that contains an expression that only
    uses Python constants. This can be used to e.g. evaluate
    a numerical expression from an untrusted source.

    Examples:

        >>> expr("1+2")
        3
        >>> expr("[1,2]*2")
        [1, 2, 1, 2]
        >>> expr("__import__('sys').modules")
        Traceback (most recent call last):
        ...
        ValueError: opcode LOAD_NAME not allowed
    """

    c = test_expr(expr, _expr_codes)
    return eval(c)

def values(expr, env):
    """values(expression, dict) -> value

    Safe Python expression evaluation

    Evaluates a string that contains an expression that only
    uses Python constants and values from a supplied dictionary.
    This can be used to e.g. evaluate e.g. an argument to a syscall.

    Note: This is potentially unsafe if e.g. the __add__ method has side
          effects.

    Examples:

        >>> values("A + 4", {'A': 6})
        10
        >>> class Foo:
        ...    def __add__(self, other):
        ...        print "Firing the missiles"
        >>> values("A + 1", {'A': Foo()})
        Firing the missiles
        >>> values("A.x", {'A': Foo()})
        Traceback (most recent call last):
        ...
        ValueError: opcode LOAD_ATTR not allowed
    """

    # The caller might need his dictionary again
    env = dict(env)

    # We do not want to have built-ins set
    env['__builtins__'] = {}

    c = test_expr(expr, _values_codes)
    return eval(c, env)
