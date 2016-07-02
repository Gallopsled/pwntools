# -*- coding: utf-8 -*-
"""
Topographical sort
"""
from collections import OrderedDict
from collections import defaultdict
from random import randint
from random import shuffle

from .context import context
from .log import getLogger

log = getLogger(__name__)

def check_cycle(reg, assignments):
    """Walk down the assignment list of a register,
    return the path walked if it is encountered again.

    Returns:

        The list of register involved in the cycle.
        If there is no cycle, this is an empty list.

    Example:

        >>> check_cycle('a', {'a': 1})
        []
        >>> check_cycle('a', {'a': 'a'})
        ['a']
        >>> check_cycle('a', {'a': 'b', 'b': 'a'})
        ['a', 'b']
        >>> check_cycle('a', {'a': 'b', 'b': 'c', 'c': 'b', 'd': 'a'})
        []
        >>> check_cycle('a', {'a': 'b', 'b': 'c', 'c': 'd', 'd': 'a'})
        ['a', 'b', 'c', 'd']
    """
    return check_cycle_(reg, assignments, [])

def check_cycle_(reg, assignments, path):
    target = assignments[reg]
    path.append(reg)

    # No cycle, some other value (e.g. 1)
    if target not in assignments:
        return []

    # Found a cycle
    if target in path:
        # Does the cycle *start* with target?
        # This determines whether the original register is
        # in the cycle, or just depends on registers in one.
        if target == path[0]:
            return path

        # Just depends on one.
        return []

    # Recurse
    return check_cycle_(target, assignments, path)

def extract_dependencies(reg, assignments):
    """Return a list of all registers which directly
    depend on the specified register.

    Example:

        >>> extract_dependencies('a', {'a': 1})
        []
        >>> extract_dependencies('a', {'a': 'b', 'b': 1})
        []
        >>> extract_dependencies('a', {'a': 1, 'b': 'a'})
        ['b']
        >>> extract_dependencies('a', {'a': 1, 'b': 'a', 'c': 'a'})
        ['b', 'c']
    """
    # sorted() is only for determinism
    return sorted([k for k,v in assignments.items() if v == reg])


def resolve_order(reg, deps):
    """
    Resolve the order of all dependencies starting at a given register.

    Example:

        >>> want = {'a': 1, 'b': 'c', 'c': 'd', 'd': 7, 'x': 'd'}
        >>> deps = {'a': [], 'b': [], 'c': ['b'], 'd': ['c', 'x'], 'x': []}
        >>> resolve_order('a', deps)
        ['a']
        >>> resolve_order('b', deps)
        ['b']
        >>> resolve_order('c', deps)
        ['b', 'c']
        >>> resolve_order('d', deps)
        ['b', 'c', 'x', 'd']
    """
    x = []
    for dep in deps[reg]:
        x.extend(resolve_order(dep, deps))
    x.append(reg)
    return x

def depends_on_cycle(reg, assignments, in_cycles):
    while reg in assignments:
        if reg in in_cycles:
            return True
        reg = assignments.get(reg, None)
    return False

def regsort(in_out, all_regs, tmp = None, xchg = True, randomize = None):
    """
    Sorts register dependencies.

    Given a dictionary of registers to desired register contents,
    return the optimal order in which to set the registers to
    those contents.

    The implementation assumes that it is possible to move from
    any register to any other register.

    If a dependency cycle is encountered, one of the following will
    occur:

    - If ``xchg`` is ``True``, it is assumed that dependency cyles can
      be broken by swapping the contents of two register (a la the
      ``xchg`` instruction on i386).
    - If ``xchg`` is not set, but not all destination registers in
      ``in_out`` are involved in a cycle, one of the registers
      outside the cycle will be used as a temporary register,
      and then overwritten with its final value.
    - If ``xchg`` is not set, and all registers are involved in
      a dependency cycle, the named register ``temporary`` is used
      as a temporary register.
    - If the dependency cycle cannot be resolved as described above,
      an exception is raised.

    Arguments:

        in_out(dict):
            Dictionary of desired register states.
            Keys are registers, values are either registers or any other value.
        all_regs(list):
            List of all possible registers.
            Used to determine which values in ``in_out`` are registers, versus
            regular values.
        tmp(obj, str):
            Named register (or other sentinel value) to use as a temporary
            register.  If ``tmp`` is a named register **and** appears
            as a source value in ``in_out``, dependencies are handled
            appropriately.  ``tmp`` cannot be a destination register
            in ``in_out``.
            If ``bool(tmp)==True``, this mode is enabled.
        xchg(obj):
            Indicates the existence of an instruction which can swap the
            contents of two registers without use of a third register.
            If ``bool(xchg)==False``, this mode is disabled.
        random(bool):
            Randomize as much as possible about the order or registers.

    Returns:

        A list of tuples of ``(src, dest)``.

        Each register may appear more than once, if a register is used
        as a temporary register, and later overwritten with its final
        value.

        If ``xchg`` is ``True`` and it is used to break a dependency cycle,
        then ``reg_name`` will be ``None`` and ``value`` will be a tuple
        of the instructions to swap.

    Example:

        >>> R = ['a', 'b', 'c', 'd', 'x', 'y', 'z']

        If order doesn't matter for any subsequence, alphabetic
        order is used.

        >>> regsort({'a': 1, 'b': 2}, R)
        [('mov', 'a', 1), ('mov', 'b', 2)]
        >>> regsort({'a': 'b', 'b': 'a'}, R)
        [('xchg', 'a', 'b')]
        >>> regsort({'a': 'b', 'b': 'a'}, R, tmp='X') #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'X', 'a'),
         ('mov', 'a', 'b'),
         ('mov', 'b', 'X')]
        >>> regsort({'a': 1, 'b': 'a'}, R) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'b', 'a'),
         ('mov', 'a', 1)]
        >>> regsort({'a': 'b', 'b': 'a', 'c': 3}, R) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'c', 3),
         ('xchg', 'a', 'b')]
        >>> regsort({'a': 'b', 'b': 'a', 'c': 'b'}, R) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'c', 'b'),
         ('xchg', 'a', 'b')]
        >>> regsort({'a':'b', 'b':'a', 'x':'b'}, R, tmp='y', xchg=False) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'x', 'b'),
         ('mov', 'y', 'a'),
         ('mov', 'a', 'b'),
         ('mov', 'b', 'y')]
        >>> regsort({'a':'b', 'b':'a', 'x':'b'}, R, tmp='x', xchg=False) #doctest: +ELLIPSIS
        Traceback (most recent call last):
        ...
        PwnlibException: Cannot break dependency cycles ...
        >>> regsort({'a':'b','b':'c','c':'a','x':'1','y':'z','z':'c'}, R) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'x', '1'),
         ('mov', 'y', 'z'),
         ('mov', 'z', 'c'),
         ('xchg', 'a', 'b'),
         ('xchg', 'b', 'c')]
        >>> regsort({'a':'b','b':'c','c':'a','x':'1','y':'z','z':'c'}, R, tmp='x') #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'y', 'z'),
         ('mov', 'z', 'c'),
         ('mov', 'x', 'a'),
         ('mov', 'a', 'b'),
         ('mov', 'b', 'c'),
         ('mov', 'c', 'x'),
         ('mov', 'x', '1')]
        >>> regsort({'a':'b','b':'c','c':'a','x':'1','y':'z','z':'c'}, R, xchg=0) #doctest: +NORMALIZE_WHITESPACE
        [('mov', 'y', 'z'),
         ('mov', 'z', 'c'),
         ('mov', 'x', 'a'),
         ('mov', 'a', 'b'),
         ('mov', 'b', 'c'),
         ('mov', 'c', 'x'),
         ('mov', 'x', '1')]
    """
    if randomize is None:
        randomize = context.randomize

    sentinel = object()

    # Drop all registers which will be set to themselves.
    #
    # For example, {'eax': 'eax'}
    in_out = {k:v for k,v in in_out.items() if k != v}

    # Collapse constant values
    #
    # For eaxmple, {'eax': 0, 'ebx': 0} => {'eax': 0, 'ebx': 'eax'}
    v_k = defaultdict(lambda: [])
    for k,v in sorted(in_out.items()):
        if v not in all_regs and v != 0:
            v_k[v].append(k)

    post_mov = {}

    for v,ks in sorted(v_k.items()):
        for k in ks[1:]:
            post_mov[k] = ks[0]
            in_out.pop(k)

    # Check input
    if not all(k in all_regs for k in in_out):
        log.error("Unknown register! Know: %r.  Got: %r" % (all_regs, list(in_out)))

    # In the simplest case, no registers are 'inputs'
    # which are also 'outputs'.
    #
    # For example, {'eax': 1, 'ebx': 2, 'ecx': 'edx'}
    if not any(v in in_out for k,v in in_out.items()):
        result = [('mov', k,in_out[k]) for k in sorted(in_out)]

        if randomize:
            shuffle(result)

        for dreg, sreg in sorted(post_mov.items()):
            result.append(('mov', dreg, sreg))

        return result

    # Invert so we have a dependency graph.
    #
    # Input:   {'A': 'B', 'B': '1', 'C': 'B'}
    # Output:  {'A': [], 'B': ['A', 'C'], 'C': []}
    #
    # In this case, both A and C must be set before B.
    deps  = {r: extract_dependencies(r, in_out) for r in in_out}

    # Final result which will be returned
    result = []

    # Find all of the cycles.
    #
    # Given that everything is single-assignment, the cycles
    # are guarnteed to be disjoint.
    cycle_candidates = sorted(list(in_out))
    cycles           = []
    in_cycle         = []
    not_in_cycle     = []

    if randomize:
        shuffle(cycle_candidates)

    while cycle_candidates:
        reg   = cycle_candidates[0]
        cycle = check_cycle(reg, in_out)

        if cycle:
            if randomize:
                x = randint(0, len(cycle))
                cycle = cycle[x:] + cycle[:x]


            cycles.append(cycle)
            in_cycle.extend(cycle)
            for reg in cycle:
                cycle_candidates.remove(reg)
        else:
            not_in_cycle.append(cycle_candidates.pop(0))

    #
    # If there are cycles, ensure that we can break them.
    #
    # If the temporary register itself is in, or ultimately
    # depends on a register which is in a cycle, we cannot use
    # it as a temporary register.
    #
    # In this example below, X, Y, or Z cannot be a temporary register,
    # as the following must occur before resolving the cycle:
    #
    #  - X = Y
    #  - Y = Z
    #  - Z = C
    #
    #   X → Y → Z → ───╮
    #                  ↓
    #  ╭─ (A) → (B) → (C) ─╮
    #  ╰──────── ← ────────╯
    if depends_on_cycle(tmp, in_out, in_cycle):
        tmp = None

    # If XCHG is expressly disabled, and there is no temporary register,
    # try to see if there is any register which can be used as a temp
    # register instead.
    if not (xchg or tmp):
        for reg in in_out:
            if not depends_on_cycle(reg, in_out, in_cycle):
                tmp = reg
                break
        else:
            nope = sorted((k,v) for k,v in in_out.items())
            log.error("Cannot break dependency cycles in %r" % nope)


    # Don't set the temporary register now
    if tmp in not_in_cycle:
        not_in_cycle.remove(tmp)

    # Resolve everything *not* in a cycle.
    if randomize:
        shuffle(not_in_cycle)

    while not_in_cycle:
        reg   = not_in_cycle[0]
        order = resolve_order(reg, deps)

        for reg in order:
            # Did we already handle this reg?
            if reg not in not_in_cycle:
                continue

            src =  in_out[reg]
            result.append(('mov', reg, src))
            not_in_cycle.remove(reg)

            # Mark this as resolved
            if reg in deps.get(src, []):
                deps[src].remove(reg)


    # If using a temporary register, break each cycle individually
    #
    #  ╭─ (A) → (B) → (C) ─╮
    #  ╰──────── ← ────────╯
    #
    # Becomes separete actions:
    #
    #   tmp = A
    #   A = B
    #   B = C
    #   C = tmp
    #
    #  ╭─ (A) → (B) → (C) ─╮
    #  ╰──────── ← ────────╯
    if randomize:
        shuffle(cycles)

    if tmp:
        for cycle in cycles:

            first = cycle[0]
            last  = cycle[-1]

            deps[first].remove(last)
            in_out[last] = tmp

            order = resolve_order(last, deps)

            result.append(('mov', tmp, first))
            for reg in order:
                result.append(('mov', reg, in_out[reg]))

    else:
        for cycle in cycles:
            size = len(cycle)
            for i in range(size-1):
                result.append(('xchg', cycle[i], cycle[(i+1) % size]))

    # Finally, set the temp register's final value
    if tmp and tmp in in_out:
        result.append(('mov', tmp, in_out[tmp]))

    for dreg, sreg in sorted(post_mov.items()):
        result.append(('mov', dreg, sreg))

    return result
