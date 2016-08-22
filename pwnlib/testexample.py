"""
Module-level documentation would go here, along with a general description
of the functionality.  You can also add module-level doctests.

You can see what the documentation for this module will look like here:
https://docs.pwntools.com/en/stable/testexample.html

The tests for this module are run when the documentation is automatically-generated
by Sphinx.  This particular module is invoked by an "automodule" directive, which
imports everything in the module, or everything listed in ``__all__`` in the module.

The doctests are automatically picked up by the ``>>>`` symbol, like from
the Python prompt.  For more on doctests, see the `Python documentation
<https://docs.python.org/2/library/doctest.html>`_.

All of the syntax in this file is ReStructuredText.  You can find a
`nice cheat sheet here <https://goo.gl/qEKFIu>`_.

Here's an example of a module-level doctest:

    >>> add(3, add(2, add(1, 0)))
    6

If doctests are wrong / broken, you can disable them temporarily.

    >>> add(2, 2) # doctest: +SKIP
    5

Some things in Python are non-deterministic, like ``dict`` or ``set``
ordering.  There are a lot of ways to work around this, but the
accepted way of doing this is to test for equality.

    >>> a = {a:a+1 for a in range(3)}
    >>> a == {0:1, 1:2, 2:3}
    True

In order to use other modules, they need to be imported from the RST
which documents the module.

    >>> os.path.basename('foo/bar')
    'bar'

"""

def add(a, b):
    '''add(a, b) -> int

    Adds the numbers ``a`` and ``b``.

    Arguments:
        a(int): First number to add
        b(int): Second number to add

    Returns:
        The sum of ``a`` and ``b``.

    Examples:

        >>> add(1,2)
        3
        >>> add(-1, 33)
        32
    '''
    return a+b
