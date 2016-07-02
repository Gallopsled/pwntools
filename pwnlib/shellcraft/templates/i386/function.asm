<%
    from pwnlib.shellcraft import i386
%>
<%docstring>
Converts a shellcraft template into a callable function.

Arguments:
    template_sz(callable):
        Rendered shellcode template.  Any variable Arguments
        should be supplied as registers.
    name(str):
        Name of the function.
    registers(list):
        List of registers which should be filled from the stack.

::

    >>> shellcode = ''
    >>> shellcode += shellcraft.function('write', shellcraft.i386.linux.write, )

    >>> hello = shellcraft.i386.linux.echo("Hello!", 'eax')
    >>> hello_fn = shellcraft.i386.function(hello, 'eax').strip()
    >>> exit = shellcraft.i386.linux.exit('edi')
    >>> exit_fn = shellcraft.i386.function(exit, 'edi').strip()
    >>> shellcode = '''
    ...     push STDOUT_FILENO
    ...     call hello
    ...     push 33
    ...     call exit
    ... hello:
    ...     %(hello_fn)s
    ... exit:
    ...     %(exit_fn)s
    ... ''' % (locals())
    >>> p = run_assembly(shellcode)
    >>> p.recvall()
    'Hello!'
    >>> p.wait_for_close()
    >>> p.poll()
    33

Notes:

    Can only be used on a shellcraft template which takes
    all of its arguments as registers.  For example, the
    pushstr
</%docstring>
<%page args="name, template_function, *registers"/>
<%
    ifdef = '_%s_' % name
%>
/* ${name}(${', '.join(registers)}) */
#ifndef ${ifdef}
#define ${ifdef}
${name}:
    /* Save stack */
    ${i386.prolog()}
    /* Load arguments */
% for i, reg in enumerate(registers):
    ${i386.stackarg(i, reg)}
% endfor
    ${template_function(*registers)}
    /* Restore stack */
    ${i386.epilog(len(registers))}
#endif /* ${ifdef} */
