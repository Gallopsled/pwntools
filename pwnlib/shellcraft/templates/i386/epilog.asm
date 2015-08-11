<%page args="nargs=0"/>
<%docstring>
Function epilogue.

Arguments:
    nargs(int): Number of arguments to pop off the stack.
</%docstring>

    leave
%if nargs:
    ret ${nargs}*4
%else:
    ret
%endif
