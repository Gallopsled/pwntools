
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="idtype, id, infop, options"/>
<%docstring>
Invokes the syscall waitid.  See 'man 2 waitid' for more information.

Arguments:
    idtype(idtype_t): idtype
    id(id_t): id
    infop(siginfo_t): infop
    options(int): options
</%docstring>

    ${syscall('SYS_waitid', idtype, id, infop, options)}
