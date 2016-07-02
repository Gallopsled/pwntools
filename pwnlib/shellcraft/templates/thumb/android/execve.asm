<%
    from pwnlib.shellcraft import thumb
    from pwnlib.abi import linux_arm_syscall
%>
<%docstring>
Execute a different process.
</%docstring>
<%page args="path = '/system/bin//sh', argv=[], envp={}"/>
<%
if isinstance(envp, dict):
    envp = ['%s=%s' % (k,v) for (k,v) in envp.items()]

regs = linux_arm_syscall.register_arguments
%>
% if argv:
    ${thumb.pushstr_array(regs[2], argv)}
% else:
    ${thumb.mov(regs[2], 0)}
% endif
% if envp:
    ${thumb.pushstr_array(regs[3], envp)}
% else:
    ${thumb.mov(regs[3], 0)}
% endif
    ${thumb.pushstr(path)}
    ${thumb.syscall('SYS_execve', 'sp', regs[2], regs[3])}
