<%
    from pwnlib.shellcraft import arm
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
    ${arm.pushstr_array(regs[2], argv)}
% else:
    ${arm.mov(regs[2], 0)}
% endif
% if envp:
    ${arm.pushstr_array(regs[3], envp)}
% else:
    ${arm.mov(regs[3], 0)}
% endif
    ${arm.pushstr(path)}
    ${arm.syscall('SYS_execve', 'sp', regs[2], regs[3])}
