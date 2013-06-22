from pwn.internal.shellcode_helper import *
from ..misc.pushstr import pushstr

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'])
def exit(returncode = None, arch = None, os = None):
    """Exits. Default return code, None, means "I don't care"."""

    returncode = arg_fixup(returncode)

    if arch == 'i386':
        if os in ['linux', 'freebsd']:
            return _exit_i386(returncode, os)
    elif arch == 'amd64':
        if os in ['linux', 'freebsd']:
            return _exit_amd64(returncode, os)

    bug("OS/arch combination (%s, %s) is not supported for exit" % (os, arch))

def _exit_amd64(returncode, os):
    out = ["push SYS_exit",
           "pop rax"]

    if returncode != None:
        if os == 'linux':
            if returncode == 0:
                out += ['xor ebx, ebx']
            elif isinstance(returncode, int):
                out += [pushstr(p32(returncode), null = False, raw = True),
                        'pop rbx']
            else:
                out += ['mov ebx, %s' % str(returncode)]
        elif os == 'freebsd':
            if returncode == 0:
                out += ['cdq', 'push rdx']
            elif isinstance(returncode, int):
                out += [pushstr(p32(returncode), null = False, raw = True)]
            else:
                out += ['push %s' % str(returncode)]
            out += ['push rax']
    out += ['syscall']

    return '\n'.join('    ' + s for s in out)


def _exit_i386(returncode, os):
    if returncode == None:
        return """
            push SYS_exit
            pop eax
            int 0x80
            """

    if os == 'linux':
        return """
            """ + pwn.shellcode.mov('ebx', returncode, raw = True) + """
            push SYS_exit
            pop eax
            int 0x80"""
    elif os == 'freebsd':
        if str(returncode) == "0":
            return """
                push SYS_exit
                pop eax
                cdq
                push edx
                push edx
                int 0x80"""
        else:
            return """
                push %s
                push SYS_exit
                pop eax
                push eax
                int 0x80""" % str(returncode)
    else:
        bug('OS was neither linux nor freebsd')
