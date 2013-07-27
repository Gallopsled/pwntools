import pwn

def asm(*blocks, **kwargs):
    """assembles a piece of code.
    Example:
        from pwn import *
        context("i386", "linux")
        sc = shellcode.dupsh()
        print enhex(asm(sc))"""
    import pwn.internal.shellcode_helper as H
    blocks = H.AssemblerContainer(*blocks, os=kwargs.get('os'), arch=kwargs.get('arch'), cast = 'text')
    emit_asm = kwargs.get('emit_asm', False)
    keep_tmp = kwargs.get('keep_tmp', False)

    if all(isinstance(b, H.AssemblerBlob) for b in blocks.blocks):
        data = pwn.flat(b.blob for b in blocks.blocks)
        if emit_asm:
            return 'The following blob was computed:\n' + data.encode('hex')
        else:
            return data

    code_blocks = []
    for n, b in enumerate(blocks.blocks):
        code_blocks.append('pwn_block%d:' % n)
        if isinstance(b, H.AssemblerText):
            code_blocks.append('\n'.join('    '*(not line.strip().endswith(':')) + line.strip() for line in b.text.strip().split('\n')))
        elif isinstance(b, H.AssemblerBlob):
            if target_arch in ['i386', 'amd64']:
                code_blocks.append('db ' + ', '.join('0x%02x' % ord(c) for c in b.blob))
            else:
                code_blocks.append('.byte ' + ', '.join('0x%02x' % ord(c) for c in b.blob))
        else:
            raise Exception("Trying to assemble something that is not an assembler block")

    system = pwn.with_context(os = blocks.os, arch = blocks.arch)
    return _asm(system['arch'], system['os'], code_blocks, emit_asm, keep_tmp)

@pwn.need_context
def disasm(data, arch = None, keep_tmp = False):
    """disassembles a block of code
    Example:
        from pwn import *
        context("i386", "linux")
        print disasm(unhex("31c9f7e950682f2f7368682f62696eb00b89e3cd80"))"""
    return _disasm(data, arch, keep_tmp)

def _run(cmd):
    import subprocess, errno
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        exitcode = p.wait()
    except OSError, e:
        if e.errno == errno.ENOENT:
            pwn.die('%s is not installed' % cmd[0])
        else:
            raise
    if exitcode != 0 or stdout != '' or stderr != '':
        err = 'There was a problem running %s.\n' % ' '.join(cmd)
        if exitcode != 0:
            err += 'It had the exitcode %d.\n' % exitcode
        if stdout != '':
            err += 'It had this on stdout:\n%s\n' % stdout
        if stderr != '':
            err += 'It had this on stdout:\n%s\n' % stderr
        raise Exception(err)

@pwn.memoize
def _asm(target_arch, target_os, code_blocks, emit_asm = 0, keep_tmp = False):
    import pwn.internal.shellcode_helper as H
    import os.path, tempfile, subprocess, string, shutil

    if target_arch == None:
        raise Exception('You need to set the architecture with context')

    tmpdir = tempfile.mkdtemp(prefix = 'pwn-asm-')
    def path(s):
        return os.path.join(tmpdir, s)
    try:
        magic = pwn.randoms(32, only = string.ascii_lowercase)

        code = []

        cpp = ['cpp', '-nostdinc', '-undef', '-w']
        if pwn.DEBUG:
            cpp += ['-D', 'DEBUG']

        if target_os != None:
            include = os.path.join(pwn.installpath, 'pwn', 'include', target_os)
            cpp += ['-I', include]

        if target_os == 'linux':
            if os.path.isfile(os.path.join(include, target_arch + '.h')):
                cpp += ['-I', os.path.join(include, 'diet')]
                code += ['#include <%s.h>' % target_arch]
        elif target_os == 'freebsd':
            code += ['#include <common.h>']

        code += [magic]
        if target_arch not in ['i386', 'amd64']:
            code += ['.section .shellcode,"ax"']

        if target_arch == 'arm':
            code += ['.arm']
        elif target_arch == 'thumb':
            code += ['.thumb']
            target_arch = 'arm'
        elif target_arch == 'i386':
            code += ['bits 32']
        elif target_arch == 'amd64':
            code += ['bits 64']

        code += code_blocks
        code = '\n'.join(code)

        if target_arch in ['i386', 'amd64']:
            assembler = ['nasm', '-Ox']
            objcopy = ['objcopy']
        else:
            assembler = [os.path.join(pwn.installpath, 'binutils', target_arch + '-as')]
            if not os.path.isfile(assembler[0]):
                raise Exception('Could not find the gnu assembler for this architecture: %s' % target_arch)
            objcopy = [os.path.join(pwn.installpath, 'binutils', 'promisc-objcopy')]
        objcopy += ['-j.shellcode', '-Obinary']

        if emit_asm == 2:
            output = []

            output += [
                "/*",
                "   Assemble with:",
                "   %s [input] -o [input].tmp1"                       % ' '.join(cpp),
                "   sed -e '0,/^%s$/d' [input].tmp1 > [input].tmp2"   % magic,
                "   %s [input].tmp2 -o [input].tmp3"                  % ' '.join(assembler)
                ]
            if target_arch not in ['i386', 'amd64']:
                output += ["   %s [input].tmp3 [output]"              % ' '.join(objcopy)]
            output += ["*/", "", code]
            return '\n'.join(output)

        pwn.write(path('step1'), code)
        _run(cpp + [path('step1'), path('step2')])
        code = pwn.read(path('step2'))

        _code = code.split('\n' + magic + '\n')

        if len(_code) != 2:
            raise Exception("The output from cpp was weird:\n%s" % code)

        code = _code[1]

        if emit_asm == 1:
            output = []

            if target_arch in ['i386', 'amd64']:
                output += [
                    ';; Assemble with:',
                    ';;   %s <input> -o <output>'    % ' '.join(assembler)
                    ]
            else:
                output += [
                    "/*",
                    "   Assemble with:",
                    '   %s <input> -o <input>.tmp'   % ' '.join(assembler),
                    '   %s [input].tmp [output]'     % ' '.join(objcopy),
                    '*/',
                    ]
            output += ["", code]
            return '\n'.join(output)

        pwn.write(path('step3'), code)
        _run(assembler + ['-o', path('step4'), path('step3')])

        if target_arch in ['i386', 'amd64']:
            return pwn.read(path('step4'))

        # Sanity check for seeing if the output has relocations
        relocs = subprocess.check_output(['readelf', '-r', path('step4')]).strip()
        if len(relocs.split('\n')) > 1:
            raise Exception('There were relocations in the shellcode:\n\n%s' % relocs)

        _run(objcopy + [path('step4'), path('step5')])

        return pwn.read(path('step5'))
    finally:
        if not keep_tmp:
            try:
                shutil.rmtree(tmpdir)
            except:
                pass

@pwn.memoize
def _disasm(data, target_arch, keep_tmp = False):
    import os.path, tempfile, subprocess, shutil

    if target_arch == None:
        raise Exception('You need to set the architecture with context')

    tmpdir = tempfile.mkdtemp(prefix = 'pwn-disasm-')
    def path(s):
        return os.path.join(tmpdir, s)
    try:
        bfdarch = target_arch
        extra = ['-w', '-N', '*']

        if target_arch == 'i386':
            bfdname = 'elf32-i386'
        elif target_arch == 'amd64':
            bfdname = 'elf64-x86-64'
            bfdarch = 'i386:x86-64'
        elif target_arch == 'arm':
            bfdname = 'elf32-littlearm'
        elif target_arch == 'thumb':
            bfdname = 'elf32-littlearm'
            bfdarch = 'arm'
            extra = ['--prefix-symbol=$t.']
        elif target_arch == 'mips':
            bfdname = 'elf32-bigmips'
        elif target_arch == 'alpha':
            bfdname = 'elf64-alpha'
        elif target_arch == 'cris':
            bfdname = 'elf32-cris'
        elif target_arch == 'ia64':
            bfdname = 'elf64-ia64-little'
            bfdarch = 'ia64-elf64'
        elif target_arch == 'm68k':
            bfdname = 'elf32-m68k'
        elif target_arch == 'powerpc':
            bfdname = 'elf32-powerpc'
        elif target_arch == 'vax':
            bfdname = 'elf32-vax'

        if target_arch in ['i386', 'amd64']:
            objcopy = ['objcopy']
            objdump = ['objdump', '-Mintel']
        else:
            objcopy = [os.path.join(pwn.installpath, 'binutils', 'promisc-objcopy')]
            objdump = [os.path.join(pwn.installpath, 'binutils', 'promisc-objdump')]

        objcopy += ['-I', 'binary',
                    '-O', bfdname,
                    '-B', bfdarch,
                    '--set-section-flags', '.data=code',
                    '--rename-section', '.data=.text',
                    ]

        objdump += ['-d']

        pwn.write(path('step1'), data)
        _run(objcopy + extra + [path('step1'), path('step2')])

        output0 = subprocess.check_output(objdump + [path('step2')])
        output1 = output0.split('<.text>:\n')
        if len(output1) != 2:
            raise Exception('Something went wrong with objdump:\n\n%s' % output0)
        else:
            return output1[1].strip('\n')
    finally:
        if not keep_tmp:
            try:
                shutil.rmtree(tmpdir)
            except:
                pass
