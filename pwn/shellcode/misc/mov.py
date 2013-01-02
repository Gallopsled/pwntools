from pwn.internal.shellcode_helper import *
import pwn
import string

_reg32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']
_reg8  = ['al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh']
_regs  = _reg32 + _reg8

_smaller8 = {
        'eax': 'al',
        'ebx': 'bl',
        'ecx': 'cl',
        'edx': 'dl',
}

@shellcode_reqs(avoider = True, arch='i386')
def mov(dest, src, known_zero = False, stack_allowed = True, deterministic = False):
    """Does a mov into the dest while avoiding forbidden characters. Current only 8-bit and 32-bit registers are supported.

    The src can be be an immediate or another register.

    If the register is known to be zero then set known_zero to true, to potentially reduce the code size.

    If the stack is not allowed to be used for pushes and pops, set stack_allowed to False.

    Set determistic to False if you want the output to be deterministic.
    """

    if dest not in _regs:
        pwn.die('Unknown destination %s for mov shellcode' % dest)

    src = arg_fixup(src)
    allowed = pwn.get_only()
    l = _mov_only(dest, src, allowed, known_zero)

    if not stack_allowed:
        l = [(a,b) for a,b in l if not 'push ' in b or 'pop ' in b]

    if len(l) == 0:
        if stack_allowed and dest in _reg32 and isinstance(src, int):
            e = _fallback_mov(dest, src, allowed)
            if e != None:
                pwn.log.warning('Constrains are pretty nasty for mov(%s, %s, %s, %s, %s). Using the retarded and long fallback.' % (dest, src, known_zero, stack_allowed, deterministic))

                return e
        pwn.die('Could not generate mov(%s, %s, %s, %s, %s) for with the given constraints.' % (dest, src, known_zero, stack_allowed, deterministic))

    best = len(l[0][0])
    l = [b for a,b in l if len(a) == best]

    if deterministic:
        return sorted(l)[0]
    else:
        return random.choice(l)


def _fallback_mov(dest, src, allowed):
    """Retarded fallback for mov, which pushes the bytes to the stack one at a time."""

    def all_in(bs):
        return all(b in allowed for b in bs)

    if all_in('\x6a'):
        pushi = 'push strict byte 0x'
    elif all_in('\x68'):
        pushi = 'push strict dword 0x686868'
    else:
        return None

    push_oks = {
        'eax': all_in('\x50'), # Can we do "push eax"?
        'ecx': all_in('\x51'), # Can we do "push ecx"?
        'edx': all_in('\x52'), # Can we do "push edx"?
        'ebx': all_in('\x53'), # Can we do "push ebx"?
        'esp': all_in('\x54'), # Can we do "push esp"?
        'ebp': all_in('\x55'), # Can we do "push ebp"?
        'esi': all_in('\x56'), # Can we do "push esi"?
        'edi': all_in('\x57')  # Can we do "push edi"?
    }

    pop_oks = {
        'eax': all_in('\x58'), # Can we do "pop eax"?
        'ecx': all_in('\x59'), # Can we do "pop ecx"?
        'edx': all_in('\x5a'), # Can we do "pop edx"?
        'ebx': all_in('\x5b'), # Can we do "pop ebx"?
        'esp': all_in('\x5c'), # Can we do "pop esp"?
        'ebp': all_in('\x5d'), # Can we do "pop ebp"?
        'esi': all_in('\x5e'), # Can we do "pop esi"?
        'edi': all_in('\x5f')  # Can we do "pop edi"?
    }

    if not pop_oks[dest]:
        return None

    stack_oks = {
        'eax': all_in('\x50\x58'), # Can we do "push eax" and "pop eax"?
        'ecx': all_in('\x51\x59'), # Can we do "push ecx" and "pop ecx"?
        'edx': all_in('\x52\x5a'), # Can we do "push edx" and "pop edx"?
        'ebx': all_in('\x53\x5b'), # Can we do "push ebx" and "pop ebx"?
        'esp': all_in('\x54\x5c'), # Can we do "push esp" and "pop esp"?
        'ebp': all_in('\x55\x5d'), # Can we do "push ebp" and "pop ebp"?
        'esi': all_in('\x56\x5e'), # Can we do "push esi" and "pop esi"?
        'edi': all_in('\x57\x5f')  # Can we do "push edi" and "pop edi"?
    }

    inc_oks = {
        'eax': all_in('\x40'), # Can we do "inc eax"?
        'ecx': all_in('\x41'), # Can we do "inc ecx"?
        'edx': all_in('\x42'), # Can we do "inc edx"?
        'ebx': all_in('\x43'), # Can we do "inc ebx"?
        'esp': all_in('\x44'), # Can we do "inc esp"?
        'ebp': all_in('\x45'), # Can we do "inc ebp"?
        'esi': all_in('\x46'), # Can we do "inc esi"?
        'edi': all_in('\x47')  # Can we do "inc edi"?
    }

    dec_oks = {
        'eax': all_in('\x58'), # Can we do "dec eax"?
        'ecx': all_in('\x59'), # Can we do "dec ecx"?
        'edx': all_in('\x5a'), # Can we do "dec edx"?
        'ebx': all_in('\x5b'), # Can we do "dec ebx"?
        'esp': all_in('\x5c'), # Can we do "dec esp"?
        'ebp': all_in('\x5d'), # Can we do "dec ebp"?
        'esi': all_in('\x5e'), # Can we do "dec esi"?
        'edi': all_in('\x5f')  # Can we do "dec edi"?
    }

    stack_set = {r for r,v in stack_oks.items() if v and r != 'esp'}
    inc_set   = {r for r   in stack_set if inc_oks[r]}
    dec_set   = {r for r   in stack_set if dec_oks[r]}
    any_set   = {r for r   in stack_set if inc_oks[r] or dec_oks[r]}

    if not any_set:
        return None

    incesp = None

    if inc_oks['esp']:
        incesp = "inc esp"

    if incesp == None:
        return None

    decesp = None

    if dec_oks['esp']:
        decesp = "dec esp"

    if decesp == None:
        return None

    good = []

    for c in ordlist(pwn.p32(src)):
        best = 1024
        best_try = None

        for b in ordlist(allowed):
            if inc_set:
                cur = (256 + c - b) % 256
                if cur < best:
                    best = cur
                    best_try = ('inc', b, cur)
            if dec_set:
                cur = (256 + b - c) % 256
                if cur < best:
                    best = cur
                    best_try = ('dec', b, cur)
        good.append(best_try)

    dec_used = any(d == 'dec' for d,_,_ in good)
    inc_used = any(d == 'inc' for d,_,_ in good)

    inc_reg = None
    dec_reg = None
    saves = set()

    if dest in dec_set:
        dec_reg = dest
    else:
        for r in dec_set:
            dec_reg = r
            saves.add(r)
            break

    if dest in inc_set:
        inc_reg = dest
    else:
        for r in inc_set:
            inc_reg = r
            saves.add(r)
            break

    if dec_reg != dest and inc_reg != dest:
        for r in inc_set.intersection(dec_set):
            inc_reg = dec_reg = r
            saves = {r}

    code = []
    junk_reg = inc_reg if inc_reg != None else dec_reg

    for r in sorted(saves):
        code += ['push ' + r]

    code += ['push ' + junk_reg]
    regs = {'inc': inc_reg, 'dec': dec_reg}

    for n in range(4):
        d, b, count = good[n]
        r = regs[d]
        if n != 0:
            code += ['pop ' + r]
        code += [pushi + "%02x" % b, 'pop ' + r] + [d + ' ' + r] * count + ['push ' + r]
        if n != 3:
            code += [incesp]

    code += [decesp]*3 + ['pop ' + dest] + [incesp]*4

    for r in sorted(saves, reverse = True):
        code += ['pop ' + r]
    return '\n'.join(code)

@pwn.memoize
def _mov_only(dest, src, only, known_zero = False):
    return [(a,b) for a,b in _mov_asm(dest, src, known_zero) if all(byte in only for byte in a)]

@pwn.memoize
def _mov_asm(dest, src, known_zero = False):
    NUM_THREADS = 4
    res = [None] * NUM_THREADS
    instrs_list = _mov(dest, src, known_zero = known_zero)

    def assembler(n):
        out = []
        for instrs in instrs_list[n::NUM_THREADS]:
            cur = []

            for inst in instrs:
                s = pwn.nasm.nasm_raw('bits 32\n_start:\n' + inst, return_none = True, optimize='x')
                if s == None:
                    cur = None
                    pwn.log.warning('Could not assemble: ' + inst)
                    break
                cur.append(s)

            if cur != None:
                out.append((''.join(cur), '\n'.join(instrs)))
        res[n] = out

    threads = [None] * NUM_THREADS

    for n in range(NUM_THREADS):
        threads[n] = pwn.Thread(target = assembler, args = (n,))
        threads[n].daemon = True
        threads[n].start()

    for n in range(NUM_THREADS):
        threads[n].join()

    return sorted(concat(res), key=lambda (a,b): len(a))

def _size(reg):
    if reg in _reg32:
        return 32
    if reg in _reg8:
        return 8

def _mov(dest, src, known_zero = False):
    src = arg_fixup(src)

    return _mov_helper(dest, src, known_zero)

@pwn.memoize(use_file = False)
def _mov_helper(dest, src, known_zero = False, forced_zero = False, recurse = 2):
    if dest == src:
        return [['']]

    if src == 0 and known_zero:
        return [['']]

    if isinstance(src, int):
        srcu = src & ((1 << _size(dest)) - 1)
        src  = srcu - 2 * (srcu & (1 << (_size(dest)-1)))
    else:
        srcu = src

    out = []

    def add(*l):
        for instrs in pwn.combinations(l):
            cur = []
            for inst in instrs:
                if isinstance(inst, str):
                    inst = [inst]

                if isinstance(inst, list) or isinstance(inst, tuple):
                    src2  = src  if not isinstance(src , int) else hex(src)
                    srcu2 = srcu if not isinstance(srcu, int) else hex(srcu)
                    cur += [s.replace('DEST', dest).replace('SRCU', srcu2).replace('SRC', src2) for s in inst]
                else:
                    bug('Appended instruction was neither list nor string')
            if cur != None:
                out.append(cur)

    def rec(d = dest, s = src, k = known_zero, f = forced_zero, r = recurse - 1):
        if recurse > 0:
            return _mov_helper(d,s,k,f,r)
        else:
            return []

    if src == 0:
        add([
                'xor DEST, DEST',
                'sub DEST, DEST',
                '.mov0: add DEST, DEST\njnz .mov0',
                '.mov0: shl DEST, 1\njnz .mov0',    # There is a shorter version for shl reg32, 1
                '.mov0: shl DEST, 0xc1\njnz .mov0', # 0xc1 is contained in most shl instructions
        ])

        if dest in _reg8:
            add([
                '.mov0: dec DEST\njnz .mov0',
                '.mov0: inc DEST\njnz .mov0',
                '.mov0: add DEST, 0x61\njnz .mov0',
            ])
        elif dest in _reg32:
            add([
                '.mov0: imul DEST, 0x62\njnz .mov0',
                ['add DEST, DEST'] * 32,
            ])

    elif not known_zero:
        add(rec(s = 0), rec(f = True, k = True))

    if known_zero:
        if 0 <= srcu <= 255:
            if dest in _smaller8:
                add(rec(d = _smaller8[dest]))

            add([['inc DEST'] * srcu])

            if dest in _reg8:
                add([['dec DEST'] * (256 - src)])
        add([
            'add DEST, SRC',
            'or  DEST, SRC',
            'xor DEST, SRC',
            ['sub DEST, SRC', 'neg DEST']
        ])

    if not forced_zero:
        if -128 <= src <= 127:
            if dest in _smaller8:
                add(rec(d = _smaller8[dest]), ['movsx DEST, ' + _smaller8[dest]])

            if dest in _reg32:
                add([['push SRC', 'pop DEST']])

                pair = xor_pair(p8(src), only = string.ascii_letters + string.digits)
                if pair != None:
                    n1, n2 = map(pwn.u8, pair)
                    add([['push ' + hex(n1), 'pop DEST', 'xor DEST, ' + hex(n2)]])
        if 0 <= srcu <= 255:
            if dest in _smaller8:
                add(rec(d = _smaller8[dest]), ['movzx DEST, ' + _smaller8[dest]])

            if dest in _reg32:
                add([['push strict byte 0x6a', 'pop DEST'] + ['inc DEST'] * (src - 0x6a) + ['dec DEST'] * (0x6a - src)])

                # push 0x6a == 'jj'
                add([['push 0x6a', 'pop DEST']], [
                    'xor DEST, SRCU ^ 0x6a',
                    'add DEST, SRCU - 0x6a',
                    'sub DEST, 0x6a - SRCU'
                ])

        if isinstance(src, int):
            if dest in _reg32:
                add(rec(s = src-1), [['inc DEST']])
                add(rec(s = src+1), [['dec DEST']])

                # push 0x68686868 == 'hhhhh'
                add([['push 0x68686868', 'pop DEST']], [
                    'xor DEST, SRCU ^ 0x68686868',
                    'add DEST, SRCU - 0x68686868',
                    'sub DEST, 0x68686868 - SRCU'
                ])

                pair = xor_pair(p32(src), only = string.ascii_letters + string.digits)
                if pair != None:
                    n1, n2 = map(pwn.u32, pair)
                    add([['push ' + hex(n1), 'pop DEST', 'xor DEST, ' + hex(n2)]])

                if dest != 'eax':
                    add([['push eax']], rec(d = 'eax'), [
                        ['push eax', 'pop DEST', 'pop eax'],
                        ['mov DEST, eax', 'pop eax']
                    ])
            add(rec(s = ~src), [
                'not DEST',
                ['neg DEST', 'dec DEST'],
            ])
            add(rec(s = -src), [
                'neg DEST',
                ['not DEST', 'inc DEST'],
            ])


    add([['mov DEST, SRC']])

    return out
