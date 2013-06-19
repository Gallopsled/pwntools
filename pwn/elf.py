import pwn

# readelf/objdump binaries
_READELF = '/usr/bin/readelf'
_OBJDUMP = '/usr/bin/objdump'
def check(f):
    import os
    if not (os.access(f, os.X_OK) and os.path.isfile(f)):
        pwn.die('Executable %s needed for readelf.py, please install binutils' % f)
check(_READELF)
check(_OBJDUMP)

def symbols(file):
    import re, subprocess
    symbols = {}
    # -s : symbol table
    cmd = [_READELF, '-s', file]
    out = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    field = '\s+(\S+)'
    lines = re.findall('^\s+\d+:' + field * 7 + '$', out, re.MULTILINE)

    for addr, size, type, _bind, _vis, _ndx, name in lines:
        addr = int(addr, 16)
        size = int(size, 10)
        if addr <> 0 and name <> '':
            symbols[name] = {'addr': addr,
                             'size': size,
                             'type': type,
                             }
    return symbols

class ELF:
    '''A parsed ELF file'''

    __cache = {}
    def __init__(self, path):
        import os, re
        path = os.path.realpath(path)
        if path in ELF.__cache:
            pwn.log.warning('Loaded "%s" again; use "elf.load(...)" to avoid this' \
                            % os.path.basename(path))
        pwn.log.waitfor('Loading ELF file `%s\'' % os.path.basename(path))
        self.segments = []
        self.sections = {}
        self.symbols = {}
        self.plt = {}
        self.got = {}
        self.libs = {}
        self.elfclass = None
        self._data = None
        self.execstack = False

        if not (os.access(path, os.R_OK) and os.path.isfile(path)):
            pwn.die('File %s is not readable or does not exist' % path)

        self._path = path

        self._load_elfclass()
        self._load_segments()
        self._load_sections()
        self._load_symbols()
        self._load_libs()
        # this is a nasty hack until we get our pure python elf parser
        # we'll just have to live without PLT and GOT info for PICs until then
        if not re.match('\.so(\.\d+)?$', path):
            try:
                self._load_plt_got()
            except:
                pass
        if self.execstack:
            pwn.log.status('\nStack is executable!')
        pwn.log.succeeded()
        ELF.__cache[path] = self

    def _load_elfclass(self):
        # -h : ELF header
        import re, subprocess
        cmd = [_READELF, '-h', self._path]
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
        self.elfclass = re.findall('Class:\s*(.*$)', out, re.MULTILINE)[0]

    def _load_segments(self):
        # -W : Wide output
        # -l : Program headers
        import re, subprocess
        cmd = [_READELF, '-W', '-l', self._path]
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
        hexint = '(0x[0-9a-f]+)'
        numfield = '\s+' + hexint
        flgfield = '\s+([RWE ]{3})'
        lines = re.findall('^\s+([A-Z_]+)' + numfield * 5 + flgfield + numfield,
                           out, re.MULTILINE)

        for type, off, vaddr, paddr, filesiz, memsiz, flg, align in lines:
            off = int(off, 16)
            vaddr = int(vaddr, 16)
            paddr = int(paddr, 16)
            filesiz = int(filesiz, 16)
            memsiz = int(memsiz, 16)
            flg = flg.replace(' ', '')
            align = int(align, 16)
            self.segments.append({'type'    : type,
                                  'offset'  : off,
                                  'virtaddr': vaddr,
                                  'physaddr': paddr,
                                  'filesiz' : filesiz,
                                  'memsiz'  : memsiz,
                                  'flg'     : flg,
                                  'align'   : align,
                                  })
            if type == 'GNU_STACK' and 'E' in flg:
                self.execstack = True
        self.segments.sort(key = lambda x: x['virtaddr'])

    def _load_sections(self):
        # -W : Wide output
        # -S : Section headers
        import re, subprocess
        cmd = [_READELF, '-W', '-S', self._path]
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
        field = '\s+(\S+)'
        posint = '[123456789]\d*'
        flags = '\s+([WAXMSILGTExOop]*)'
        lines = re.findall('^\s+\[\s*' + posint + '\]' + field * 6 + flags,
                           out, re.MULTILINE)

        for name, _type, addr, off, size, _es, flgs in lines:
            addr = int(addr, 16)
            off = int(off, 16)
            size = int(size, 16)
            self.sections[name] = {'addr'  : addr,
                                   'offset': off,
                                   'size'  : size,
                                   'flags' : flgs,
                                   }

    def _load_symbols(self):
        self.symbols = symbols(self._path)

    def _load_libs(self):
        import subprocess
        dat = ''
        try:
            dat = subprocess.check_output(['ldd', self._path])
        except subprocess.CalledProcessError:
            pass

        self.libs = parse_ldd_output(dat)

    def extra_libs(self, libs):
        for v, k in libs.items():
            self.libs[v] = k

    # this is crazy slow -- include this feature in the all-python ELF parser
    def _load_plt_got(self):
        import re, subprocess
        cmd = [_OBJDUMP, '-d', self._path]
        out = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
        got32 = '[^j]*jmp\s+\*0x(\S+)'
        got64 = '[^#]*#\s+(\S+)'
        lines = re.findall('([a-fA-F0-9]+)\s+<([^@<]+)@plt>:(%s|%s)' % (got32, got64), out)

        for addr, name, _, gotaddr32, gotaddr64 in lines:
            addr = int(addr, 16)
            gotaddr = int(gotaddr32 or gotaddr64, 16)
            self.plt[name] = addr
            self.got[name] = gotaddr

    def _load_data(self):
        if self._data is None:
            with open(self._path, 'r') as f:
                self._data = list(f.read())

    def read_symbol(self, name):
        if name in self.symbols:
            sym = self.symbols[name]
            addr = sym['addr']
            size = sym['size']
            data = self.read(addr, size)
            if data is None:
                pwn.die('Symbol %s does not live in any section' % name)
            else:
                return data
        else:
            pwn.die('No symbol named %s' % name)

    def section(self, name):
        if name in self.sections:
            self._load_data()
            sec = self.sections[name]
            offset = sec['offset']
            size = sec['size']
            return ''.join(self._data[offset:offset + size])
        else:
            pwn.die('No section named %s' % name)

    def _filter_segments(self, flg, negate = False):
        self._load_data()
        for seg in self.segments:
            if (flg in seg['flg']) ^ negate:
                off = seg['offset']
                siz = seg['filesiz']
                addr = seg['virtaddr']
                yield (''.join(self._data[off : off + siz]), addr)

    def executable_segments(self):
        return self._filter_segments('E', False)

    def non_writable_segments(self):
        return self._filter_segments('W', True)

    def read(self, addr, numb):
        self._load_data()
        out = []
        for seg in self.segments:
            if seg['virtaddr'] > addr:
                return
            if seg['virtaddr'] + seg['filesiz'] > addr:
                n = min(numb, seg['virtaddr'] + seg['filesiz'] - addr)
                off = seg['offset'] + addr - seg['virtaddr']
                out += self._data[off:off + n]
                numb -= n
                addr += n
                if numb == 0:
                    break
        return ''.join(out)

    def write(self, addr, repl):
        self._load_data()
        numb = len(repl)
        for seg in self.segments:
            if seg['virtaddr'] > addr:
                return
            if seg['virtaddr'] + seg['filesiz'] > addr:
                n = min(numb, seg['virtaddr'] + seg['filesiz'] - addr)
                off = seg['offset'] + addr - seg['virtaddr']
                self._data[off:off + n] = repl[:n]
                repl = repl[n:]
                numb -= n
                addr += n
                if numb == 0:
                    break

    @pwn.chained
    def search(self, s, non_writable = False):
        self._load_data()
        for seg in self.segments:
            if 'W' in seg['flg'] and non_writable: continue
            off = seg['offset']
            siz = seg['filesiz']
            dat = self._data[off : off + siz]
            yield map(lambda i: i + seg['virtaddr'], pwn.findall(dat, list(s)))

    def replace(self, s, repl, non_writable = False, padding = '\x90'):
        import types
        self._load_data()
        for seg in self.segments:
            if 'W' in seg['flg'] and non_writable: continue
            off = seg['offset']
            siz = seg['filesiz']
            dat = self._data[off : off + siz]
            for idx in pwn.findall(dat, list(s)):
                addr = idx + seg['virtaddr']
                if isinstance(repl, types.FunctionType):
                    rep = repl(addr, s)
                else:
                    rep = repl
                if rep is None: continue
                rep = rep.ljust(len(s), padding)
                if len(rep) > len(s):
                    pwn.die('Replacement is larger than the replaced')
                self._data[off + idx : off + idx + len(s)] = rep

    def save(self, path):
        with open(path, 'w') as fd:
            fd.write(self.get_data())

    def get_data(self):
        self._load_data()
        return ''.join(self._data)

def load (path):
    import os
    path = os.path.realpath(path)
    if path in ELF._ELF__cache:
        return ELF._ELF__cache[path]
    return ELF(path)

def parse_ldd_output(dat):
    import re
    expr = re.compile(r'(?:([^ ]+) => )?([^(]+)?(?: \(0x[0-9a-f]+\))?$')
    res = {}

    for line in dat.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        parsed = expr.search(line)
        if not parsed:
            pwn.log.warning('Could not parse line: "%s"' % line)
        name, resolved = parsed.groups()
        if name == None:
            if re.search('/ld-[^/]*$', resolved):
                name = 'ld'
            elif re.search('^linux', resolved):
                name = 'linux'
            else:
                pwn.log.warning('Could not parse line: "%s"' % line)
                continue

        res[name] = resolved
        if name.startswith('libc.so.'):
            res['libc'] = resolved
    return res
