from struct import pack as p 
from struct import unpack as up
from binascii import hexlify as h
from lib import gadgets
from lib import readelf
import time
from subprocess import *
from threading import Thread

#
# TO DO:
# - automatic stack size detection
# - dynamic ROP extraction
#
#


class ROPinHood(object):

    def __init__(self, filename):
        self.ropgadget = gadgets.ROPGadget()
        self.elfreader = readelf.Elf()

        self.filename = filename
        self.payloads = {0 : []} #self.payload}
        self._reprs = {0 : []}
        self.gadgets = {} # {'name': '', 'address': '', 'repr':''}
        self.poprets = {} # custom popret things
        self.__load_gadgets_from_file()
        self.prog = Popen(['./'+filename], stdin=PIPE, stdout=PIPE, stderr=PIPE)

    def send(self, payload):
        self.prog.stdin.write(''.join(payload))

    def recv(self):
        return self.prog.stdout.readline()

    def shell(self, shell='hax>'):
        def loop():
            while True:
                print self.prog.stdout.readline(),
        t = Thread(target = loop)
        t.daemon = True
        t.start()
        while True:
            try:
                time.sleep(0.1)
                self.prog.stdin.write(raw_input('%s ' % shell) + '\n')
            except KeyboardInterrupt:
                break

    def get_payload(self, i):
        return ''.join(self.payloads[i])

    def add_payload(self):
        count = len(self.payloads)
        self.payloads.update({count : []})
        self._reprs.update({count : []})

    def __load_gadgets_from_file(self, trackback=3):
        self.ropgadget.generate(self.filename, trackback)
        self.elfreader.read_headers(self.filename)
        self._segments = self.elfreader._headers

        self.elfreader.read_plt(self.filename)
        self._plt = self.elfreader._plt

        self.elfreader.read_got(self.filename)
        self._got = self.elfreader._got

        self.elfreader.read_libc_offset(self.filename)
        self._libc_offsets = self.elfreader._libc_offset
        return True

    def get_offset(self, elm):
        if not elm in self._libc_offsets.keys():
            print "[*] Warning, element not found in offset table"
            return None
        return self._libc_offsets[elm]

    def get_in_got(self, elm):
        if not elm in self._got.keys():
            print "[*] Warning, element not found in GOT"
            return None
        return self._got[elm]

    def get_in_plt(self, elm):
        if not elm in self._plt.keys():
            print "[*] Warning, element not found in PLT"
            return None
        return self._plt[elm]

    def load_gadget(self, args):
        for key in args:
            try:
                val = p('<I', args[key])
            except:
                val = args[key]
            finally:
                if 'pop' in key:
                    self.poprets.update({key:val})
                else:
                    self.gadgets.update({key:val})

    def insert(self, item, args=False, ret=False):
        if not args:
            return self._insert_singleton(item)
        else:
            return self._insert_link(item, args, ret)

    def _insert_singleton(self, item):
        try:
            itemval = self.gadgets[item]
        except:
            itemval = item
        i = len(self.payloads)-1
        self.payloads[i].append(itemval)
        self._reprs[i].append((item, itemval))
        return True

    def __unpack_args(self, args):
        result = []
        _repr_result = []
        for arg in args:
            if arg in self.gadgets: # manually inserted gets precedence
                result.append((arg, self.gadgets[arg]))
            elif 'got' in arg: # it's a got thing
                elm, got = arg.split('@')
                result.append((arg, p('<I', self._got[elm])))
            elif arg in self._plt: # find it in plt
                result.append((arg, p('<I', self._plt[arg])))
            elif arg in self._segments:
                result.append((arg, p('<I', self._segments[arg])))
        return result


    def _insert_link(self, f, args, ret=False):
        ''' takes arguments of the form: function, [args], function_return_val_or_addr
'''
        num_args = len(args)
        if ret:
            if ret in self.poprets.keys():
                popret = self.poprets[ret]
                name = ret
            else:
                popret = ret
                name = ret
        else:
            # find rop automatically
            poprets = self.ropgadget.asm_search('pop ? '*num_args)
            if len(poprets) == 0:
                print "[**] Could not insert ROP chain link, no gadget with %d pops found in vocabulary" % num_args
                return False
            else:
                name = 'pop'*num_args+'ret'
                fullname, popret_addr = poprets[0]
                popret = p('<I', int(popret_addr))

        i = len(self.payloads)-1
        f = self.__unpack_args([f])[0]
        args = self.__unpack_args(args)
        self.payloads[i].append(f[1])
        self.payloads[i].append(popret)
        [self.payloads[i].append(item[1]) for item in args]

        self._reprs[i].append((f[0], f[1]))
        self._reprs[i].append((name, popret))
        [self._reprs[i].append((item[0], item[1])) for item in args]

        return True

    def clear(self):
        self.payload = []

    def __str__(self):
        def _format(item, key):
            while len(item) < 10:
                if len(item) % 2 == 0:
                    item = "%s " % item
                else:
                    item = " %s" % item
            return "[%s]     <- %s\n" % (item, key)

        accum = ''
        for j in self._reprs.keys():
            _repr = self._reprs[j]
            _repr.reverse()
            i = 0
            for key, item in _repr:
                if (len(item) > 4) and (key in self.gadgets.keys()):
                    accum += _format(hex(up('I', item[:4])[0]), key + '        %s bytes' % len(item))
                    accum += _format('...', key)
                else:
                    if item.isspace():
                        accum += _format('\\n', 'space')
                    else:
                        try:
                            accum += _format(hex(up('I',item)[0]), key)
                        except:
                            accum += _format(item, key)
                i += 1
            _repr.reverse()
            accum += '\n'
        return accum


    def build_portable(self):
        # build the exploit to an almost self-contained executable
        pass
