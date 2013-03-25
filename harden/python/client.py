#!/usr/bin/env python
from socket import AF_INET, SOCK_STREAM, socket, timeout
from Queue import Queue
from threading import Thread
import time, sys, readline, random, os, termios, fcntl, struct, re

class ConnClosed(Exception):
    pass

class Protocol(Exception):
    pass

class Client(Thread):
    def __init__(self, host, port):
        Thread.__init__(self)
        self.daemon = True
        self.host = host
        self.port = port
        self.onMsg   = None
        self.onTopic = None
        self.onDebug = None
        self.userlist = []
        self.proto = Queue()

    def stop(self):
        self.running = False
        self.join()

    def run(self):
        self.running = True
        while self.running:
            try:
                s = self.recvline()
            except timeout:
                continue
            except:
                raise
                self.running = False
                break
            try:
                if   s.startswith('MSG') and self.onMsg:
                    _typ, _tok, nick, t1, t2, msg = s.split(' ', 5)
                    ts = time.strptime(t1 + ' ' + t2, '%Y-%m-%d %H:%M:%S')
                    self.onMsg(nick, ts, msg)
                elif s.startswith('TOPIC') and self.onTopic:
                    try:
                        self.onTopic(s.split(' ', 2)[2])
                    except IndexError:
                        raise
                        self.onTopic('')
                elif s.startswith('>>>') and self.onDebug:
                    self.onDebug(s.split(' ', 1)[1])
                elif s.startswith('USER'):
                    _typ, _tok, user = s.split(' ', 3)
                    self.userlist.append(user)
                else:
                    self.proto.put(s)
            except:
                raise
                # silently drop malformed lines
                pass
        self.sock.close()

    def recvuntil(self, stop):
        s = ''
        while True:
            c = self.sock.recv(1)
            if c == 0:
                raise ConnClosed('Connection closed by server')
            if c == stop:
                break
            s += c
        return s

    def recvline(self):
        return self.recvuntil('\n')

    def recvthis(self, expected):
        s = self.proto.get()
        if not s.startswith(expected):
            raise Protocol('Expected "%s" but got "%s"' % (expected, s))
        return s

    def sendline(self, line):
        line = line + '\n'
        n = 0
        while n < len(line):
            n += self.sock.send(line[n:])

    def do_connect(self):
        self.sock = socket(AF_INET, SOCK_STREAM, 0)
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(0.1)
        self.start()
        self.sendline('HELO SERVER')
        self.recvthis('HELO CLIENT')

    def do_nick(self, nick):
        self.sendline('NICK %s' % nick)
        try:
            s = self.recvthis('NICK OK')
            self.nick = s[s.find('(') + 1: -1]
        except Protocol:
            raise
            if self.onDebug:
                self.onDebug('BAD NICK!')
        return self.nick

    def do_join(self):
        self.sendline('JOIN')
        s = self.recvthis('TOKEN')
        self.token = s[6:]

    def do_quit(self):
        self.sendline('QUIT SURE')
        self.recvthis('GOODBEY')
        self.sock.close()

    def do_topic(self, topic):
        self.sendline('TOPIC %s %s' % (self.token, topic))

    def do_msg(self, msg):
        self.sendline('MSG %s %s' % (self.token, msg))

    def do_list(self):
        self.sendline('LIST %s' % self.token)
        self.recvthis('LIST END')
        users = self.userlist
        self.userlist = []
        return users

def write(s):
    sys.stdout.write(s)

def save():
    write('\x1b[s')

def restore():
    write('\x1b[u')

def goto(x, y):
    write('\x1b[%d;%dH' % (y, x))

def flush():
    sys.stdout.flush()

def clearline():
    write('\x1b[1G\x1b[K')

def clearforward():
    write('\x1b[J')

def clearscreen():
    write('\x1b[2J')

def red(s):
    return '\x1b[31m%s\x1b[0m' % s

def yellow(s):
    return '\x1b[33m%s\x1b[0m' % s

def bluebg(s):
    return '\x1b[44m%s\x1b[0m' % s

def greenbg(s):
    return '\x1b[42m%s\x1b[0m' % s

def bell():
    write('\a')

def get_term_size():
    fd = os.open(os.ctermid(), os.O_RDONLY)
    height, width = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
    os.close(fd)
    return width, height

class GUI(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.daemon = True
        self.width, self.height = get_term_size()
        self.topic = ''
        self.status = ''
        self.users = []
        self.nick = ''
        self.prompt = red('>') + ' '
        readline.parse_and_bind('tab: complete')
        readline.set_completer(self.completer)

        clearscreen()
        self.retopic()
        self.restatus()
        flush()

        goto(17, self.height / 2 - 1)
        write('*** Imagenary Cyber Relations ***')
        goto(15, self.height / 2)
        #host = raw_input('Host: ')
        host = 'pwnies.dk'
        self.client = Client(host, 4242)
        self.client.onMsg = self.on_msg
        self.client.onTopic = self.on_topic
        self.client.onDebug = self.msg
        import amnesia
        try:
            self.client.do_connect()
        except:
            raise
            goto(15, self.height / 2 + 1)
            write(red('Could not connect to %s!' % host))
            flush()
            time.sleep(2)
            clearscreen()
            goto(1, 1)
            return

        goto(15, self.height / 2 + 1)
        #nick = raw_input('Nick: ')
        nick = 'idolftest'
        self.nick = self.client.do_nick(nick)
        clearscreen()
        self.retopic()
        self.restatus()
        self.client.do_join()
        self.help()
        self.start()
        try:
            while True:
                goto(1, self.height - 1)
                clearline()
                msg = raw_input(self.nick + self.prompt)
                self.retopic()
                self.restatus()
                if msg == '':
                    continue
                elif msg == '/help':
                    self.help()
                elif msg == '/quit':
                    self.client.do_quit()
                    raise KeyboardInterrupt
                elif msg == '/list':
                    users = self.client.do_list()
                    self.msg('Active users:')
                    for u in users:
                        self.msg(' ' + u)
                elif msg.startswith('/topic'):
                    topic = msg.split(' ', 1)[1]
                    self.client.do_topic(topic)
                elif msg.startswith('/nick'):
                    nick = msg.split(' ', 1)[1]
                    self.nick = self.client.do_nick(nick)
                else:
                    self.client.do_msg(msg)
        except KeyboardInterrupt:
            raise
            self.client.stop()
            self.stop()
            clearscreen()
            goto(1, 1)

    def stop(self):
        self.running = False
        self.join()

    def run(self):
        self.running = True
        n = 0
        ansi_escape = re.compile(r'\x1b[^m]*m')
        while self.running:
            time.sleep(0.1)
            w, h = get_term_size()
            if w <> self.width or h <> self.height:
                self.width = w
                self.height = h
                save()
                self.restatus()
                self.retopic()
                self.reprompt()
                restore()
                flush()
            if n % 100 == 0: #roughly every 10s
                users = self.client.do_list()
                if self.nick in users:
                    users.remove(self.nick)
                self.users = set(ansi_escape.sub('', u) for u in users)
            if n % 10: # roughly every second
                status = time.strftime(' (%H:%M) ')
                if self.users == []:
                    users = 'Forever alone :\'('
                else:
                    users = 'Active users: ' + ', '.join(self.users)
                    if len(users) + len(status) > self.width:
                        users = '%d active users online' % len(self.users)
                status += users
                if status <> self.status:
                    self.status = status
                    save()
                    self.restatus()
                    restore()
                    flush()
            n += 1

    def help(self):
        self.msg('Commands:')
        self.msg(' /quit   disconnect from server')
        self.msg(' /list   list connected users')
        self.msg(' /topic <topic>')
        self.msg('         set topic')
        self.msg(' /nick <nick>')
        self.msg('         set username')
        self.msg(' /help   prints this help message')

    def completer(self, text, state):
        if state > 0:
            return None
        options = [u for u in self.users if u.startswith(text)]
        if options:
            if len(options) == 1 and text == readline.get_line_buffer():
                return options[0] + ': '
            else:
                return os.path.commonprefix(options)
        else:
            return None

    def msg(self, s):
        self.on_msg('>>', time.localtime(), yellow(s))

    def on_msg(self, nick, ts, msg):
        save()
        bell()
        goto(1, self.height - 1)
        clearforward()
        write('%s %s> %s\n\n' % (time.strftime('%H:%M', ts), nick, msg))
        self.retopic()
        self.restatus()
        self.reprompt()
        restore()
        flush()

    def on_topic(self, topic):
        self.topic = topic
        save()
        self.retopic()
        restore()
        flush()
        self.msg('Topic changed to %s' % self.topic)

    def retopic(self):
        goto(1, 1)
        write('\x1b[K')
        write(bluebg(self.topic[:self.width].ljust(self.width)))

    def reprompt(self):
        goto(1, self.height - 1)
        write(self.nick + self.prompt)
        write(readline.get_line_buffer())

    def restatus(self):
        goto(1, self.height)
        write(greenbg(self.status.ljust(self.width)))

if __name__ == '__main__':
    GUI()
