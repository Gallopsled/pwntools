import pwn, atexit, os, paramiko
from paramiko import SSHClient

resolv = {'fantast' : 'fa.ntast.dk'
          }

class _Node(SSHClient):
    def __init__(self, *args):
        SSHClient.__init__(self, *args)

    def execute(self, cmd):
        i, o, e = self.exec_command(cmd)
        i.close()
        return (o.read(), e.read())

class _Cloud(object):
    def __init__(self):
        object.__setattr__(self, '__dict__', resolv)
        object.__setattr__(self, '__hosts', dict())

    def __getattribute__(self, name):
        hosts = object.__getattribute__(self, '__hosts')
        if name in hosts:
            return hosts[name]
        elif name in resolv:
            host = resolv[name]
            ssh = _Node()
            hosts[name] = ssh
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            pwn.log.waitfor('Connecting to %s' % name)
            ssh.connect(
                host,
                username = 'pwn',
                key_filename = os.path.join(pwn.installpath, 'ssh/pwn'),
                look_for_keys = False,
                compress = True,
                timeout = 2,
                allow_agent = False)
            pwn.log.succeeded()
            atexit.register(lambda: ssh.close())
            return ssh
        else:
            return object.__getattribute__(self, name)

pwn.cloud = _Cloud()
