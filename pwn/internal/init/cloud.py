import pwn, atexit, os
from paramiko import SSHClient, AutoAddPolicy

nodes = {'fantast':
             {'host'  : 'fa.ntast.dk',
              'cores' : 1,
              'mem'   : 128
              },
         'storm':
             {'host'  : 'storm.pwnies.dk',
              'cores' : 40,
              'mem'   : 128 * 1024
              },
         'lightning':
             {'host'  : 'lightning.pwnies.dk',
              'cores' : 24,
              'mem'   : 32 * 1024
              },
         'thunder':
             {'host'  : 'thunder.pwnies.dk',
              'cores' : 16,
              'mem'   : 32 * 1024
              },
         'rain':
             {'host'  : 'rain.pwnies.dk',
              'cores' : 8,
              'mem'   : 2 * 1024
              },
         'stakken':
             {'host'  : 'stakken.pwnies.dk',
              'cores' : 4,
              'mem'   : 12 * 1024
              },
         'apollo':
             {'host'  : 'apollo.pwnies.dk',
              'cores' : 1,
              'mem'   : 128
              },
         'artemis':
             {'host'  : 'artemis.pwnies.dk',
              'cores' : 1,
              'mem'   : 128
              }
         }

class _Node(SSHClient):
    def __init__(self):
        SSHClient.__init__(self)

    def set_context(self, bin_path):
        pass

    def exec_command_output(self, cmd):
        i, o, e = self.exec_command(cmd)
        i.close()
        return (o.read(), e.read())

    def upload(self, path):
        pass

class _Cloud(object):
    def __init__(self):
        dict = {n:None for n in nodes.keys()}
        dict['nodes'] = nodes
        object.__setattr__(self, '__dict__', dict)
        object.__setattr__(self, 'nodes', nodes)
        object.__setattr__(self, '__hosts', {})

    def __getattribute__(self, name):
        hosts = object.__getattribute__(self, '__hosts')
        if name in hosts:
            return hosts[name]
        elif name in nodes:
            host = nodes[name]['host']
            user = nodes[name].get('user', 'pwn')
            port = nodes[name].get('port', 22)
            ssh = _Node()
            hosts[name] = ssh
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            pwn.log.waitfor('Connecting to %s' % name)
            try:
                ssh.connect(
                    host,
                    username = user,
                    port = port,
                    key_filename = os.path.join(pwn.installpath, 'dat/ssh/pwn'),
                    look_for_keys = False,
                    compress = True,
                    timeout = 10,
                    allow_agent = False)
            except:
                pwn.log.failed()
                raise
            pwn.log.succeeded()
            atexit.register(lambda: ssh.close())
            return ssh
        else:
            return object.__getattribute__(self, name)

    def __getitem__(self, name):
        return object.__getattribute__(self, '__getattribute__')(name)

pwn.cloud = _Cloud()
