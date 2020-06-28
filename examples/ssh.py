"""
Example showing how to use the ssh class.
"""

from pwn import *

shell = ssh(host='bandit.labs.overthewire.org',user='bandit0',password='bandit0', port=2220)

# Show basic command syntax
log.info("username: %s" % shell.whoami())
log.info("pwd: %s" % shell.pwd())

# Show full tube syntax
tube = shell.run('cat')
tube.send("Hello, cat")
tube.shutdown("out")
print(tube.recvall())

# Show automatic working directories
shell.set_working_directory()
log.info("pwd: %s" % shell.pwd())

shell.upload_data("""
#include <stdio.h>
int main() {
    return printf("Hello, world");
}
""", 'example.c')

shell.gcc(['example.c','-o','example'])

print(shell['./example'])

# Show the different styles of calling
print(shell.echo("single string"))
print(shell.echo(["list","of","strings"]))
print(shell["echo single statement"])

# ssh.process() is the most flexible way to run a command)
io = shell.process(['/bin/bash', '-c', 'echo Hello $FOO'], 
                   env={'FOO': 'World'}, # Set environment
                   stderr='/dev/null',   # Override file descriptors
                   aslr=False,           # Disable ASLR on processes
                   setuid=False,         # Disable setuid bit so processes can be debugged
                   shell=False)          # Enable or disable shell evaluation
print(io.recvall())

# Show off the interactive shell
shell.interactive()
