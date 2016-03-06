"""
Example showing how to use the ssh class.
"""

from pwn import *

shell = ssh(host='bandit.labs.overthewire.org',user='bandit0',password='bandit0')

# Show basic command syntax
log.info("username: %s" % shell.whoami())
log.info("pwd: %s" % shell.pwd())

# Show full tube syntax
tube = shell.run('cat')
tube.send("Hello, cat")
tube.shutdown("out")
print tube.recvall()

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

print shell['./example']

# Show the different styles of calling
print shell.echo("single string")
print shell.echo(["list","of","strings"])
print shell["echo single statement"]

# Show off the interactive shell
shell.interactive()
