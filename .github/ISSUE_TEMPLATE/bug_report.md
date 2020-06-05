---
name: Bug report
about: Create a report to help us improve
title: ''
labels: backport-required, bug
assignees: ''

---

Thanks for contributing to Pwntools!

## Update Pwntools First

When reporting an issue, be sure that you are running the latest released version of pwntools (`pip install --upgrade pwntools`).

## Debug Output

Having the extra debug output really helps us, and might help you diagnose the problem yourself.

When submitting an issue that has output from Pwntools, make sure to run your script as shown below, to enable the extra debugging data.

```sh
$ python exploit.py DEBUG LOG_FILE=log.txt
```

You should see `[DEBUG]` statements that show what's happening behind the scenes:

```
[+] Starting local process '/bin/sh' argv=['sh'] : pid 16823
[DEBUG] Sent 0x7 bytes:
    'whoami\n'
[DEBUG] Sent 0x5 bytes:
    'exit\n'
[+] Receiving all data: Done (11B)
[DEBUG] Received 0xb bytes:
    'crashheap\n'
[*] Process '/bin/sh' stopped with exit code 0 (pid 16823)
```

## Verify on Ubuntu

If possible, please verify that your issue occurs on 64-bit Ubuntu 18.04.  We provide a Dockerfile based on Ubuntu 18.04 via `docker.io` to make this super simple, no VM required!

```sh
# Download the Docker image
$ docker pull pwntools/pwntools:stable

# Boot the image
$ docker run -it pwntools/pwntools:stable

pwntools@7dc3ef409476:~$ python
>>> from pwn import *
>>> # Test your code here
```
