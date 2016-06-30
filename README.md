# binjitsu - CTF toolkit
[![Docs latest](https://readthedocs.org/projects/binjitsu/badge/?version=latest)](https://binjitsu.readthedocs.org/)
[![Travis](https://travis-ci.org/Gallopsled/pwntools.svg?branch=master)](https://travis-ci.org/binjitsu/binjitsu)
[![Twitter](https://img.shields.io/badge/twitter-ctfbinjitsu-4099FF.svg?style=flat)](https://twitter.com/ctfbinjitsu)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://choosealicense.com/licenses/mit/)

binjitsu is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.

```python
from pwn import *
context(arch = 'i386', os = 'linux')

r = remote('exploitme.example.com', 31337)
# EXPLOIT CODE GOES HERE
r.send(asm(shellcraft.sh()))
r.interactive()
```

# Try It Now!

You can now do a live demo of Binjitsu, [right in your browser](http://demo.binjit.su).  Alternately, you can SSH to the same host, and log in as user `zerocool` with [this private key][key] (password `i_promise_not_to_be_evil`).

It will drop you into a clean, Docker-ized container.  There is nothing of value on the VPS, so please don't be evil.

[key]: https://gist.githubusercontent.com/zachriggle/efa2e0080ae6de2e8344/raw/4b503e9db54f009d97477d03d4ba5678471f8ff0/id_rsa

# Origin

binjitsu is a fork of the [`pwntools`](https://github.com/Gallopsled/pwntools) project.  For the most part, it's a drop-in replacement, though I've added some functionality of my own which may not be available in the upstream release.

# Documentation
Our documentation is available at [binjitsu.readthedocs.org](https://binjitsu.readthedocs.org/)

To get you started, we've provided some example solutions for past CTF challenges in our [write-ups repository](https://github.com/binjitsu/examples).

# Installation

binjitsu is best supported on 64-bit Ubuntu 12.04 and 14.04, but most functionality should work on any Posix-like distribution (Debian, Arch, FreeBSD, OSX, etc.).  Python 2.7 is required.

Most of the functionality of binjitsu is self-contained and Python-only.  You should be able to get running quickly with

```sh
apt-get update
apt-get install python2.7 python-pip python-dev git
pip install --upgrade git+https://github.com/Gallopsled/pwntools.git
```

However, some of the features (assembling/disassembling foreign architectures) require non-Python dependencies.  For more information, see the [complete installation instructions here](https://binjitsu.readthedocs.org/install.html).


# Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md)

# Contact
If you have any questions not worthy of a [bug report](https://github.com/Gallopsled/pwntools/issues), feel free to ping
at [`ebeip90` on Freenode](irc://irc.freenode.net/pwntools) and ask away.
Click [here](https://kiwiirc.com/client/irc.freenode.net/pwntools) to connect.
There is also a [mailing list](https://groups.google.com/forum/#!forum/pwntools-users) for higher latency discussion.
