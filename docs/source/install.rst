Installation
============

pwntools is best supported on Ubuntu 12.04 and 14.04, but most
functionality should work on any Posix-like distribution (Debian, Arch,
FreeBSD, OSX, etc.).

Prerequisites
-------------

In order to get the most out of ``pwntools``, you should have the
following system libraries installed.

-  binutils for your target architecture (`Ubuntu`_)
-  `libcapstone 2.1`_ (Ubuntu `i386`_ `amd64`_)

Released Version
-----------------

Pwntools is available as a pip package. It reqiures Python 2.7, and one
of its dependences requires the Python headers.

.. code:: sh

    apt-get install python2.7 python2.7-dev python-pip
    pip install pwntools

Latest Version
--------------

Alternatively if you prefer to use the latest version from the
repository:

.. code:: sh

    git clone https://github.com/Gallopsled/pwntools
    PWN=$(realpath pwntools)
    cd $PWN
    pip2 install -r requirements.txt
    export PATH="$PWN/bin:$PATH"
    export PYTHONPATH="$PWN:$PYTHONPATH"

If you want to make these settings permanent:

.. code:: sh

    >>~/.bashrc cat <<EOF
    # Set up path for Pwntools
    export PATH="$PWN/bin:\$PATH"
    export PYTHONPATH="$PWN:\$PYTHONPATH"
    EOF

.. _Ubuntu: https://launchpad.net/~pwntools/+archive/ubuntu/binutils
.. _libcapstone 2.1: http://www.capstone-engine.org
.. _i386: http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2_i386.deb
.. _amd64: http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2_amd64.deb
N:\$PYTHONPATH"
EOF
```
