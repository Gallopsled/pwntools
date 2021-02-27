Binutils
-------------

Assembly of foreign architectures (e.g. assembling Sparc shellcode on
Mac OS X) requires cross-compiled versions of ``binutils`` to be
installed. We've made this process as smooth as we can.

In these examples, replace ``$ARCH`` with your target architecture (e.g., arm, mips64, vax, etc.).

Building `binutils` from source takes about 60 seconds on a modern 8-core machine.

Ubuntu
^^^^^^^^^^^^^^^^

For Ubuntu 12.04 through 15.10, you must first add the pwntools `Personal Package Archive repository <https://launchpad.net/~pwntools/+archive/ubuntu/binutils>`__.

Ubuntu Xenial (16.04) has official packages for most architectures, and does not require this step.

.. code-block:: bash

    $ apt-get install software-properties-common
    $ apt-add-repository ppa:pwntools/binutils
    $ apt-get update

Then, install the binutils for your architecture.

.. code-block:: bash

    $ apt-get install binutils-$ARCH-linux-gnu

Mac OS X
^^^^^^^^^^^^^^^^

Mac OS X is just as easy, but requires building binutils from source.
However, we've made ``homebrew`` recipes to make this a single command.
After installing `brew <http://brew.sh>`__, grab the appropriate
recipe from our `binutils
repo <https://github.com/Gallopsled/pwntools-binutils/>`__.

.. code-block:: bash

    $ brew install https://raw.githubusercontent.com/Gallopsled/pwntools-binutils/master/macos/binutils-$ARCH.rb

Alternate OSes
^^^^^^^^^^^^^^^^

If you want to build everything by hand, or don't use any of the above
OSes, ``binutils`` is simple to build by hand.

.. code-block:: bash

    #!/usr/bin/env bash

    V=2.25   # Binutils Version
    ARCH=arm # Target architecture

    cd /tmp
    wget -nc https://ftp.gnu.org/gnu/binutils/binutils-$V.tar.gz
    wget -nc https://ftp.gnu.org/gnu/binutils/binutils-$V.tar.gz.sig

    gpg --keyserver keys.gnupg.net --recv-keys 4AE55E93
    gpg --verify binutils-$V.tar.gz.sig

    tar xf binutils-$V.tar.gz

    mkdir binutils-build
    cd binutils-build

    export AR=ar
    export AS=as

    ../binutils-$V/configure \
        --prefix=/usr/local \
        --target=$ARCH-unknown-linux-gnu \
        --disable-static \
        --disable-multilib \
        --disable-werror \
        --disable-nls

    MAKE=gmake
    hash gmake || MAKE=make

    $MAKE -j clean all
    sudo $MAKE install

