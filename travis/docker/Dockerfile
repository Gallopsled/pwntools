FROM pwntools/pwntools:base

# Support sharing history with the develop Dockerfile
ENV HISTFILE=/home/pwntools/.history

# Uninstall existing versions of pwntools
USER root
RUN python2.7 -m pip uninstall -q -y pwntools \
    && python3 -m pip uninstall -q -y pwntools

# Switch back to the pwntools user from here forward
USER pwntools
WORKDIR /home/pwntools

# Since we are not installing Pwntools systemwide, the "pwn" binaries
# etc will all end up in this path.
ENV PATH="/home/pwntools/.local/bin:${PATH}"

# Install Pwntools to the home directory, make it an editable install
RUN git clone https://github.com/Gallopsled/pwntools \
 && python2.7 -m pip install --no-cache-dir --upgrade --editable pwntools \
 && python3 -m pip install --no-cache-dir --upgrade --editable pwntools \
 && PWNLIB_NOTERM=1 pwn version

# Requirements for running the tests
RUN python2.7 -m pip install --no-cache-dir --upgrade --requirement pwntools/docs/requirements.txt \
    && python3 -m pip install --no-cache-dir --upgrade --requirement pwntools/docs/requirements.txt

# Python niceties for debugging
RUN python2.7 -m pip install --no-cache-dir -U ipython ipdb \
    && python3 -m pip install --no-cache-dir -U ipython ipdb

# Dependencies from .travis.yml addons -> apt -> packages
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ="UTC"
RUN sudo apt-get update && sudo -E apt-get install -y \
	tzdata \
	ash \
	bash \
	bash-static \
	binutils-msp430 \
	binutils-multiarch \
	binutils-s390x-linux-gnu \
	dash \
	gcc \
	gcc-multilib \
	gdb \
	ksh \
	lib32stdc++6 \
	libc6-dev-i386 \
	mksh \
	pandoc \
	qemu-user-static \
	socat \
	sshpass \
	vim \
	zsh \
# Misc useful things when developing
	curl \
	ipython3 \
	lsb-release \
	ssh \
	unzip \
	wget

# Use zsh by default
RUN sudo -E chsh -s /bin/zsh pwntools

# Get and install prezto
RUN git clone --recursive https://github.com/sorin-ionescu/prezto.git .zprezto
RUN bash -c 'for file in .zprezto/runcoms/z*; do ln -s $file .$(basename $file); done'

# Get and install pwndbg
RUN git clone --recursive https://github.com/pwndbg/pwndbg
RUN cd pwndbg && ./setup.sh

# Install autocompletion
RUN ln -s /home/pwntools/pwntools/extra/zsh_completion/_pwn /home/pwntools/.zprezto/modules/completion/external/src

# Install ipython profile and auto-import
RUN mkdir -p           /home/pwntools/.ipython/profile_default/startup
ADD 10-import.py       /home/pwntools/.ipython/profile_default/startup
ADD ipython_config.py  /home/pwntools/.ipython/profile_default

# Do not require password for sudo
RUN echo "pwntools ALL=(ALL:ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/travis

# Some additional debugging tools that are useful
RUN python2.7 -m pip install --no-cache-dir ipdb && \
    python3 -m pip install --no-cache-dir ipdb

# Install debugging utilities
USER root
RUN apt-get -y install gdb gdbserver tmux gdb-multiarch

# Set up binfmt-misc mappings inside the VM
USER root
RUN mkdir /etc/qemu-binfmt && \
    ln -sf /usr/lib/arm-linux-gnueabihf /etc/qemu-binfmt/arm && \
    ln -sf /usr/lib/aarch64-linux-gnu   /etc/qemu-binfmt/aarch64 && \
    ln -sf /usr/lib/mips-linux-gnu      /etc/qemu-binfmt/mips && \
    ln -sf /usr/lib/mipsel-linux-gnu    /etc/qemu-binfmt/mipsel && \
    ln -sf /usr/lib/powerpc-linux-gnu   /etc/qemu-binfmt/powerpc && \
    ln -sf /usr/lib/powerpc-linux-gnu64 /etc/qemu-binfmt/powerpc64 && \
    ln -sf /usr/lib/sparc64-linux-gnu   /etc/qemu-binfmt/sparc64 && \
    ln -sf /usr/lib/riscv64-linux-gnu   /etc/qemu-binfmt/riscv64

# Create the Travis user
USER root
RUN useradd -m travis
RUN echo "travis ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/travis

# Set up SSH stuff so we can SSH into localhost
USER pwntools
RUN ssh-keygen -t rsa -f ~/.ssh/id_rsa -N '' && \
    cp ~/.ssh/id_rsa.pub /tmp && \
    echo \
"Host *\n\
    User travis\n\
    HostName 127.0.0.1\n\
"> ~/.ssh/config

# Set up authorized_keys so we can login as travis with no creds
USER travis
RUN mkdir -m 0700 ~/.ssh && \
    echo 'from="127.0.0.1"' $(cat /tmp/id_rsa.pub) > ~/.ssh/authorized_keys

# Add the doctest entrypoint to /usr/bin so we don't have to supply the full path
USER root
ADD doctest2 doctest3 /usr/bin

# Switch back to pwntools to actually run the image
USER pwntools
WORKDIR /home/pwntools

# Copy in the Doctest script
COPY doctest2 doctest3 tmux.sh /home/pwntools

# Do everything in UTF-8 mode!
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV SHELL=/bin/bash

# Set entry point to doctest by default
WORKDIR /home/pwntools
