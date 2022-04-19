FROM pwntools/pwntools:base

# Support sharing history with the develop Dockerfile
ENV HISTFILE=/home/pwntools/.history

# Uninstall existing versions of pwntools
USER root
RUN python -m pip uninstall -q -y pwntools \
 && python3 -m pip uninstall -q -y pwntools

# Switch back to the pwntools user from here forward
USER pwntools
WORKDIR /home/pwntools

# Since we are not installing Pwntools systemwide, the "pwn" binaries
# etc will all end up in this path.
ENV PATH="/home/pwntools/.local/bin:${PATH}"

# Install Pwntools to the home directory, make it an editable install
RUN git clone https://github.com/Gallopsled/pwntools \
 && python  -m pip install --upgrade --editable pwntools \
 && python3 -m pip install --upgrade --editable pwntools \
 && PWNLIB_NOTERM=1 pwn version

# Requirements for running the tests
RUN python  -m pip install --upgrade --requirement pwntools/docs/requirements.txt \
 && python3 -m pip install --upgrade --requirement pwntools/docs/requirements.txt

# Python niceties for debugging
RUN python  -m pip install -U ipython ipdb \
 && python3 -m pip install -U ipython ipdb

# Dependencies from .travis.yml addons -> apt -> packages
RUN sudo apt-get install -y \
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
	zsh

# Misc useful things when developing
RUN sudo apt-get install -y  \
	curl \
	ipython \
	ipython3 \
	lsb-release \
	ssh \
	unzip \
	wget

# Use zsh by default
RUN sudo chsh -s /bin/zsh pwntools

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