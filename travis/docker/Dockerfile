FROM pwntools/pwntools:base

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

# Do not require password for sudo
RUN echo "pwntools ALL=(ALL:ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/travis# Some additional debugging tools that are useful
RUN python  -m pip install ipdb
RUN python3 -m pip install ipdb

# Create the Travis user
USER root
RUN useradd -m travis
RUN echo "travis ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/travis

# Set up SSH stuff so we can SSH into localhost
USER pwntools
RUN ssh-keygen -t rsa -f ~/.ssh/id_rsa -N ''
RUN cp ~/.ssh/id_rsa.pub /tmp
RUN echo \
"Host *\n\
    User travis\n\
    HostName 127.0.0.1\n\
"> ~/.ssh/config

# Set up authorized_keys so we can login as travis with no creds
USER travis
RUN mkdir -m 0700 ~/.ssh
RUN echo 'from="127.0.0.1"' $(cat /tmp/id_rsa.pub) > ~/.ssh/authorized_keys

# Add the doctest entrypoint to /usr/bin so we don't have to supply the full path
USER root
ADD doctest /usr/bin

# Switch back to pwntools to actually run the image
USER pwntools
WORKDIR /home/pwntools

# Copy in the Doctest script
COPY doctest /home/pwntools/doctest

# Set entry point to doctest by default
ENTRYPOINT /home/pwntools/doctest