############################################################
# Dockerfile to build Binjitsu container
# Based on Ubuntu
############################################################

FROM ubuntu
MAINTAINER Maintainer Zach Riggle

RUN apt-get update && apt-get install -y software-properties-common
RUN apt-add-repository --yes ppa:pwntools/binutils
RUN apt-get update
RUN apt-get install -y \
    binutils \
    binutils-aarch64-linux-gnu \
    binutils-arm-linux-gnueabihf \
    curl \
    gdb \
    gdbserver \
    gdb-multiarch \
    git \
    libc6-i386 \
    libc6-arm64-cross \
    libc6-armhf-cross \
    libc6-dev-i386 \
    libncurses5-dev \
    libncursesw5-dev \
    python-dev \
    python-pip \
    python3-pip \
    python2.7 \
    qemu \
    qemu-user-static \
    tmux \
    wget
RUN pip install --upgrade ipython
RUN useradd -m zerocool
RUN usermod -U zerocool


RUN mkdir -p /etc/qemu-binfmt
RUN ln -s /usr/aarch64-linux-gnu /etc/qemu-binfmt/aarch64
RUN ln -s /usr/arm-linux-gnueabihf /etc/qemu-binfmt/arm

RUN git clone https://github.com/aquynh/capstone \
	&& cd capstone \
	&& git checkout -t origin/next \
	&& sudo ./make.sh install \
	&& cd bindings/python \
	&& python2 setup.py install \
	&& python3 setup.py install
RUN pip install --upgrade pycparser
RUN pip3 install --upgrade pycparser

RUN pip install --upgrade git+https://github.com/binjitsu/binjitsu.git

RUN git clone https://github.com/zachriggle/pwndbg /home/zerocool/pwndbg
RUN echo "source /home/zerocool/pwndbg/gdbinit.py" > /home/zerocool/.gdbinit

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN chown -R zerocool.zerocool /home/zerocool
RUN chsh -s /bin/bash zerocool
