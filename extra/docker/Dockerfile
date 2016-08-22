############################################################
# Dockerfile to build Pwntools container
# Based on Ubuntu
############################################################

FROM ubuntu:trusty
MAINTAINER Maintainer Gallopsled et al.

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
	libffi-dev \
	libglib2.0-dev \
	libncurses5-dev \
	libncursesw5-dev \
	ltrace \
	python-dev \
	python-pip \
	python3-pip \
	python2.7 \
	qemu \
	qemu-user-static \
	strace \
	tmux \
	wget
RUN pip install --upgrade ipython
RUN useradd -m zerocool
RUN usermod -U zerocool

RUN mkdir -p /etc/qemu-binfmt
RUN ln -s /usr/aarch64-linux-gnu /etc/qemu-binfmt/aarch64
RUN ln -s /usr/arm-linux-gnueabihf /etc/qemu-binfmt/arm

RUN pip install --upgrade pip pycparser psutil python-ptrace
RUN pip3 install --upgrade pip pycparser psutil python-ptrace

RUN pip install --upgrade git+https://github.com/Gallopsled/pwntools.git

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN chown -R zerocool.zerocool /home/zerocool
RUN chsh -s /bin/bash zerocool
