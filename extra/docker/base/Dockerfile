############################################################
# Dockerfile to build Pwntools container
# Based on Ubuntu
############################################################

FROM ubuntu:jammy
MAINTAINER Maintainer Gallopsled et al.

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y \
        sudo \
        locales \
        build-essential \
        elfutils \
        git \
        libssl-dev \
        libffi-dev \
        python2.7 \
        python2.7-dev \
        python2-pip-whl \
        python3 \
        python3-pip \
        python3-dev \
        python-is-python3 \
        qemu-user-static \
        binutils-arm-linux-gnueabihf \
        binutils-aarch64-linux-gnu \
        binutils-mips-linux-gnu \
        binutils-mipsel-linux-gnu \
        binutils-powerpc-linux-gnu \
        binutils-powerpc64-linux-gnu \
        binutils-sparc64-linux-gnu \
        binutils-riscv64-linux-gnu \
        tmux \
        patchelf \
    && locale-gen en_US.UTF-8 \
    && update-locale LANG=en_US.UTF-8 \
    && PYTHONPATH=`echo /usr/share/python-wheels/pip-*.whl` python2.7 -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python2.7 -m pip install --no-cache-dir --upgrade pwntools \
    && python3 -m pip install --no-cache-dir --upgrade pip \
    && python3 -m pip install --no-cache-dir --upgrade pwntools \
    && PWNLIB_NOTERM=1 pwn update \
    && useradd -m pwntools \
    && passwd --delete --unlock pwntools \
    && echo "pwntools ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/pwntools
USER pwntools
