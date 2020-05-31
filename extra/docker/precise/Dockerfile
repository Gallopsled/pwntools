############################################################
# Dockerfile to build Pwntools container
# Based on Ubuntu
############################################################

FROM ubuntu:precise
MAINTAINER Maintainer Gallopsled et al.

RUN apt-get update \
    && apt-get install -y \
        build-essential \
        git \
        libssl-dev \
        libffi-dev \
        python2.7 \
        python-pip \
        python-dev \
    && pip install --upgrade pip \
    && python -m pip install --upgrade pwntools \
    && PWNLIB_NOTERM=1 pwn update \
    && apt-get install -y sudo \
    && useradd -m pwntools \
    && passwd --delete --unlock pwntools \
    && echo "pwntools ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/pwntools
USER pwntools
WORKDIR /home/pwntools
