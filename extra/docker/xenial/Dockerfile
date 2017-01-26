############################################################
# Dockerfile to build Pwntools container
# Based on Ubuntu
############################################################

FROM ubuntu:xenial
MAINTAINER Maintainer Gallopsled et al.

RUN apt-get update
RUN apt-get install -y build-essential
RUN apt-get install -y git
RUN apt-get install -y libssl-dev
RUN apt-get install -y libffi-dev
RUN apt-get install -y python2.7
RUN apt-get install -y python-pip
RUN apt-get install -y python-dev
RUN pip install --upgrade pip
RUN python -m pip install --upgrade pwntools
RUN PWNLIB_NOTERM=1 pwn update
