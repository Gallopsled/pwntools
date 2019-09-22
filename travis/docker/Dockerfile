############################################################
# Dockerfile to build Pwntools container
# Based on Ubuntu
############################################################

FROM pwntools/pwntools:stable
MAINTAINER Maintainer Gallopsled et al.

USER root

RUN apt-get update

# Use UTF-8
RUN apt-get install -y locales
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Dependencies from .travis.yml addons -> apt -> packages
RUN apt-get install -y ash
RUN apt-get install -y bash
RUN apt-get install -y dash
RUN apt-get install -y gcc-multilib
RUN apt-get install -y gcc-arm-linux-gnueabi
RUN apt-get install -y gcc-aarch64-linux-gnu
RUN apt-get install -y gcc-mips-linux-gnu
RUN apt-get install -y gcc-powerpc-linux-gnu
RUN apt-get install -y gcc
RUN apt-get install -y gdb
RUN apt-get install -y ksh
RUN apt-get install -y lib32stdc++6
RUN apt-get install -y libc6-dev-i386
RUN apt-get install -y mksh
RUN apt-get install -y pandoc
RUN apt-get install -y zsh

# Dependencies from travis/install.sh
RUN apt-get install -y binutils
RUN apt-get install -y qemu-user-static
RUN apt-get install -y binutils-*
RUN apt-get install -y libcapstone3

# Required for various other things
RUN apt-get install -y curl
RUN apt-get install -y wget
RUN apt-get install -y unzip
RUN apt-get install -y openjdk-8-jre-headless
RUN apt-get install -y libxml2-dev
RUN apt-get install -y libxslt1-dev
RUN apt-get install -y ssh
RUN apt-get install -y lsb-release

# Installing Python3 and setting it to the default
WORKDIR /root
RUN apt-get install -y python3
RUN apt-get install -y python3
RUN apt-get install -y python3-dev
RUN apt-get install -y python3-pip
RUN pip3 install --upgrade pip
RUN echo 'alias python=python3' >> ~/.bashrc

#==============================================================================
#                               ANDROID EMULATOR
#==============================================================================
# Android emulator from travis/install.sh
WORKDIR /usr/local
RUN wget -nv https://dl.google.com/android/android-sdk_r24.4.1-linux.tgz; \
    tar xf android-sdk_r24.4.1-linux.tgz; \
    rm -f android-sdk_r24.4.1-linux.tgz;
RUN ln -s android-sdk-linux android-sdk
ENV PATH="/usr/local/android-sdk/tools:$PATH"
ENV PATH="/usr/local/android-sdk/platform-tools:$PATH"

RUN wget -nv https://dl.google.com/android/repository/android-ndk-r13b-linux-x86_64.zip ; \
    unzip android-ndk-r13b-linux-x86_64.zip ; \
    rm -f android-ndk-r13b-linux-x86_64.zip ;
RUN ln -s android-ndk-r13b android-ndk

# Ensure that all executables can be run by other users e.g. travis
RUN find android-sdk/ -perm 744 -type f -executable | xargs chmod +x

ENV NDK="/usr/local/android-ndk"
ENV PATH="$NDK:$PATH"

RUN echo y | android update sdk --no-ui --all --filter platform-tools,extra-android-support
RUN echo y | android update sdk --no-ui --all --filter android-21
RUN echo y | android update sdk --no-ui --all --filter sys-img-armeabi-v7a-android-21

#==============================================================================
#                          PWNTOOLS TEST REQUIREMENTS
#==============================================================================

# Install pwntools from 'dev3', to get all of the latest dependencies
# Then uninstall pwntools so we have a clean slate, but still have
# all of its dependencies installed.
WORKDIR /root
RUN git clone https://github.com/Gallopsled/pwntools
WORKDIR /root/pwntools
RUN git checkout dev3
RUN pip3 install --upgrade --editable .
RUN pip3 install --upgrade --requirement docs/requirements.txt
RUN pip3 uninstall --yes pwntools
WORKDIR /root
RUN rm -rf pwntools

#==============================================================================
#                           PWNTOOLS SSH TEST SETUP
#==============================================================================
# Start the container as travis
RUN useradd -m travis
RUN echo "travis ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/travis

# Set up SSH stuff so we can SSH into localhost
USER travis
WORKDIR /home/travis
RUN ssh-keygen -t rsa -f ~/.ssh/travis -N ''
RUN echo 'from="127.0.0.1"' $(cat .ssh/travis.pub) > .ssh/authorized_keys
RUN echo \
Host "example.pwnme\n\
    User travis\n\
    HostName 127.0.0.1\n\
    IdentityFile ~/.ssh/travis\n"\
> ~/.ssh/config

#==============================================================================
#                            ANDROID EMULATOR SETUP
#==============================================================================
RUN echo no | android --silent create avd --name android-armeabi-v7a   --target android-21 --force --snapshot --abi armeabi-v7a
RUN emulator64-arm -avd android-armeabi-v7a -no-window -no-boot-anim -no-skin -no-audio -no-window -no-snapshot & \
    adb wait-for-device; \
    adb shell id; \
    adb shell getprop; \
    adb emu kill

# Final touchup
USER root
# Setting Python3 as the default
RUN echo 'alias python=python3' >> ~/.bashrc

RUN apt-get install -y strace nano vim tmux

# Entry point
USER travis
# Setting Python3 as the default
RUN echo 'alias python=python3' >> ~/.bashrc
RUN mkdir /home/travis/pwntools
WORKDIR /home/travis/pwntools
ADD run.sh .
COPY pwntools.tar.gz .
RUN tar xf pwntools.tar.gz
RUN sudo rm -f pwntools.tar.gz
ENTRYPOINT bash run.sh
