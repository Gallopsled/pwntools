from debian:buster

RUN apt-get update
RUN apt-get -y dist-upgrade
RUN apt-get -y install python3 python3-pip
RUN apt-get -y install git wget unzip

RUN pip3 install --upgrade git+https://github.com/Gallopsled/pwntools@dev