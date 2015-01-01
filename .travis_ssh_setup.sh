#!/usr/bin/env bash
#
# Install a demo user for SSH purposes
#
U=demouser
H=/home/$U

sudo useradd -m $U
ssh-keygen -t rsa -f /tmp/$U -N ''

eval $(ssh-agent -s)
ssh-add    /tmp/$U

sudo -u $U mkdir $H/.ssh
sudo -u $U cp    /tmp/$U.pub $H/.ssh/authorized_keys
sudo chmod -R 700 $H

(echo -n "$U:"; pwgen 100 1) | sudo chpasswd
