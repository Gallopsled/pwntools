#!/usr/bin/env bash
#
# Install a demo user for SSH purposes
#
U=demouser
H=/home/$U

# Create the new user account
sudo useradd -m $U

# Generate a new key so that we can log into it
ssh-keygen -t rsa -f ~/.ssh/$U -N ''

# Start ssh-agent so that the key is loaded, and paramiko can find it
eval $(ssh-agent -s)
ssh-add    ~/.ssh/$U

# Load the public key into a memory for below
pubkey=$(cat ~/.ssh/$U.pub)

# Set the authorized_keys entry to only permit login from localhost,
# and only with 
sudo -u $U mkdir $H/.ssh
sudo -u $U tee $H/.ssh/authorized_keys <<EOF
from="127.0.0.1" $pubkey
EOF

# Disable password login for the user, and ensure the account is not locked
sudo passwd --delete --unlock $U

# In the pwntools examples, we ssh to 'example.pwnme'
# Set up an SSH config entry to make this actually work
cat >> ~/.ssh/config <<EOF
Host example.pwnme
    User demouser
    HostName 127.0.0.1
    IdentityFile ~/.ssh/$U
EOF