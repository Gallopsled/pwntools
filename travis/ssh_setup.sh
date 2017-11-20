#!/usr/bin/env bash
#
# Install a demo user for SSH purposes
#
# All of the "conditional sudo" is to do container-based builds on
# Travis which are much, much faster.
set -ex

U=travis
H=/home/$U

USUDO()
{
if [[ "$USER" == "travis" ]];
then
    $*
else
    sudo -u $U $*
fi
}


if [[ "$USER" == "travis" ]];
then
    rm -f ~/.ssh/*
else
    # Create the new user account
    # Disable password login for the user, and ensure the account is not locked
    sudo useradd -m $U
    sudo passwd --delete --unlock $U
fi

# Generate a new key so that we can log into it
ssh-keygen -t rsa -f ~/.ssh/$U -N ''

# Load the public key into a memory for below
pubkey=$(cat ~/.ssh/$U.pub)

# Set the authorized_keys entry to only permit login from localhost,
# and only with
USUDO mkdir $H/.ssh || true
USUDO tee -a $H/.ssh/authorized_keys <<EOF
from="127.0.0.1" $pubkey
EOF

# In the pwntools examples, we ssh to 'example.pwnme'
# Set up an SSH config entry to make this actually work
cat >> ~/.ssh/config <<EOF

Host example.pwnme
    User $U
    HostName 127.0.0.1
    IdentityFile ~/.ssh/$U
EOF

ssh -o "StrictHostKeyChecking no" -vvvv travis@example.pwnme id

set +ex
