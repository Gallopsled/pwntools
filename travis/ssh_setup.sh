#!/usr/bin/env bash
#
# Install a demo user for SSH purposes
#
# All of the "conditional sudo" is to do container-based builds on
# Travis which are much, much faster.
set -e

U=travis
H=/home/$U

ls -lash ~/.ssh/

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

# Set the authorized_keys entry to only permit login from localhost,
# and only with
USUDO mkdir $H/.ssh || true

# Generate a new key so that we can log into it
ssh-keygen -t rsa -f ~/.ssh/$U -N ''

if [[ "$USER" == "travis" ]]; then
    cat ~/.ssh/$U.pub
else
    echo -n 'from="127.0.0.1 "'
    cat ~/.ssh/$U.pub
fi | USUDO tee -a $H/.ssh/authorized_keys

# In the pwntools examples, we ssh to 'example.pwnme'
# Set up an SSH config entry to make this actually work
cat >> ~/.ssh/config <<EOF

Host example.pwnme
    User $U
    HostName 127.0.0.1
    IdentityFile ~/.ssh/$U
EOF

cat /etc/ssh/sshd_config || true
cat /etc/ssh/ssh_config  || true

ls -lash ~/.ssh/

ssh -o PreferredAuthentications=publickey -o "StrictHostKeyChecking no" -vvvv travis@127.0.0.1 id

set +e
