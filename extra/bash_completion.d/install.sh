#!/usr/bin/env bash

BASH_COMPLETION_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if grep "$BASH_COMPLETION_DIR" ~/.bash_profile; then
    >&2 echo "Already installed"
    exit
fi >/dev/null

cat >> ~/.bash_profile <<EOF
# Install autocompletion for Pwntools
. "$BASH_COMPLETION_DIR/pwn"
EOF