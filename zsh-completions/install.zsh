#!/usr/bin/env zsh

>>~/.zshrc <<EOF

fpath=($(/bin/readlink -f ${0%/*}) \$fpath)
compinit
EOF

source ~/.zshrc