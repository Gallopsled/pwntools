#!/usr/bin/env zsh

# Try to find a writable directory first, in reverse order
for dir in "${(Oa)fpath[@]}"; do
    if [ -w "$dir" ]; then
        cp -f ${0:h}/_pwn "$dir"
        return
    fi
done

cat <<EOF
Could not find a suitable directory to install the completion.

Try adding this line at the top of your ~/.zshrc, and start a new shell.

    fpath=( ${0:A:h} \$fpath )

If completion does not work, add this to the bottom of your ~/.zshrc, and start a new shell.
Users of prezto should enable the 'completion' module (enabled by default).

    compinit -i

EOF