#!/usr/bin/env bash


if [ "$TRAVIS_BRANCH" = "stable" ] && [ ! -z "$TRY_KEY" ]; then
    # Start the SSH agent
    eval "$(ssh-agent -s)"

    # Add the keys
    echo "$TRY_KEY" > ~/.ssh/try_key
    chmod 600         ~/.ssh/try_key
    ssh-add           ~/.ssh/try_key

    # Update!
    ssh root@demo.pwntools.com -- 'docker/update'
fi
