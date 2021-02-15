#!/usr/bin/env bash

# We have to explicitly start the ssh service
sudo service ssh start

# Enable the IPv6 interface
echo 0 | sudo tee /proc/sys/net/ipv6/conf/all/disable_ipv6

PWNLIB_NOTERM=1 coverage3 run -m sphinx -b doctest docs/source docs/build/doctest $TARGET
