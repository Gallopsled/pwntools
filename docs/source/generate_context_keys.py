#!/usr/bin/python

from pwn2.lib.context import defaults

for k in dir(defaults):
    if k and k[0] != '_':



