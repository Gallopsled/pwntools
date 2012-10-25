#!/bin/sh

CC=gcc -O3 -Wall

all: tattack libc.so

tattack: tattack.c
	$(CC) -o $@ $<

libc.so: libc.c
	$(CC) $< -shared -c -fPIC -o $@