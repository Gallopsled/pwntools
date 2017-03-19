CC?=clang
SOURCE=main.c
CFLAGS+=-O2 -fomit-frame-pointer -fno-stack-protector

all:
	$(MAKE) CC=clang                 main-amd64   preload-amd64
	$(MAKE) CC=clang CFLAGS=-m32     main-i386    preload-i386
	$(MAKE) CC=arm-linux-gnueabi-gcc main-arm     preload-arm
	$(MAKE) CC=aarch64-linux-gnu-gcc main-aarch64 preload-aarch64

main-%: main.c
	$(CC) -o "$@" main.c

preload-%: preload.c
	$(CC) -o "$@" preload.c -fPIC -pie -shared

clean:
	rm -f main-* preload-*

.PHONY: all clean
