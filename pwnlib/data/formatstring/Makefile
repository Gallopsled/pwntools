CC?=clang
SOURCE=main.c
CFLAGS+=-O2 -fomit-frame-pointer -fno-stack-protector

all:
	$(MAKE) CC=clang                 main-amd64
	$(MAKE) CC=clang CFLAGS=-m32     main-i386
	$(MAKE) CC=arm-linux-gnueabi-gcc main-arm
	$(MAKE) CC=aarch64-linux-gnu-gcc main-aarch64
	
main-%: %.o
	$(CC) -o "$@" $^

%.o: main.c
	$(CC) -o "$@" -c $^
