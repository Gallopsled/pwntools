CC?=clang
SOURCE=main.c
CFLAGS+=-O2 -fomit-frame-pointer -fno-stack-protector

all:
	$(MAKE) CC=clang                 main-amd64   patched-amd64
	$(MAKE) CC='clang -m32'          main-i386    patched-i386
	$(MAKE) CC=arm-linux-gnueabi-gcc main-arm     patched-arm
	$(MAKE) CC=aarch64-linux-gnu-gcc main-aarch64 patched-aarch64

main-%: main.c
	$(CC) -o "$@" main.c

patched-%: main-%
	python patch.py "$^" "$@" printf sprintf snprintf

clean:
	rm -f main-* patched-*

.PHONY: all clean
