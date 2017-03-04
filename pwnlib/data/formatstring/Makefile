SOURCE=main.c
CFLAGS+=-O2 -fomit-frame-pointer -fno-stack-protector

all:
	$(MAKE) CFLAGS=-m32 main
	mv main main32
	$(MAKE) main

%: %.o

%.o: %.c
	clang -o "$@" "$^"
