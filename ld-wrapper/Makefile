TARGETS=liboverride-32.so liboverride-64.so
CSRCS=$(shell find . -maxdepth 1 -name "*.c")
LIBS32=$(patsubst %.c,%.32.o,$(CSRCS)) ld-override.32.o
LIBS64=$(patsubst %.c,%.64.o,$(CSRCS)) ld-override.64.o
CFLAGS=-shared -Wall -Werror -fno-builtin -fPIC
DEPFILE=.depend
CC=gcc
LDFLAGS=-ldl
CTAGS=ctags -lc++

all: $(TARGETS)

clean:
	rm -f $(TARGETS) $(LIBS32) $(LIBS64)

liboverride-32.so: $(LIBS32)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) -m32

liboverride-64.so: $(LIBS64)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)

%.32.o: %.32.asm
	nasm -felf32 -o $@ $<

%.64.o: %.64.asm
	nasm -felf64 -o $@ $<

%.32.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $< -m32

%.64.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

.PHONY: all clean
