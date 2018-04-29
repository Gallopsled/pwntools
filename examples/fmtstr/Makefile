CFLAGS := -Wno-unused-result -Wno-format-security
TARGETS := printf.mips printf.mips64 printf.mipsel printf.mips64el printf.arm printf.aarch64 \
	         printf.ppc printf.ppc64 printf.sparc64 printf.native printf.native32 \
	         printf-loop.native printf-loop.native32

.PHONY: run
run: all
	./exploit2.py
	./exploit.py

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean:
	rm -f $(TARGETS)

# mips variants
%.mips: %.c
	mips-linux-gnu-gcc $(CFLAGS) -static -Os -o "$@" $^
%.mipsel: %.c
	mipsel-linux-gnu-gcc $(CFLAGS) -static -Os -o "$@" $^
%.mips64: %.c
	mips64-linux-gnuabi64-gcc $(CFLAGS) -static -Os -o "$@" $^
%.mips64el: %.c
	mips64el-linux-gnuabi64-gcc $(CFLAGS) -static -Os -o "$@" $^

# arm variants
%.arm: %.c
	arm-linux-gnueabi-gcc $(CFLAGS) -static -Os -o "$@" $^
%.aarch64: %.c
	aarch64-linux-gnu-gcc $(CFLAGS) -static -Os -o "$@" $^

# ppc variants
%.ppc: %.c
	powerpc-linux-gnu-gcc $(CFLAGS) -static -Os -o "$@" $^
%.ppc64: %.c
	powerpc64-linux-gnu-gcc $(CFLAGS) -static -Os -o "$@" $^

# sparc variants
%.sparc64: %.c
	sparc64-linux-gnu-gcc $(CFLAGS) -static -Os -o "$@" $^

# native variants
%.native: %.c
	gcc $(CFLAGS) -o "$@" $^
%.native32: %.c
	gcc $(CFLAGS) -m32 -o "$@" $^

# install deps on ubuntu xenial
.PHONY: install-apt
install-apt:
	apt-get install -y make gcc-mips64el-linux-gnuabi64 gcc-sparc64-linux-gnu gcc-powerpc64-linux-gnu gcc-powerpc-linux-gnu gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu gcc-mips64-linux-gnuabi64 gcc-mipsel-linux-gnu gcc-mips64el-linux-gnuabi64 gcc-mips-linux-gnu gcc-i686-linux-gnu gcc
