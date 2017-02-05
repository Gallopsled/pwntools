
ARCHES=aarch64 arm i386 microblaze mips mips64 powerpc powerpc64 s390x sh x86_64
MUSL=musl-1.1.16

SWIG=^%constant (\w+) = ((0x[0-9A-Fa-f <]|[0-9 <])+).*
PYTHON=\1 = Constant('\1', \2)

INFILES=$(shell find . -type f -iname '*.in')
HEADERS=$(patsubst %.h.in,%.h,$(INFILES)) $(NETINET)

all: include.h
	$(MAKE) $(MUSL)
	$(MAKE) $(ARCHES)

$(ARCHES): % : %.py

%.py: %.constants
	echo 'from pwnlib.constants.constant import Constant' > "$@"
	sed -E "s/$(SWIG)/$(PYTHON)/" < "$^" >> "$@"
	python -m py_compile "$@"

%.constants: %.pre
	grep -E "$(SWIG)" < "$^" | sort | uniq > "$@"

%.pre: $(MUSL) include.h
	swig \
		-I$(MUSL)/include \
		-I$(MUSL)/arch/$* \
		-I$(MUSL)/arch/generic \
		-I$(MUSL)/arch/generic/bits \
		-includeall \
		-E include.h > "$@"

headers: $(HEADERS)

%.h: %.h.in
	# This rule gives us both SYS_xxx and __NR_xxx
	cp $< $@
	sed -n -e s/__NR_/SYS_/p < $< >> $@

$(MUSL): $(MUSL).tar.gz
	tar xf "$^"
	sed -E -i 's|\(\(in_addr_t\) (.*)\)|\1|' $(MUSL)/include/netinet/in.h
	$(MAKE) headers

$(MUSL).tar.gz:
	wget --no-clobber "https://www.musl-libc.org/releases/$@"

clean:
	rm -rf *.py *.constants *.pre $(MUSL)

rebuild:
	rm -rf *.py *.constants *.pre
	$(MAKE) all

install: all
	cp -f *.py ../../../constants/linux

.PHONY: all $(ARCHES) $(NETINET_IN) install clean

# Keep intermediate files around with 'make V=1'
ifneq ($(strip $(V)),)
.PRECIOUS: %.pre %.constants
.SECONDARY: %.pre %.constants
endif
