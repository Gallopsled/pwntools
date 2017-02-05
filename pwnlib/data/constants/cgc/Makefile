SWIG=^%constant (\w+) = ((0x[0-9A-Fa-f <]|[0-9 <])+).*
PYTHON=\1 = Constant('\1', \2)
TARGET=cgc.py

all: include.h $(TARGET)

%.py: %.constants
	echo 'from pwnlib.constants.constant import Constant' > "$@"
	sed -E "s/$(SWIG)/$(PYTHON)/" < "$^" >> "$@"
	python -m py_compile "$@"

%.constants: %.pre
	grep -E "$(SWIG)" < "$^" | sort | uniq > "$@"

%.pre: $(MUSL) include.h
	swig \
		-I. \
		-includeall \
		-E include.h > "$@"

headers: $(HEADERS)

%.h: %.h.in
	# This rule gives us both SYS_xxx and __NR_xxx
	cp $< $@
	sed -n -e s/__NR_/SYS_/p < $< >> $@

clean:
	rm -rf *.py *.constants *.pre $(MUSL)

rebuild:
	rm -rf *.py *.constants *.pre
	$(MAKE) all

install: all
	cp -f *.py ../../../constants

.PHONY: all install clean

# Keep intermediate files around with 'make V=1'
ifneq ($(strip $(V)),)
.PRECIOUS: %.pre %.constants
.SECONDARY: %.pre %.constants
endif


# swig -Ifreebsd -includeall -E freebsd/common.h | egrep "^%constant" | ./load_constants.py $python/freebsd.py $headers/freebsd.h

