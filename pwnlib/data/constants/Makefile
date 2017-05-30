all:
	$(MAKE) -C cgc
	$(MAKE) -C freebsd
	$(MAKE) -C musl

install: all
	$(MAKE) -C cgc install
	$(MAKE) -C freebsd install
	$(MAKE) -C musl install

.PHONY: all install
