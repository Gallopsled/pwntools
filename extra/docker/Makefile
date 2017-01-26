subdirs=$(wildcard */)
makefiles=$(wildcard */Makefile)

all: $(makefiles) $(subdirs)
	echo $(subdirs)

$(subdirs):
	docker build -t pwntools:$(shell basename $(@)) "$@"

$(makefiles):
	make -C $(shell dirname $@)

.PHONY: all $(subdirs) $(makefiles)
