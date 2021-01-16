subdirs=$(shell find . -type d -depth 1 | xargs basename)
makefiles=$(wildcard */Makefile)
tags=base stable beta dev

all: $(makefiles) $(subdirs) $(tags)

tags: $(tags)

$(subdirs):
	@echo "Building $@"
	docker build -t pwntools/pwntools:$(shell basename $(@)) "$@"

debug:
	@echo "Makefiles $(makefiles)"
	@echo "Subdirs   $(subdirs)"
	@echo "Tags      $(tags)"

$(makefiles):
	echo "Making $@"
	make -C $(shell dirname $@)

.FORCE: $(subdirs) $(makefiles)
.PHONY: all $(subdirs) $(makefiles) $(tags)