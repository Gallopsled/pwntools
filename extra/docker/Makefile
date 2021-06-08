subdirs=$(shell find . -type d -depth 1 | xargs basename)
tags=base stable beta dev
ROOT=$(shell git rev-parse --show-toplevel)
CMD ?= zsh

ifneq ($(HISTFILE),)
MOUNT_HISTFILE=--mount type=bind,source="$(HISTFILE)",target=/home/pwntools/.history
endif

all: $(subdirs) $(tags)

tags: $(tags)

$(subdirs)::
	@echo "Building $@"
	docker build -t pwntools/pwntools:$(shell basename $(@)) "$@"

develop::
	docker run -it \
		--privileged \
		--net=host \
		--hostname localhost \
		--ulimit core=-1:-1 \
		$(MOUNT_HISTFILE) \
		--mount type=bind,source="$(ROOT)",target=/home/pwntools/pwntools \
		pwntools/pwntools:$(shell basename $(@)) \
		$(CMD)

debug:
	@echo "Subdirs   $(subdirs)"
	@echo "Tags      $(tags)"

clean:
	docker container prune
	docker

FORCE:

.PHONY: all $(subdirs) $(makefiles) $(tags)