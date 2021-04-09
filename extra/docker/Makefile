subdirs=$(shell find . -type d -depth 1 | xargs basename)
tags=base stable beta dev

all: $(subdirs) $(tags)

tags: $(tags)

base:
	@echo "Building $@"
	docker build -t pwntools/pwntools:$(shell basename $(@)) "$@"

stable beta dev: base
	@echo "Building $@"
	docker build -t pwntools/pwntools:$(shell basename $(@)) "$@"

develop:
	@echo "Building $@"
	docker build -t pwntools/pwntools:$(shell basename $(@)) "$@"
	docker run -it --privileged --net=host --hostname localhost \
		--ulimit core=-1:-1 \
		--mount type=bind,source="$(shell git rev-parse --show-toplevel)",target=/home/pwntools/pwntools \
		pwntools/pwntools:$(shell basename $(@))

debug:
	@echo "Subdirs   $(subdirs)"
	@echo "Tags      $(tags)"

clean:
	docker container prune
	docker

FORCE:

.PHONY: all $(subdirs) $(makefiles) $(tags)