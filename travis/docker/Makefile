ROOT = $(shell git rev-parse --show-toplevel)
$(shell reset)

all: shell

Dockerfile: FORCE
	cp $(ROOT)/extra/docker/develop/Dockerfile Dockerfile
	cat Dockerfile.travis >> Dockerfile

all: doctest

shell: bash

bash: image
	@echo Running interactive shell
	docker run -it --privileged --net=host --hostname localhost \
		--ulimit core=-1:-1 \
		--mount type=bind,source="$(ROOT)",target=/home/pwntools/pwntools \
		--entrypoint /bin/bash \
		travis

doctest: image
	@echo Running doctests
	docker run --privileged --net=host --hostname localhost \
		--ulimit core=-1:-1 \
		--mount type=bind,source="$(ROOT)",target=/home/pwntools/pwntools \
		--env TARGET=$(TARGET) \
		travis

image: Dockerfile
	docker build -t travis .

FORCE:
.PHONY: all image doctest bash
