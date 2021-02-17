ROOT = $(shell git rev-parse --show-toplevel)
$(shell reset)

Dockerfile: FORCE
	cp $(ROOT)/extra/docker/develop/Dockerfile Dockerfile
	cat Dockerfile.travis >> Dockerfile

all: doctest

# shell: bash

bash: image
	@echo Running interactive shell
	docker run -it --privileged --net=host --hostname localhost \
		--ulimit core=-1:-1 \
		--mount type=bind,source="$(ROOT)",target=/home/pwntools/pwntools \
		--mount type=bind,source="$(HOME)/.pwntools-cache-3.6",target=/home/pwntools/.pwntools-cache-3.6 \
		--entrypoint /bin/bash \
		travis

doctest: image FORCE
	@echo Running doctests
	docker run -it --privileged --net=host --hostname localhost \
		--ulimit core=-1:-1 \
		--mount type=bind,source="$(ROOT)",target=/home/pwntools/pwntools \
		--mount type=bind,source="$(HOME)/.pwntools-cache-3.6",target=/home/pwntools/.pwntools-cache-3.6 \
		--env TARGET=$(TARGET) \
		travis

image: Dockerfile
	docker build -t travis .

FORCE:
.PHONY: all image doctest bash
