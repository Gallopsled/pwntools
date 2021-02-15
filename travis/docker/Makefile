ROOT = $(shell git rev-parse --show-toplevel)

all: shell

Dockerfile: FORCE
	cp $(ROOT)/extra/docker/develop/Dockerfile Dockerfile
	cat Dockerfile.travis >> Dockerfile

all: doctest

shell: bash

bash: image
	docker run -it --privileged --net=host --hostname localhost \
		--ulimit core=-1:-1 \
		--mount type=bind,source="$(ROOT)",target=/home/pwntools/pwntools \
		--entrypoint $(@) \
		travis

doctest:
	docker run --privileged --net=host --hostname localhost \
		--ulimit core=-1:-1 \
		--mount type=bind,source="$(ROOT)",target=/home/pwntools/pwntools \
		--entrypoint $(@) \
		--env TARGET=$(TARGET) \
		travis

image: Dockerfile
	docker build -t travis .

FORCE:
.PHONY: all image doctest bash
