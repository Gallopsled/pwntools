ROOT = $(shell git rev-parse --show-toplevel)
$(shell reset)

all: doctest3

Dockerfile: FORCE
	cp $(ROOT)/extra/docker/develop/Dockerfile Dockerfile
	cat Dockerfile.travis >> Dockerfile
	cp $(ROOT)/extra/docker/develop/10-import.py 10-import.py
	cp $(ROOT)/extra/docker/develop/ipython_config.py ipython_config.py


shell bash: image
	@echo Running interactive shell
	docker run -it --privileged --net=host --hostname localhost \
		--ulimit core=-1:-1 \
		--mount type=bind,source="$(ROOT)",target=/home/pwntools/pwntools \
		--entrypoint ./tmux.sh \
		travis

doctest2 doctest3: image FORCE
	@echo Running doctests
	docker run -it --privileged --net=host --hostname localhost \
		--ulimit core=-1:-1 \
		--mount type=bind,source="$(ROOT)",target=/home/pwntools/pwntools \
		--env TARGET=$(TARGET) \
		--entrypoint ./$@ \
		travis

image: Dockerfile
	docker build -t travis .

FORCE:
.PHONY: all image doctest2 doctest3 bash
