all: Dockerfile

Dockerfile: ../xenial/Dockerfile FORCE
	sed "s|ubuntu:xenial|ubuntu:trusty|" < "$<" > "$@"

FORCE:

.PHONY: all
