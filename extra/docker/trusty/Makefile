all: Dockerfile

Dockerfile: ../stable/Dockerfile FORCE
	sed "s|ubuntu:xenial|ubuntu:trusty|" < "$<" > "$@"

FORCE:

.PHONY: all
