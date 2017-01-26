all: Dockerfile

Dockerfile: ../stable/Dockerfile FORCE
	sed "s|ubuntu:xenial|ubuntu:precise|" < "$<" > "$@"

FORCE:

.PHONY: all
