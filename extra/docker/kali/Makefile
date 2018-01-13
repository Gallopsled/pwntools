all: Dockerfile

Dockerfile: ../xenial/Dockerfile FORCE
	sed "s|ubuntu:xenial|kalilinux/kali-linux-docker|" < "$<" > "$@"

FORCE:

.PHONY: all
