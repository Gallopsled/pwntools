all: Dockerfile

Dockerfile: ../stable/Dockerfile FORCE
	sed "s|ubuntu:xenial|kalilinux/kali-linux-docker|" < "$<" > "$@"

FORCE:

.PHONY: all
