ROOT = $(shell git rev-parse --show-toplevel)
ANDROID ?= yes
TARGET ?= ""
TREE = $(shell cd $(ROOT) && git stash create "travis/docker testing")
ARCHIVE = $(ROOT)/travis/docker/pwntools.tar.gz

ifeq ($(strip $(TREE)),)
TREE = HEAD
endif

all: image
	docker run -e "ANDROID=$(ANDROID)" -e "TARGET=$(TARGET)" --rm --init --privileged -it travis

shell: image
	docker run --rm --init --privileged --entrypoint /bin/bash -it travis

image: $(ARCHIVE)
	docker build -t travis .

$(ARCHIVE): FORCE
	rm -f $@
	cd $(ROOT) && git archive $(TREE) -o $@

FORCE:
.PHONY: all image
