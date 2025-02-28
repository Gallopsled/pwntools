ROOT=$(shell git rev-parse --show-toplevel)

all: generate.py functions.py
	python generate.py "$(ROOT)/pwnlib/shellcraft/templates/common/linux/syscalls"

functions.py:
	wget https://raw.githubusercontent.com/zachriggle/functions/master/functions.py

generate_darwin:
	python3 generate_darwin.py "$(ROOT)"

.phony: all
