ROOT=$(shell git rev-parse --show-toplevel)
TEMPLATE_DIR="$ROOT/pwnlib/shellcraft/templates/common/linux/syscalls"

all: generate.py functions.py
	python generate.py "$(ROOT)/pwnlib/shellcraft/templates/common/linux/syscalls"

functions.py:
	wget https://raw.githubusercontent.com/zachriggle/functions/master/functions.py

.phony: all
