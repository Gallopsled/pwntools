
all: i386

i386: vuln.c
	gcc "$^" -fno-stack-protector -no-pie -m32 -o $@
