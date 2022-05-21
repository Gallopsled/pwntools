
all: i386 amd64

i386: vuln.c
	gcc "$^" -fno-stack-protector -no-pie -m32 -o $@

amd64: vuln.c
	gcc "$^" -fno-stack-protector -no-pie -o $@
