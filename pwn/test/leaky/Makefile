.phony: all
all: l_sysv_64 l_sysv_32 l_gnu_64 l_gnu_32

l_sysv_64: leaky.c
	$(CC) -pie -fPIC -Xlinker --hash-style=sysv -o $@ $^
l_sysv_32: leaky.c
	$(CC) -m32 -pie -fPIC -Xlinker --hash-style=sysv -o $@ $^
l_gnu_64: leaky.c
	$(CC) -pie -fPIC -Xlinker --hash-style=gnu -o $@ $^
l_gnu_32: leaky.c
	$(CC) -m32 -pie -fPIC -Xlinker --hash-style=gnu -o $@ $^
