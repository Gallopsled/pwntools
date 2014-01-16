.phony: all
executables=l_sysv_64 l_sysv_32 l_gnu_64 l_gnu_32
all: $(executables)

libleaky_sysv_64.so: leakylib.c
	$(CC) -shared -fPIC -Xlinker --hash-style=sysv -o $@ $^
libleaky_sysv_32.so: leakylib.c
	$(CC) -m32 -shared -fPIC -Xlinker --hash-style=sysv -o $@ $^
libleaky_gnu_64.so: leakylib.c
	$(CC) -shared -fPIC -Xlinker --hash-style=gnu -o $@ $^
libleaky_gnu_32.so: leakylib.c
	$(CC) -m32 -shared -fPIC -Xlinker --hash-style=gnu -o $@ $^

l_sysv_64: leaky.c libleaky_sysv_64.so
	$(CC) -pie -fPIC -Xlinker --hash-style=sysv -o $@ $^ -L . -lleaky_sysv_64
l_sysv_32: leaky.c libleaky_sysv_32.so
	$(CC) -m32 -pie -fPIC -Xlinker --hash-style=sysv -o $@ $^ -L . -lleaky_sysv_32
l_gnu_64: leaky.c libleaky_gnu_64.so
	$(CC) -pie -fPIC -Xlinker --hash-style=gnu -o $@ $^ -L . -lleaky_gnu_64
l_gnu_32: leaky.c libleaky_gnu_32.so
	$(CC) -m32 -pie -fPIC -Xlinker --hash-style=gnu -o $@ $^ -L . -lleaky_gnu_32
