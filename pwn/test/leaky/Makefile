PROCESSOR=$(shell uname -p)

.phony: all clean x86_64 armv7l
executables=l_sysv_64 l_sysv_32 l_gnu_64 l_gnu_32 l_pie_sysv_64 l_pie_sysv_32 l_pie_gnu_64 l_pie_gnu_32
all: $(PROCESSOR)
clean:
	rm -f l_* *.so

#Targets for armv7l
armv7l: l_sysv_arm l_gnu_arm l_pie_sysv_arm l_pie_gnu_arm
libleaky_sysv_arm.so: leakylib.c
	$(CC) -shared -fPIC -Xlinker --hash-style=sysv -o $@ $^
libleaky_gnu_arm.so: leakylib.c
	$(CC) -shared -fPIC -Xlinker --hash-style=gnu -o $@ $^

l_pie_sysv_arm: leaky.c libleaky_sysv_arm.so
	$(CC) -pie -fPIC -Xlinker --hash-style=sysv -o $@ $^ -L . -lleaky_sysv_arm
l_pie_gnu_arm: leaky.c libleaky_gnu_arm.so
	$(CC) -pie -fPIC -Xlinker --hash-style=gnu -o $@ $^ -L . -lleaky_gnu_arm
l_sysv_arm: leaky.c libleaky_sysv_arm.so
	$(CC) -Xlinker --hash-style=sysv -o $@ $^ -L . -lleaky_sysv_arm
l_gnu_arm: leaky.c libleaky_gnu_arm.so
	$(CC) -Xlinker --hash-style=gnu -o $@ $^ -L . -lleaky_gnu_arm



#Targets for x86_64
x86_64: l_sysv_64 l_sysv_32 l_gnu_64 l_gnu_32 l_pie_sysv_64 l_pie_sysv_32 l_pie_gnu_64 l_pie_gnu_32
libleaky_sysv_64.so: leakylib.c
	$(CC) -shared -fPIC -Xlinker --hash-style=sysv -o $@ $^
libleaky_sysv_32.so: leakylib.c
	$(CC) -m32 -shared -fPIC -Xlinker --hash-style=sysv -o $@ $^
libleaky_gnu_64.so: leakylib.c
	$(CC) -shared -fPIC -Xlinker --hash-style=gnu -o $@ $^
libleaky_gnu_32.so: leakylib.c
	$(CC) -m32 -shared -fPIC -Xlinker --hash-style=gnu -o $@ $^

l_pie_sysv_64: leaky.c libleaky_sysv_64.so
	$(CC) -pie -fPIC -Xlinker --hash-style=sysv -o $@ $^ -L . -lleaky_sysv_64
l_pie_sysv_32: leaky.c libleaky_sysv_32.so
	$(CC) -m32 -pie -fPIC -Xlinker --hash-style=sysv -o $@ $^ -L . -lleaky_sysv_32
l_pie_gnu_64: leaky.c libleaky_gnu_64.so
	$(CC) -pie -fPIC -Xlinker --hash-style=gnu -o $@ $^ -L . -lleaky_gnu_64
l_pie_gnu_32: leaky.c libleaky_gnu_32.so
	$(CC) -m32 -pie -fPIC -Xlinker --hash-style=gnu -o $@ $^ -L . -lleaky_gnu_32

l_sysv_64: leaky.c libleaky_sysv_64.so
	$(CC) -Xlinker --hash-style=sysv -o $@ $^ -L . -lleaky_sysv_64
l_sysv_32: leaky.c libleaky_sysv_32.so
	$(CC) -m32 -Xlinker --hash-style=sysv -o $@ $^ -L . -lleaky_sysv_32
l_gnu_64: leaky.c libleaky_gnu_64.so
	$(CC) -Xlinker --hash-style=gnu -o $@ $^ -L . -lleaky_gnu_64
l_gnu_32: leaky.c libleaky_gnu_32.so
	$(CC) -m32 -Xlinker --hash-style=gnu -o $@ $^ -L . -lleaky_gnu_32
