CC=musl-gcc-x86_32
CFLAGS=-Wall -std=c99 -D_POSIX_SOURCE
sysjs:	sysjs.o duktape.o
clean:
	rm -f *.o sysjs
