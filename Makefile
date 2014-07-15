CC=musl-gcc-x86_32
CFLAGS=-Wall -std=c99 -D_POSIX_SOURCE -D_GNU_SOURCE
sysjs:	sysjs.o sys1.o duktape.o
clean:
	rm -f *.o sysjs
