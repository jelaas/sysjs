CC=musl-gcc-x86_32
CFLAGS=-Wall -std=c99
sysjs:	sysjs.o duktape.o
clean:
	rm -f *.o sysjs
