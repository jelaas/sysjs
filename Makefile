CC=musl-gcc-x86_32
CFLAGS=-Wall -std=c99 -D_POSIX_SOURCE -D_GNU_SOURCE
all:	sysjs main
sysjs:	sysjs.o prg.o sys1.o duktape.o
main:	main.js test.js
	wc -c main.js	test.js > main
	cat main.js	test.js >> main
clean:
	rm -f *.o sysjs
