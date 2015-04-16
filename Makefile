CC=musl-gcc-x86_32
CFLAGS=-Wall -std=c99 -D_POSIX_SOURCE -D_GNU_SOURCE
all:	sysjs main stor
sysjs:	sysjs.o prg.o sys1.o duktape.o
main:	main.js test.js
	wc -c $^ > $@
	cat $^ >> $@
stor:	storage/main.js storage/content1
	wc -c $^ > $@
	cat $^ >> $@
clean:
	rm -f *.o sysjs
