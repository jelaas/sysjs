/*
 * File: sysjs.c
 * Implements: javascript vm (duktape) with system extensions (syscalls mainly)
 *
 * Copyright: Jens Låås, 2014
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <stdio.h>
#include "duktape.h"
#include "sys1.h"

struct {
	int fd;
	char *buf;
	off_t size;
	int status;
	int argc;
	char **argv;
} prg;

int wrapped_compile_execute(duk_context *ctx) {
	int ret;

	duk_compile(ctx, 0);
	close(prg.fd);
	munmap(prg.buf, prg.size);
	
	duk_push_global_object(ctx);  /* 'this' binding */
	duk_call_method(ctx, 0);
	prg.status = duk_to_int(ctx, -1);
	duk_pop(ctx); // pop return value
	
	// Check if global property 'main' exists
	duk_push_global_object(ctx);
	ret = duk_get_prop_string(ctx, -1, "main");
	duk_remove(ctx, -2); // remove global object

	// If main exists we call it
	if(ret && duk_get_type(ctx, -1) != DUK_TYPE_UNDEFINED) {
		int i;
		
		duk_push_global_object(ctx);  /* 'this' binding */
		for(i=1;i<prg.argc;i++) {
			duk_push_string(ctx, prg.argv[i]);
		}
		duk_call_method(ctx, prg.argc-1);
		prg.status = duk_to_int(ctx, -1);
	}
	duk_pop(ctx);

	return 0; // no values returned (0)
}

static int get_stack_raw(duk_context *ctx) {
	if (!duk_is_object(ctx, -1)) {
		return 1;
	}
	if (!duk_has_prop_string(ctx, -1, "stack")) {
		return 1;
	}

	/* XXX: should check here that object is an Error instance too,
	 * i.e. 'stack' is special.
	 */

	duk_get_prop_string(ctx, -1, "stack");  /* caller coerces */
	duk_remove(ctx, -2);
	return 1;
}

/* Print error to stderr and pop error. */
static void print_error(duk_context *ctx, FILE *f) {
	/* Print error objects with a stack trace specially.
	 * Note that getting the stack trace may throw an error
	 * so this also needs to be safe call wrapped.
	 */
	(void) duk_safe_call(ctx, get_stack_raw, 1 /*nargs*/, 1 /*nrets*/);
	fprintf(f, "%s\n", duk_safe_to_string(ctx, -1));
	fflush(f);
	duk_pop(ctx);
}

int main(int argc, char *argv[]) {
	int i;
	
	prg.argc = argc;
	prg.argv = argv;

	duk_context *ctx = duk_create_heap_default();

	duk_push_global_object(ctx);
	duk_push_object(ctx);  /* -> [ ... global obj ] */
	sys1(ctx);
//	duk_put_function_list(ctx, -1, sys1_funcs);
//	duk_put_number_list(ctx, -1, sys1_consts);

	for(i=1;i<argc;i++) {
		duk_push_string(ctx, argv[i]);
		duk_put_prop_index(ctx, -2, i-1);
	}
	duk_push_number(ctx, argc-1);
	duk_put_prop_string(ctx, -2, "argc");

	duk_put_prop_string(ctx, -2, "Sys1");  /* -> [ ... global ] */

	duk_pop(ctx);

	{
		int rc;
		
		// read file argv[1]
		prg.fd = open(argv[1], O_RDONLY);
		if(prg.fd == -1) {
			exit(1);
		}
		prg.size = lseek(prg.fd, 0, SEEK_END);
		prg.buf = mmap((void*)0, prg.size, PROT_READ, MAP_PRIVATE, prg.fd, 0);
	
		if(*(prg.buf) == '#') {
			while(*(prg.buf) != '\n') {
				prg.buf++;
				prg.size--;
			}
		}
		
		// push file
		duk_push_lstring(ctx, prg.buf, prg.size);
		duk_push_string(ctx, argv[1]);
		
		// execute file (compile + call)
		rc = duk_safe_call(ctx, wrapped_compile_execute, 2 /*nargs*/, 1 /*nret*/);
		if (rc != DUK_EXEC_SUCCESS) {
			print_error(ctx, stderr);
			exit(2);
		}
		duk_pop(ctx);  /* pop eval result */
		
		duk_destroy_heap(ctx);
	}
	return prg.status;
}
