/*
 * File: prg.c
 * Implements: parsing javascript program aggregate
 *
 * Copyright: Jens Låås, 2015
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "duktape.h"
#include "prg.h"

static struct prg *prg_call;

int prg_register(struct prg *prg)
{
	prg_call = prg;
	return 0;
}

static struct mod *mod_new()
{
	struct mod *m;
	m = malloc(sizeof(struct mod));
	if(m) memset(m, 0, sizeof(struct mod));
	return m;
}

int prg_wrapped_compile_execute(duk_context *ctx) {
	int ret;
	struct prg *prg = prg_call;
      
	duk_compile(ctx, 0);
	close(prg->fd);
	munmap(prg->buf, prg->size);
	
	duk_push_global_object(ctx);  /* 'this' binding */
	duk_call_method(ctx, 0);
	prg->status = duk_to_int(ctx, -1);
	duk_pop(ctx); // pop return value
	
	// Check if global property 'main' exists
	duk_push_global_object(ctx);
	ret = duk_get_prop_string(ctx, -1, "main");
	duk_remove(ctx, -2); // remove global object
	
	// If main exists we call it
	if(ret && duk_get_type(ctx, -1) != DUK_TYPE_UNDEFINED) {
		int i;
		
		duk_push_global_object(ctx);  /* 'this' binding */
		for(i=1;i<prg->argc;i++) {
			duk_push_string(ctx, prg->argv[i]);
		}
		duk_call_method(ctx, prg->argc-1);
		prg->status = duk_to_int(ctx, -1);
	}
	duk_pop(ctx);

	return 0; // no values returned (0)
}

static int modSearch(duk_context *ctx)
{
	struct mod *mod;
	struct prg *prg;
	prg = prg_call;

	const char *id = duk_to_string(ctx, 0);
	for(mod=prg->modules;mod;mod=mod->next) {
		if(!strcmp(mod->name, id)) {
			duk_push_lstring(ctx, mod->buf, mod->size);
			return 1;
		}
	}
	duk_error(ctx, DUK_ERR_ERROR, "failed to find module '%s'", id);
	return DUK_RET_ERROR;
}


int prg_push_modsearch(duk_context *ctx)
{
	duk_get_prop_string(ctx, -1, "Duktape");
	duk_push_c_function(ctx, modSearch, 1);
	duk_put_prop_string(ctx, -2, "modSearch");
	duk_pop(ctx); // pop Duktape
	return 0;
}

int prg_parse_appfile(struct prg *prg)
{
	char *p, *endp, *start, *m, *mainstart;
	off_t offset, pa_offset;
	struct mod *mod;
	
	// read file prg->name
	prg->fd = open(prg->name, O_RDONLY);
	if(prg->fd == -1) {
		exit(1);
	}
	prg->size = lseek(prg->fd, 0, SEEK_END);
	prg->buf = mmap((void*)0, prg->size, PROT_READ, MAP_PRIVATE, prg->fd, 0);
	
	/* parse file header
	 */
	p = prg->buf;
	endp = prg->buf + prg->size;
	if(*p == '#') {
		while((p < endp) && (*p != '\n')) p++;
		if(p >= endp) {
			fprintf(stderr, "EOF\n");
			exit(1);
		}
		p++;
	}
	mainstart = p;
	mod = mod_new();
	for(start=p;p < endp;p++) {
		if(*p == '\n') {
			/* is this a module specification? */
			for(m = start; *m == ' '; m++);
			if((*m >= '0') && (*m <= '9')) {
				mod->size = strtoul(m, &m, 10);
				if(!m) break;
				if(*m != ' ') break;
				m++;
				mod->name = strndup(m, p-m);
				if(!strcmp(mod->name, "total"))
					break;
				mod->next = prg->modules;
				prg->modules = mod;
				mod = mod_new();
			} else
				break;
			start = p+1;
		}
	}
	offset = prg->size;
	for(mod = prg->modules; mod; mod=mod->next) {
		offset -= mod->size;
		pa_offset = offset & ~(sysconf(_SC_PAGE_SIZE) - 1);
		mod->buf = mmap((void*)0, mod->size + offset - pa_offset,
				PROT_READ, MAP_PRIVATE, prg->fd, pa_offset);
		if(mod->buf == MAP_FAILED) {
			fprintf(stderr, "mmap failed\n");
			exit(1);
		}
		mod->buf += (offset - pa_offset);
	}
	for(mod = prg->modules; mod; mod=mod->next) {
		char *p;
		if((p=strrchr(mod->name, '.'))) {
			*p=0;
		}
	}
	for(mod = prg->modules; mod; mod=mod->next) {
		if(!strcmp(mod->name, "main")) {
			prg->main = mod;
		} else {
			char *p;
			if((p=strrchr(mod->name, '/'))) {
				if(!strcmp(p+1, "main")) {
					prg->main = mod;
				}
			}
		}
	}
	if(!prg->modules) {
		prg->main = mod_new();
		prg->main->buf = mainstart;
		prg->main->size = prg->size - (mainstart - prg->buf);
		prg->main->name = "main";
	}
	if(!prg->main) {
		fprintf(stderr, "no main module\n");
		exit(1);
	}
	return 0;
}
