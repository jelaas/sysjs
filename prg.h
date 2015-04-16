struct mod {
  char *buf;
  off_t size;
  char *name;
  struct mod *next;
};

struct prg {
  char *name;
  int fd;
  char *buf;
  off_t size;
  int status;
  int argc;
  char **argv;
  struct mod *main;
  struct mod *modules;
};

int prg_register(struct prg *prg);
int prg_wrapped_compile_execute(duk_context *ctx);
int prg_push_modsearch(duk_context *ctx);
int prg_parse_appfile(struct prg *prg);
