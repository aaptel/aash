#pragma once
#include <stdbool.h>
#include "dbg.h"

enum token_type {
	TOK_NONE = 0,
#include "parser.h"
	/* TODO: handle those in parser */
	TOK_ASSIGN       = 100,
};

/* Use to store tokens */
struct str {
	enum token_type type;
	/* for word tokens: */
	char *s;
	size_t size;
	size_t capa;
};


#define PUSH(base, array, val)						\
	do {								\
		void *p;						\
		if ((base)->size >= (base)->capa) {			\
			p = realloc((base)->array, (base)->capa+32);	\
			if (!p)						\
				E("oom");				\
			(base)->array = p;				\
			(base)->capa += 32;				\
		}							\
		(base)->array[(base)->size++] = val;			\
	} while(0)


struct cmd_redirect {
	struct stream_redirect {
		bool is_set;
		int stream;
		bool is_input;
		bool is_append;
		bool is_fd;
		union {
			int fd;
			struct str *fn;
		};
	} stdin, stdout, stderr;
};

void stream_redirect_init(struct stream_redirect *sr, struct str *mode, struct str *file);
void cmd_redirect_merge(struct cmd_redirect *c, struct stream_redirect *s);

struct expr {
	enum expr_type {
		EXPR_PROG,
		EXPR_AND,
		EXPR_OR,
		EXPR_SIMPLE_CMD,
		EXPR_PIPE,
		EXPR_NOT,
		EXPR_SUB,
	} type;
	bool run_in_bg;
	union {
		struct expr_sub {
			struct expr *expr;
			struct cmd_redirect redir;
		} sub;
		struct expr_not {
			struct expr *expr;
		} not;
		struct expr_and_or {
			struct expr *left;
			struct expr *right;
		} and_or;
		struct expr_pipe {
			struct expr *left;
			struct expr *right;
		} pipe;
		struct expr_simple_cmd {
			struct str **words;
			size_t size;
			size_t capa;
			struct cmd_redirect redir;
		} simple_cmd;
		struct prog {
			struct expr **cmds;
			size_t size;
			size_t capa;
		} prog;
	};
};

/* from parser.y */
struct str;
void * ParseAlloc(void * (*fun)(size_t));
void Parse(void *, int, struct str *, struct expr **);
void ParseFree(void *, void (*fun)(void *));

struct expr *expr_new(enum expr_type);
void expr_simple_cmd_add_word(struct expr *e, struct str *w);
