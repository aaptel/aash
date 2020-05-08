#pragma once

#include "dbg.h"

enum token_type {
	TOK_NONE = 0,
#include "parser.h"

	/* TODO: handle those in parser */
	TOK_REDIR_OUT    = 100,
	TOK_REDIR_IN     = 101,
	TOK_REDIR_APPEND = 102,
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
	union {
		struct expr_sub {
			struct expr *expr;
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
