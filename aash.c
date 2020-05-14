#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dbg.h"
#include "ast.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define FAILED(s) (!WIFEXITED(s) || WEXITSTATUS(s) != 0)
#define STATUS_TO_EXIT(s) (WIFEXITED(s) ? WEXITSTATUS(s) : 1)

#define MAX_VAR_NAME_SIZE 32
#define LOG_FILE "log.txt"

FILE *g_log = NULL;

void log_write(const char *format, ...)
{
	/*
	 * Need to be run at least once by main process so that forks
	 * can inherit it
	 */
	va_list args;

	if (!g_log) {
		g_log = fopen(LOG_FILE, "w+");
		if (!g_log)
			E("fopen");
	}

	va_start(args, format);
	vfprintf(g_log, format, args);
	va_end(args);

	fflush(g_log);
}

/*
 * Lexing
 */

struct input {
	enum input_type {
		INPUT_FILE,
		INPUT_STR,
	} type;
	union {
		FILE *fh;
		struct {
			const char *s;
			const char *start;
			size_t len;
		};
	};
	bool eof;
	size_t nb_eof;
};

void in_ungetc(struct input *in, int c)
{
	if (c == EOF) {
		if (in->eof) {
			if (in->nb_eof) {
				in->nb_eof--;
				return;
			}
			in->eof = false;
		} else {
			E("unexpected ungetc EOF");
		}
	}
	if (in->type == INPUT_FILE) {
		int r = ungetc(c, in->fh);
		assert(r != EOF);
	} else {
		assert(in->s > in->start);
		in->s--;
	}
}

int in_getc(struct input *in)
{
	int c;

	if (in->eof) {
		c = EOF;
		in->nb_eof++;
	} else {
		if (in->type == INPUT_FILE)
			c = fgetc(in->fh);
		else {
			if (in->s >= in->start + in->len)
				c = EOF;
			else
				c = *in->s++;
		}
		if (c == EOF)
			in->eof = true;
	}

	return c;
}

struct str *str_new(void)
{
	struct str *str = calloc(sizeof(*str), 1);
	if (!str)
		E("oom");
	return str;
}

void str_free(struct str *str)
{
	if (!str)
		return;
	free(str->s);
	free(str);
}

void str_push(struct str *str, char c)
{
	int new_capa = str->capa < 10 ? 10 : str->capa*2;

	/* always keep one null at the end */
	if (str->size+1 >= str->capa) {
		char *p = realloc(str->s, new_capa);
		if (!p)
			E("oom");
		str->s = p;
		str->capa = new_capa;
		memset(str->s+str->size, 0, str->capa-str->size);
	}

	str->s[str->size++] = c;
}

void read_comment(struct input *in) {
	int c;
	while ((c = in_getc(in)) != EOF) {
		if (c == '\n')
			return;
	}
}

bool is_all_digits(const char *s)
{
	for (; s && *s; s++)
		if (!isdigit(*s))
			return false;

	return true;
}
bool is_word_all_digits(struct str *w)
{
	return is_all_digits(w->s);
}


const char *token_to_string(struct str *);
struct str *read_token_raw(struct input *in);
struct str *read_token(struct input *in, enum token_type *last_tok)
{
	struct str *tok = read_token_raw(in);

	if (tok->type != TOK_WORD)
		goto out;

	/*
	 * Current token is a word but is it special?
	 */
	switch (*last_tok) {
	case TOK_WORD:
		/* if last token was a non-special word, remaining words are normal */
		break;
	case TOK_FOR:
		/* "for" expects a variable name */
		tok->type = TOK_NAME;
		break;
	case TOK_NAME:
		/* "for" NAME "in": we expect a IN word here */
		if (strcmp(tok->s, "in") == 0)
			tok->type = TOK_IN;
		break;
	case TOK_ASSIGN:
		/* a sequence of assign can occur in "a=1 b=2 cmd arg..." */
		if (strchr(tok->s, '='))
			tok->type = TOK_ASSIGN;
	default:
		/* otherwise we are starting a command, look for special word */
		if      (strcmp(tok->s, "for")  == 0) tok->type = TOK_FOR;
		else if (strcmp(tok->s, "in")   == 0) tok->type = TOK_IN;
		else if (strcmp(tok->s, "do")   == 0) tok->type = TOK_DO;
		else if (strcmp(tok->s, "done") == 0) tok->type = TOK_DONE;
		else if (strcmp(tok->s, "function") == 0) tok->type = TOK_FUNCTION;
		else if (strcmp(tok->s, "if")   == 0) tok->type = TOK_IF;
		else if (strcmp(tok->s, "then") == 0) tok->type = TOK_THEN;
		else if (strcmp(tok->s, "elif") == 0) tok->type = TOK_ELIF;
		else if (strcmp(tok->s, "else") == 0) tok->type = TOK_ELSE;
		else if (strcmp(tok->s, "fi")   == 0) tok->type = TOK_FI;


		/* first word with '=' is an assign */
		else if (strchr(tok->s, '=')) tok->type = TOK_ASSIGN;
	}

 out:
	*last_tok = tok->type;
	return tok;
}

void read_word_subshell(struct input *in, struct str *output)
{
	struct str *tok;
	int rparen_left = 1;
	const char *s;
	enum token_type last_tok = TOK_NONE;

	while (1) {
		tok = read_token(in, &last_tok);
		str_push(output, ' ');
		for (s = token_to_string(tok); *s; s++)
			str_push(output, *s);

		if (tok->type == TOK_LPAREN)
			rparen_left++;
		else if (tok->type == TOK_RPAREN) {
			rparen_left--;
			if (rparen_left == 0)
				break;
		}
		else if (tok->type == TOK_NONE) {
			break;
		}

		str_free(tok);
	}

	str_free(tok);
}

struct str *read_word(struct input *in, struct str *tok)
{
	int in_quote = 0;
	int c;
	int c2;

	tok->type = TOK_WORD;

	while ((c = in_getc(in)) != EOF) {
		if (in_quote) {
			if (c == in_quote) {
				in_quote = 0;
			}
			else if (c == '$') {
				c2 = in_getc(in);
				if (c2 == EOF) {
					str_push(tok, c);
					goto out;
				}
				if (in_quote == '"' && c2 == '(') {
					str_push(tok, c);
					str_push(tok, c2);
					read_word_subshell(in, tok);
					continue;
				}
				str_push(tok, c);
				str_push(tok, c2);
				continue;
			}
			else if (c == '\\') {
				c2 = in_getc(in);
				if (c2 == EOF) {
					str_push(tok, c);
					goto out;
				}
				if (c2 == '\n') // line continuation
					continue;
				c = c2;
			}
			str_push(tok, c);
			continue;
		} else {
			if (c == '\\') {
				c2 = in_getc(in);
				if (c2 == EOF) {
					str_push(tok, c);
					goto out;
				}
				if (c2 == '\n') // line continuation
					continue;
				str_push(tok, c2);
				continue;
			}

			if (c == '$') {
				c2 = in_getc(in);
				if (c2 == EOF) {
					str_push(tok, c);
					goto out;
				}
				if (c2 == '(') {
					str_push(tok, c);
					str_push(tok, c2);
					read_word_subshell(in, tok);
					continue;
				}
				str_push(tok, c);
				str_push(tok, c2);
				continue;
			}

			if (strchr("#|&><!()\n\t ;", c)) {
				if (c == '>' && is_word_all_digits(tok)) {
					tok->type = TOK_IO_NUMBER;
				}
				in_ungetc(in, c);
				goto out;
			}
			if (strchr("`\"'", c)) {
				in_quote = c;
			}
			str_push(tok, c);
		}
	}
 out:
	return tok;
}

#define READ_DOUBLE_OP(op2, tok1, tok2)		\
	do {					\
		c2 = in_getc(in);		\
		if (c2 == op2) {		\
			tok->type = tok2;	\
		} else {			\
			tok->type = tok1;	\
			if (c2 == EOF)		\
				goto eof;	\
			in_ungetc(in, c2);	\
			goto out;		\
		}				\
	} while (0)

struct str *read_token_raw(struct input *in)
{
	int c;
	int c2;
	struct str *tok = str_new();

	while (1) {
	next_char:
		switch (c = in_getc(in)) {
		eof:
		case EOF:
			tok->type = TOK_NONE;
			goto out;
		case '{':
			tok->type = TOK_LBRACE;
			goto out;
		case '}':
			tok->type = TOK_RBRACE;
			goto out;
		case '#':
			read_comment(in);
			break;
		case '|':
			READ_DOUBLE_OP('|', TOK_PIPE, TOK_OR);
			goto out;
		case '&':
			READ_DOUBLE_OP('&', TOK_BG, TOK_AND);
			goto out;
		case '>':
			c2 = in_getc(in);
			if (c2 == '>')
				tok->type = TOK_REDIR_APPEND;
			else if (c2 == '&')
				tok->type = TOK_REDIR_FD;
			else {
				tok->type = TOK_REDIR_OUT;
				in_ungetc(in, c2);
			}
			goto out;
		case '<':
			tok->type = TOK_REDIR_IN;
			goto out;
		case '!':
			tok->type = TOK_NOT;
			goto out;
		case '(':
			tok->type = TOK_LPAREN;
			goto out;
		case ')':
			tok->type = TOK_RPAREN;
			goto out;
		case '\n':
			tok->type = TOK_NEWLINE;
			goto out;
		case ';':
			tok->type = TOK_SEMICOL;
			goto out;
		case ' ':
		case '\t':
			goto next_char;
		default:
			/* WORD and quoted strings */
			in_ungetc(in, c);
			read_word(in, tok);
			goto out;
		}
	}
 out:
	return tok;
}

struct expr *expr_new(enum expr_type type)
{
	struct expr *expr = calloc(1, sizeof(*expr));
	expr->type = type;
	return expr;
}

const char *token_to_string(struct str *tok)
{
	switch (tok->type) {
	case TOK_NONE: return "";
	case TOK_NEWLINE: return "\n";
	case TOK_SEMICOL: return ";";
	case TOK_WORD: return tok->s;
	case TOK_PIPE: return "|";
	case TOK_OR: return "||";
	case TOK_AND: return "&&";
	case TOK_NOT: return "!";
	case TOK_REDIR_OUT: return ">";
	case TOK_REDIR_IN: return "<";
	case TOK_REDIR_APPEND: return ">>";
	case TOK_REDIR_FD: return ">&";
	case TOK_BG: return "&";
	case TOK_LPAREN: return "(";
	case TOK_RPAREN: return ")";
	case TOK_LBRACE: return "{";
	case TOK_RBRACE: return "}";
	case TOK_IO_NUMBER: return tok->s;
	case TOK_ASSIGN: return tok->s;
	case TOK_FOR: return "for";
	case TOK_IN: return "in";
	case TOK_DO: return "do";
	case TOK_DONE: return "done";
	case TOK_FUNCTION: return "function";
	case TOK_IF: return "if";
	case TOK_THEN: return "then";
	case TOK_ELIF: return "elif";
	case TOK_ELSE: return "else";
	case TOK_FI: return "fi";
	default: return "))UNKNOWN TOKEN((";
	}
}

void dump_token(struct str *tok)
{
	switch (tok->type) {
	case TOK_NONE: puts("NONE"); break;
	case TOK_NEWLINE: puts("NEWLINE"); break;
	case TOK_SEMICOL: puts("SEMICOL ;"); break;
	case TOK_WORD: printf("WORD <%s>\n", tok->s); break;
	case TOK_PIPE: puts("PIPE"); break;
	case TOK_OR: puts("OR"); break;
	case TOK_AND: puts("AND"); break;
	case TOK_NOT: puts("NOT"); break;
	case TOK_REDIR_OUT: puts("REDIR >"); break;
	case TOK_REDIR_IN: puts("REDIR <"); break;
	case TOK_REDIR_APPEND: puts("APPEND >>"); break;
	case TOK_REDIR_FD: puts("REDIR_FD >&"); break;
	case TOK_BG: puts("BG &"); break;
	case TOK_LPAREN: puts("LPAREN ("); break;
	case TOK_RPAREN: puts("RPAREN )"); break;
	case TOK_LBRACE: puts("LBRACE {"); break;
	case TOK_RBRACE: puts("RBRACE }"); break;
	case TOK_IO_NUMBER: printf("IO_NUMBER %s\n", tok->s); break;
	case TOK_ASSIGN: puts("IO_ASSIGN"); break;
	case TOK_FOR: puts("FOR"); break;
	case TOK_IN: puts("IN"); break;
	case TOK_DO: puts("DO"); break;
	case TOK_DONE: puts("DONE"); break;
	case TOK_FUNCTION: puts("FUNCTION"); break;
        case TOK_IF: puts("IF"); break;
        case TOK_THEN: puts("THEN"); break;
        case TOK_ELIF: puts("ELIF"); break;
        case TOK_ELSE: puts("ELSE"); break;
        case TOK_FI: puts("FI"); break;
	default: puts("???"); break;
	}
}

void expr_simple_cmd_add_word(struct expr *e, struct str *w)
{
	struct expr_simple_cmd *c = &e->simple_cmd;
	/*
	 * if we are adding the first word or if we only added
	 * assignment words and the word is an assignement, make it an
	 * assignement
	 */
	if ((c->size == 0 || c->words[c->size-1]->type == TOK_ASSIGN) && strchr(w->s, '=')) {
		w->type = TOK_ASSIGN;
	}
	PUSH(c, words, w);
}

void indent(int n)
{
	int i;
	for (i = 0; i < n; i++)
		printf("  ");
}

#define IND_PRINT(n, fmt, ...) indent(n), printf(fmt, ##__VA_ARGS__)
#define DUMP_BINARY(n, e, name, field)				\
	do {							\
		IND_PRINT(n, "%s {\n", name);			\
		IND_PRINT(n+1, "left {\n");			\
		dump_expr(e->field.left, n+2, graphviz);	\
		IND_PRINT(n+1, "}\n");				\
		IND_PRINT(n+1, "right {\n");			\
		dump_expr(e->field.right, n+2, graphviz);	\
		IND_PRINT(n+1, "}\n");				\
		IND_PRINT(n, "}\n");				\
	} while (0)


void dump_cmd_redirect(struct cmd_redirect *c)
{
	printf("REDIR ");
	if (c->stdin.is_set) {
		assert(!c->stdin.is_fd);
		printf("stdin=%s ", c->stdin.fn->s);
	}
	if (c->stdout.is_set) {
		printf("stdout=");
		if (c->stdout.is_fd)
			printf("fd%d ", c->stdout.fd);
		else
			printf("fn<%s> ", c->stdout.fn->s);
	}
	if (c->stderr.is_set) {
		printf("stderr=");
		if (c->stderr.is_fd)
			printf("fd%d ", c->stderr.fd);
		else
			printf("fn<%s> ", c->stderr.fn->s);
	}
}

void dump_expr(struct expr *e, int n, bool graphviz)
{
	int i;

	if (!e) {
		IND_PRINT(n, "NULL EXPR\n");
		return;
	}

	if (e->run_in_bg) { IND_PRINT(n, "(in bg) "); }
	switch (e->type) {
	case EXPR_PROG:
		IND_PRINT(n, "PROG {\n");
		for (i = 0; i < e->prog.size; i++)
			dump_expr(e->prog.cmds[i], n+1, graphviz);
		IND_PRINT(n, "}\n");
		break;
	case EXPR_AND:
		DUMP_BINARY(n, e, "AND", and_or);
		break;
	case EXPR_OR:
		DUMP_BINARY(n, e, "OR", and_or);
		break;
	case EXPR_PIPE:
		DUMP_BINARY(n, e, "PIPE", pipe);
		break;
	case EXPR_SIMPLE_CMD:
		IND_PRINT(n, "CMD ");
		for (i = 0; i < e->simple_cmd.size; i++)
			printf("<%s> ", e->simple_cmd.words[i]->s);
		dump_cmd_redirect(&e->simple_cmd.redir);
		putchar('\n');
		break;
	case EXPR_NOT:
		IND_PRINT(n, "NOT {\n");
		dump_expr(e->not.expr, n+1, graphviz);
		IND_PRINT(n, "}\n");
		break;
	case EXPR_SUB:
		IND_PRINT(n, "SUBSHELL ");
		dump_cmd_redirect(&e->sub.redir);
		printf(" {\n");
		dump_expr(e->sub.expr, n+1, graphviz);
		IND_PRINT(n, "}\n");
		break;
	case EXPR_FOR:
		IND_PRINT(n, "FOR %s IN ", e->efor.name->s);
		for (i = 0; i < e->efor.size; i++)
			printf("<%s> ", e->efor.words[i]->s);
		printf("{\n");
		dump_expr(e->efor.body, n+1, graphviz);
		IND_PRINT(n, "}\n");
		break;
	case EXPR_FUNCTION:
		IND_PRINT(n, "FUNCTION %s {", e->func.name->s);
		dump_expr(e->func.body, n+1, graphviz);
		IND_PRINT(n, "}\n");
		break;
	case EXPR_IF:
		IND_PRINT(n, "IF {\n");
		IND_PRINT(n+1, "TEST {\n");
		dump_expr(e->eif.test, n+2, graphviz);
		IND_PRINT(n+1, "}\n");
		IND_PRINT(n+1, "THEN {\n");
		dump_expr(e->eif.xthen, n+2, graphviz);
		IND_PRINT(n+1, "}\n");
		IND_PRINT(n+1, "ELSE {\n");
		dump_expr(e->eif.xelse, n+2, graphviz);
		IND_PRINT(n+1, "}\n");
		IND_PRINT(n, "}\n");
		break;
	default:
		IND_PRINT(n, "UNKNOWN TYPE %d\n", e->type);
		break;
	}
}

void stream_redirect_init(struct stream_redirect *sr, struct str *mode, struct str *file)
{
	memset(sr, 0, sizeof(*sr));
	sr->is_set = true;
	switch (mode->type) {
	case TOK_REDIR_APPEND:
		sr->is_append = true;
		sr->fn = file;
		break;
	case TOK_REDIR_OUT:
		sr->fn = file;
		break;
	case TOK_REDIR_IN:
		sr->is_input = true;
		sr->stream = 0;
		sr->fn = file;
		break;
	case TOK_REDIR_FD:
		sr->is_fd = true;
		sr->fd = atoi(file->s);
		break;
	default:
		E("unknown mode");
	}
}

void cmd_redirect_merge(struct cmd_redirect *c, struct stream_redirect *s)
{
	assert(s->is_set);

	switch (s->stream) {
	case 0:
		c->stdin = *s;
		break;
	case 1:
		c->stdout = *s;
		break;
	case 2:
		c->stderr = *s;
		break;
	default:
		E("cannot handle stream %d", s->stream);
	}
}

/* merge other into c */
void simple_cmd_merge(struct expr_simple_cmd *c, struct expr_simple_cmd *other)
{
	int i;
	for (i = 0; i < other->size; i++) {
		PUSH(c, words, other->words[i]);
		other->words[i] = NULL;
	}
	if (other->redir.stdin.is_set)
		c->redir.stdin = other->redir.stdin;
	if (other->redir.stdout.is_set)
		c->redir.stdout = other->redir.stdout;
	if (other->redir.stderr.is_set)
		c->redir.stderr = other->redir.stderr;
}

struct exec_result {
	int status;
	pid_t pid;
};

struct exec_context {
	pid_t *bg_jobs;
	size_t size;
	size_t capa;

	/* globals */
	struct vars {
		struct var_binding {
			char *name;
			char *value;
		} *bindings;
		size_t size;
		size_t capa;
	} vars;

	/* stack of var tables */
	struct func_vars {
		struct vars *stack;
		size_t size;
		size_t capa;
	} func_vars;

	struct funcs {
		struct func_binding {
			char *name;
			struct expr *func;
		} *bindings;
		size_t size;
		size_t capa;
	} funcs;
};

bool is_func_var(const char *s)
{
	/*
	 * $0 is global
	 * $<n> are func vars
	 * $@, $*, $# are func vars
	 */
	if (strcmp(s, "0") == 0)
		return false;
	if (is_all_digits(s))
		return true;
	if (strlen(s) != 1)
		return false;
	return strchr("@*#", *s);
}

void exec_expr(struct expr *e, struct exec_context *ctx, struct exec_result *res);

struct vars *exec_get_func_vars(struct exec_context *exec)
{
	if (exec->func_vars.size == 0) {
		PUSH(&exec->func_vars, stack,  (struct vars){0});
	}
	return &exec->func_vars.stack[exec->func_vars.size-1];
}

struct var_binding *exec_get_var_binding(struct exec_context *exec, const char *name)
{
	int i;
	struct vars *vars;
	struct var_binding *v;

	if (!name || !*name) {
		L("trying to get null var");
		return NULL;
	}

	L("name=<%s>", name);

	vars = is_func_var(name) ? exec_get_func_vars(exec) : &exec->vars;
	for (i = 0; i < vars->size; i++) {
		v = &vars->bindings[i];
		if (v->name && strcmp(name, v->name) == 0)
			return v;
	}

	return NULL;
}

void exec_set_var_binding(struct exec_context *exec, const char *name, const char *val)
{
	struct var_binding *v;
	struct vars *vars;

	if (!name || !*name) {
		L("trying to set null var");
		return;
	}

	if (!val || !*val) {
		L("null val for var <%s>", name);
		return;
	}

	L("name=<%s> val=<%s>", name, val);

	vars = is_func_var(name) ? exec_get_func_vars(exec) : &exec->vars;
	v = exec_get_var_binding(exec, name);
	if (v) {
		free(v->value);
		v->value = strdup(val);
		return;
	}

	struct var_binding newv = {
		.name = strdup(name),
		.value = strdup(val),
	};

	PUSH(vars, bindings, newv);
}

void exec_push_func_vars(struct exec_context *exec)
{
	PUSH(&exec->func_vars, stack, (struct vars){0});
}

void exec_pop_func_vars(struct exec_context *exec)
{
	struct vars *top;
	int i;

	assert(exec->func_vars.size > 0);

	/* free top of func vars stack */
	top = exec_get_func_vars(exec);
	for (i = 0; i < top->size; i++) {
		free(top->bindings[i].name);
		free(top->bindings[i].value);
	}
	free(top->bindings);

	exec->func_vars.size--;
}

void exec_set_func_binding(struct exec_context *exec, const char *name, struct expr *func)
{
	int i;

	for (i = 0; i < exec->funcs.size; i++) {
		struct func_binding *v = &exec->funcs.bindings[i];
		if (strcmp(name, v->name) == 0) {
			// TODO free/duplicate expr
			v->func = func;
			return;
		}
	}

	struct func_binding newv = {
		.name = strdup(name),
		.func = func, // TODO duplicate expr?
	};

	PUSH(&exec->funcs, bindings, newv);
}

struct expr *exec_find_func(struct exec_context *exec, const char *name)
{
	int i;
	for (i = 0; i < exec->funcs.size; i++) {
		struct func_binding *v = &exec->funcs.bindings[i];
		if (strcmp(name, v->name) == 0)
			return v->func;
	}
	return NULL;
}

/*
 * Shell builtins
 */

typedef int (*builtin_func_t) (struct expr_simple_cmd *, struct exec_context *, struct exec_result *);

int builtin_wait(struct expr_simple_cmd *cmd, struct exec_context *ctx, struct exec_result *res)
{
	pid_t rc, pid;

	/* wait last created pid */

	if (ctx->size == 0) {
		res->status = 1;
		return 1;
	}

	pid = ctx->bg_jobs[ctx->size-1];
	rc = waitpid(pid, &res->status, 0);
	if (rc < 0)
		return 1;

	return 0;
}

struct {
	const char *name;
	builtin_func_t func;
} g_builtins[] = {
	{"wait", builtin_wait},
};

builtin_func_t builtin_find(const char *name)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(g_builtins); i++) {
		if (strcmp(name, g_builtins[i].name) == 0)
			return g_builtins[i].func;
	}
	return NULL;
}

/*
 * String expansion and re-parsing... shell is fucked up
 */

struct expand_context {
	struct str **words;
	size_t size;
	size_t capa;
	size_t total_added;
	int in_quote;
	bool new_word_on_next_push;
};

const char* read_var(const char *start, char *name)
{
	const char *s = start;
	char *out = name;
	bool in_brace = false;

	if (*s == '{') {
		in_brace = true;
		s++;
	}
	if (strchr("#$!?", *s)) {
		*out++ = *s++;
		if (in_brace && *s && *s == '}')
			s++;
		goto out;
	}
	for (; *s; s++) {
		if (in_brace) {
			if (*s == '}')
				goto out;
		}
		else {

			if (!(*s == '_' || isalnum(*s))) {
				s--;
				goto out;
			}
		}
		if ((out-name)+1 < MAX_VAR_NAME_SIZE)
			*out++ = *s;
		else
			goto out;

	}
 out:
	*out = '\0';
	return *s ? s : s-1;
}

void expand_push(struct expand_context *exp, char c)
{
	if (exp->size == 0 || exp->new_word_on_next_push) {
		PUSH(exp, words, str_new());
		exp->new_word_on_next_push = false;
	}

	str_push(exp->words[exp->size-1], c);
	exp->total_added++;
}

void expand_next_word(struct expand_context *exp)
{
	if (exp->new_word_on_next_push) {
		PUSH(exp, words, str_new());
		exp->new_word_on_next_push = false;
	} else {
		exp->new_word_on_next_push = true;
	}
}

void expand_push_var(struct exec_context *exec, struct expand_context *exp, const char *var)
{
	const char *s;
	struct var_binding *v = exec_get_var_binding(exec, var);
	if (!v)
		return;

	for (s = v->value; s && *s; s++) {
		if (exp->in_quote)
			expand_push(exp, *s);
		else {
			if (strchr(" \n\t", *s))
				expand_next_word(exp);
			else
				expand_push(exp, *s);
		}
	}
}

const char* expand_push_subshell(struct exec_context *exec, struct expand_context *expd, const char *s)
{
	struct expr *root;
	void *parser;
	const char *end;
	struct str *tok;
	struct str *output;
	int rparen_left;
	pid_t pid, rcpid;
	int rc, status;
	int pipefd[2];
	int i;
	enum token_type last_tok = TOK_NONE;

	struct input in = {
		.type = INPUT_STR,
		.start = s,
		.s = s,
		.len = strlen(s),
	};

	L("s=<%s>", s);

	/*
	 * Read all tokens until parens are balanced or we reach end
	 * of the word
	 */

	rparen_left = 1;
	parser = ParseAlloc(malloc);
	while (1) {
		tok = read_token(&in, &last_tok);
		if (tok->type == TOK_LPAREN)
			rparen_left++;
		else if (tok->type == TOK_RPAREN) {
			rparen_left--;
			if (rparen_left == 0)
				break;
		}
		else if (tok->type == TOK_NONE) {
			break;
		}

		Parse(parser, tok->type, tok, &root);
	}

	/* end points to next char after final ), or EOF */
	end = in.s-1;

	/*
	 * Parse subshell
	 */

	Parse(parser, TOK_NONE, NULL, &root);
	ParseFree(parser, free);

	/*
	 * Execute it in subprocess and capture output
	 */

	rc = pipe(pipefd);
	if (rc < 0)
		E("pipe");

	pid = fork();
	if (pid < 0)
		E("fork");

	if (pid == 0) {
		/* child */
		struct exec_context sub_exec = {0};
		struct exec_result sub_res = {0};

		L("in child");
		close(pipefd[0]);
		dup2(pipefd[1], 1);
		exec_expr(root, &sub_exec, &sub_res);
		exit(STATUS_TO_EXIT(sub_res.status));
	}

	close(pipefd[1]);
	output = str_new();
	while (1) {
		char buf[128];
		ssize_t nread;

		nread = read(pipefd[0], buf, sizeof(buf));
		if (nread < 0) {
			perror("read");
			E("read");
		}
		if (nread == 0)
			break;
		for (i = 0; i < nread; i++) {
			str_push(output, buf[i]);
		}
	}

	rcpid = waitpid(pid, &status, 0);
	if (rcpid < 0)
		E("waitpid");


	// remove trailing whilespace
	for (i = output->size-1; i >= 0 && isspace(output->s[i]); i--)
		output->size--;

	L("output=<%.*s>", output->size, output->s);

	// push output
	for (i = 0; i < output->size; i++) {
		char c = output->s[i];
		if (!expd->in_quote && isspace(c))
			expand_next_word(expd);
		else
			expand_push(expd, c);
	}

	// TODO: free tokens and exprs

	return end;
}

void exec_expand(struct exec_context *exec, struct expand_context *exp, struct str *in)
{
	const char *s = in->s;
	bool contained_quotes = false;
	size_t added_at_start = exp->total_added;

	exp->in_quote = 0;

	for (s = in->s; *s; s++) {
		char c = *s, c2 = *(s+1);

		if (exp->in_quote) {
			contained_quotes = true;

			if (c == exp->in_quote) {
				exp->in_quote = 0;
				continue;
			}
			if (c == '\\') {
				if (!c2) {
					expand_push(exp, c);
					goto out;
				}
				expand_push(exp, c2);
				s++;
				continue;
			}
			if (exp->in_quote == '"' && c == '$') {
				if (strchr("$!?{_#*", c2) || isalnum(c2)) {
					char var_name[MAX_VAR_NAME_SIZE];

					s = read_var(s+1, var_name);
					expand_push_var(exec, exp, var_name);
					continue;
				}
				if (c2 == '(') {
					 s = expand_push_subshell(exec, exp, s+2);
					 continue;
				}
			}
			expand_push(exp, c);
		} else {
			if (strchr("\"'", c)) {
				exp->in_quote = c;
				continue;
			}
			if (c == '\\') {
				if (!c2) {
					expand_push(exp, c);
					goto out;
				}
				expand_push(exp, c2);
				s++;
				continue;
			}
			if (c == '$') {
				if (strchr("$!?{_#*", c2) || isalnum(c2)) {
					char var_name[MAX_VAR_NAME_SIZE];

					s = read_var(s+1, var_name);
					expand_push_var(exec, exp, var_name);
					continue;
				}
				if (c2 == '(') {
					 s = expand_push_subshell(exec, exp, s+2);
					 continue;
				}
			}
			expand_push(exp, c);
		}
	}
 out:
	if (contained_quotes && exp->total_added - added_at_start == 0)
		expand_next_word(exp);
	return;
}

void expand_words(struct expand_context *expd, struct exec_context *exec, struct str **ws, size_t nb)
{
	int i;

	for (i = 0; i < nb; i++) {
		struct str *w = ws[i];
		// discard assignements
		assert(w->type == TOK_WORD);
		exec_expand(exec, expd, w);
		if (i < nb-1)
			expand_next_word(expd);
	}
}

/*
 * Execution
 */

void exec_apply_redir(struct cmd_redirect *c)
{
	if (c->stdin.is_set) {
		int new_stdin;
		assert(!c->stdin.is_fd);
		new_stdin = open(c->stdin.fn->s, O_RDONLY);
		if (new_stdin < 0)
			E("open");
		dup2(new_stdin, 0);
	}
	if (c->stdout.is_set) {
		int new_stdout;
		if (c->stdout.is_fd) {
			new_stdout = c->stdout.fd;
		} else {
			new_stdout = open(c->stdout.fn->s,
					  O_WRONLY
					  | O_CREAT
					  | (c->stdout.is_append ? O_APPEND : 0),
					  0644);
			if (new_stdout < 0)
				E("open");
		}
		dup2(new_stdout, 1);
	}
	if (c->stderr.is_set) {
		int new_stderr;
		if (c->stderr.is_fd) {
			new_stderr = c->stderr.fd;
		} else {
			new_stderr = open(c->stderr.fn->s,
					  O_WRONLY
					  | O_CREAT
					  | (c->stderr.is_append ? O_APPEND : 0),
					  0644);
			if (new_stderr < 0)
				E("open");
		}
		dup2(new_stderr, 2);
	}
}

void exec_assign(struct exec_context *exec, struct str *w)
{
	struct expand_context expd = {0};
	struct str tmp = {0};
	struct str *expanded;
	char name[MAX_VAR_NAME_SIZE] = {0};
	char *value;
	char *eq;
	int i, j;

	/* extract name & value ptr */
	eq = strchr(w->s, '=');
	assert(eq);
	value = eq+1;
	memcpy(name, w->s, eq - w->s);

	/* expand value */
	tmp.s = value;
	tmp.size = strlen(value);
	exec_expand(exec, &expd, &tmp);

	/* generate expanded struct str */
	expanded = str_new();
	int added = 0;
	for (i = 0; i < expd.size; i++) {
		if (added) {
			str_push(expanded, ' ');
			added = 0;
		}
		for (j = 0; j < expd.words[i]->size; j++) {
			str_push(expanded, expd.words[i]->s[j]);
			added++;
		}
	}

	/* store var */
	exec_set_var_binding(exec, name, expanded->s);

	/* done */
	str_free(expanded);
	FREE_ARRAY(&expd, words, str_free);
}

void exec_cmd(struct expr *expr, struct exec_context *exec)
{
	struct expand_context expd = {0};
	int i;

	/*
	 * We are in the child and about to exec, no need to worry
	 * about freeing memory
	 */

	expand_words(&expd, exec, expr->simple_cmd.words, expr->simple_cmd.size);

	L("");
	char **argv = calloc(sizeof(*argv), expd.size+1);
	for (i = 0; i < expd.size; i++) {
		argv[i] = expd.words[i]->s;
		if (!argv[i])
			argv[i] = "";
		L("exec argv[%2d] = <%s>", i, argv[i]);
	}
	exec_apply_redir(&expr->simple_cmd.redir);
	execvp(argv[0], argv);
	exit(1);
}

void exec_func_call(struct exec_context *exec, struct expr *func, struct expr *e, struct exec_result *res)
{	struct expr_simple_cmd *cmd = &e->simple_cmd;
	char buf[MAX_VAR_NAME_SIZE] = {0};
	struct expand_context expd = {0};
	int i;
	int rc;

	expand_words(&expd, exec, cmd->words, cmd->size);

	/*
	 * Push new var bindings for position arguments
	 */
	exec_push_func_vars(exec);

	for (i = 1; i < expd.size; i++) {
		rc = snprintf(buf, sizeof(buf), "%d", i);
		if (rc > sizeof(buf)) {
			buf[sizeof(buf)-1] = 0;
			L("truncated var name %d => <%s>", i, buf);
		}
		exec_set_var_binding(exec, buf, expd.words[i]->s);
	}
	rc = snprintf(buf, sizeof(buf), "%zu", expd.size-1);
	if (rc > sizeof(buf))
		buf[sizeof(buf)-1] = 0;
	exec_set_var_binding(exec, "#", buf);

	exec_expr(func->func.body, exec, res);

	/*
	 * Pop positional arguments
	 */
	exec_pop_func_vars(exec);

	FREE_ARRAY(&expd, words, str_free);
}

void exec_expr(struct expr *e, struct exec_context *ctx, struct exec_result *res)
{
	int i;
	pid_t rcpid, bg_pid;
	int rc;
	builtin_func_t builtin;
	struct expr *func;

	assert(e);

	if (e->run_in_bg) {
		bg_pid = fork();
		if (bg_pid < 0)
			E("fork");
		if (bg_pid != 0) {
			/* parent */
			PUSH(ctx, bg_jobs, bg_pid);
			res->pid = bg_pid;
			goto out;
		}
	}

	switch (e->type) {
	case EXPR_PROG:
		for (i = 0; i < e->prog.size; i++)
			exec_expr(e->prog.cmds[i], ctx, res);
		break;
	case EXPR_SIMPLE_CMD:
		/* simple cmd is also used for assignments... */
		if (e->simple_cmd.size == 1 && e->simple_cmd.words[0]->type == TOK_ASSIGN) {
			exec_assign(ctx, e->simple_cmd.words[0]);
			res->status = 0;
			goto out;
		}
		/* check builtins */
		builtin = builtin_find(e->simple_cmd.words[0]->s);
		if (builtin) {
			builtin(&e->simple_cmd, ctx, res);
			goto out;
		}
		/* check for function calls */
		func = exec_find_func(ctx, e->simple_cmd.words[0]->s);
		if (func) {
			exec_func_call(ctx, func, e, res);
			goto out;
		}
		/* otherwise fork & exec */
		res->pid = fork();
		if (res->pid < 0)
			E("fork");

		if (res->pid == 0) {
			/* child */
			exec_cmd(e, ctx);
			/* should never return */
			exit(1);
		}

		rcpid = waitpid(res->pid, &res->status, 0);
		if (rcpid < 0)
			E("waitpid");
		break;
	case EXPR_AND:
		/* run left, stop if failure */
		exec_expr(e->and_or.left, ctx, res);
		if (FAILED(res->status))
			goto out;
		/* run right, stop if failure */
		exec_expr(e->and_or.right, ctx, res);
		if (FAILED(res->status))
			goto out;
		break;
	case EXPR_OR:
		/* run left, stop if success */
		exec_expr(e->and_or.left, ctx, res);
		if (!FAILED(res->status))
			goto out;
		/* run right, stop if success */
		exec_expr(e->and_or.right, ctx, res);
		if (!FAILED(res->status))
			goto out;
		break;
	case EXPR_NOT:
		/* inverse failure and success */
		exec_expr(e->not.expr, ctx, res);
		res->status = W_EXITCODE(!STATUS_TO_EXIT(res->status), 0);
		break;
	case EXPR_PIPE:
	{
		int pipefd[2];
		pid_t left, right;

		// TODO: avoid extra forks?

		rc = pipe(pipefd);
		if (rc < 0)
			E("pipe");

		left = fork();
		if (left < 0)
			E("fork");

		if (left == 0) {
			dup2(pipefd[1], 1);
			close(pipefd[0]);
			close(pipefd[1]);
			exec_expr(e->and_or.left, ctx, res);
			exit(STATUS_TO_EXIT(res->status));
		}

		right = fork();
		if (right < 0)
			E("fork");

		if (right == 0) {
			dup2(pipefd[0], 0);
			close(pipefd[0]);
			close(pipefd[1]);
			exec_expr(e->and_or.right, ctx, res);
			exit(STATUS_TO_EXIT(res->status));
		}

		close(pipefd[0]);
		close(pipefd[1]);
		rcpid = waitpid(right, &res->status, 0);
		if (rcpid < 0)
			E("waitpid");
		break;
	}
	case EXPR_SUB:
	{
		pid_t child = fork();
		if (child < 0)
			E("fork");

		if (child == 0) {
			exec_apply_redir(&e->sub.redir);
			exec_expr(e->sub.expr, ctx, res);
			exit(STATUS_TO_EXIT(res->status));
		}

		rcpid = waitpid(child, &res->status, 0);
		if (rcpid < 0)
			E("waitpid");
		break;
	}
	case EXPR_FOR:
	{
		struct expand_context expd = {0};

		expand_words(&expd, ctx, e->efor.words, e->efor.size);
		for (i = 0; i < expd.size; i++) {
			L("expanded <%s>", expd.words[i]->s);
			exec_set_var_binding(ctx, e->efor.name->s, expd.words[i]->s);
			exec_expr(e->efor.body, ctx, res);
		}
		FREE_ARRAY(&expd, words, str_free);
		break;
	}
	case EXPR_FUNCTION:
		exec_set_func_binding(ctx, e->func.name->s, e);
		res->status = 0;
		break;
	case EXPR_IF:
		exec_expr(e->eif.test, ctx, res);
		if (FAILED(res->status))
			exec_expr(e->eif.xelse, ctx, res);
		else
			exec_expr(e->eif.xthen, ctx, res);
		break;
	default:
		E("TODO");
	}

 out:
	if (e->run_in_bg && bg_pid == 0) {
		/* child */
		exit(STATUS_TO_EXIT(res->status));
	}
	return;
}


void expr_free(struct expr *e)
{
	if (!e)
		return;

	switch (e->type) {
	case EXPR_SUB:
		expr_free(e->sub.expr);
		break;
	case EXPR_NOT:
		expr_free(e->not.expr);
		break;
	case EXPR_OR:
	case EXPR_AND:
		expr_free(e->and_or.left);
		expr_free(e->and_or.right);
		break;
	case EXPR_PIPE:
		expr_free(e->pipe.left);
		expr_free(e->pipe.right);
		break;
	case EXPR_SIMPLE_CMD:
		FREE_ARRAY(&e->simple_cmd, words, str_free);
		break;
	case EXPR_PROG:
		FREE_ARRAY(&e->prog, cmds, expr_free);
		break;
	case EXPR_FOR:
		str_free(e->efor.name);
		FREE_ARRAY(&e->efor, words, str_free);
		expr_free(e->efor.body);
		break;
	case EXPR_FUNCTION:
		str_free(e->efor.name);
		expr_free(e->efor.body);
		break;
	case EXPR_IF:
		expr_free(e->eif.test);
		expr_free(e->eif.xthen);
		expr_free(e->eif.xelse);
		break;
	}
	free(e);
}


int main(void)
{
	struct input in = {.type = INPUT_FILE, .fh = stdin};
	struct str *tok;
	struct expr *root;
	void *parser = ParseAlloc(malloc);
	enum token_type last_tok = TOK_NONE;

	L("initializing log");

	printf("=== LEXING ===\n");

	while (1) {
		/* read token */
		tok = read_token(&in, &last_tok);
		printf("TOK: ");
		dump_token(tok);

		/* feed it to parser */
		Parse(parser, tok->type, tok, &root);
		if (tok->type == TOK_NONE)
			break;
	}
	ParseFree(parser, free);

	printf("=== PARSING ===\n");

	dump_expr(root, 0, false);

	printf("=== RUNNING ===\n");
	fflush(NULL);

	struct exec_result res = {0};
	struct exec_context ctx = {0};

	exec_expr(root, &ctx, &res);
	printf("RESULT = %d (exit code=%d)\n", res.status, WEXITSTATUS(res.status));

	return 0;
}
