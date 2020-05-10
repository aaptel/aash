#include <stdlib.h>
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

/*
 * Lexing
 */

struct input {
	FILE *fh;
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
	int r = ungetc(c, in->fh);
	assert(r != EOF);
}

int in_getc(struct input *in)
{
	int c;

	if (in->eof) {
		c = EOF;
		in->nb_eof++;
	} else {
		c = fgetc(in->fh);
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

bool is_word_all_digits(struct str *w)
{
	int i;
	char *s = w->s;

	for (i = 0; i < w->size-1; i++)
		if (!isdigit(s[i]))
			return false;

	return true;
}

struct str *read_word(struct input *in, struct str *tok)
{
	int in_quote = 0;
	int in_shellexp = 0; // $( .. )
	int c;
	int c2;

	tok->type = TOK_WORD;

	while ((c = in_getc(in)) != EOF) {
		if (in_quote) {
			if (c == in_quote) {
				if (in_quote == ')') {
					in_shellexp--;
					if (in_shellexp == 0)
						in_quote = 0;
				} else {
					in_quote = 0;
				}
			}
			else if (c == '$') {
				c2 = in_getc(in);
				if (c2 == EOF) {
					str_push(tok, c);
					goto out;
				}
				if (c2 == '(' && in_quote == ')') {
					assert(in_shellexp > 0);
					in_shellexp++;
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
					in_quote = ')';
					assert(in_shellexp == 0);
					in_shellexp++;
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

struct str *read_token(struct input *in)
{
	int c;
	int c2;
	struct str *tok = str_new();

	while (1) {
	next_char:
		switch (c = in_getc(in)) {
		eof:
		case EOF:
			goto out;
		case '#':
			read_comment(in);
			break;
		case '|':
			READ_DOUBLE_OP('|', TOK_PIPE, TOK_OR);
			break;
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
	case TOK_IO_NUMBER: printf("IO_NUMBER %s\n", tok->s); break;
	case TOK_ASSIGN: puts("IO_ASSIGN"); break;
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

struct exec_result {
	int status;
	pid_t pid;
};

struct exec_context {
	pid_t *bg_jobs;
	size_t size;
	size_t capa;

	struct vars {
		struct binding {
			char *name;
			char *value;
		} *bindings;
		size_t size;
		size_t capa;
	} vars;
};

void exec_set_binding(struct exec_context *exec, const char *name, const char *val)
{
	int i;

	for (i = 0; i < exec->vars.size; i++) {
		struct binding *v = &exec->vars.bindings[i];
		if (strcmp(name, v->name) == 0) {
			free(v->value);
			v->value = strdup(val);
			return;
		}
	}

	struct binding newv = {
		.name = strdup(name),
		.value = strdup(val),
	};

	PUSH(&exec->vars, bindings, newv);
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
	int in_quote;
};

#define MAX_VAR_NAME_SIZE 32
char* read_var(char *s, char *name)
{
	char *out = name;
	bool in_brace = false;

	if (*s == '{') {
		in_brace = true;
		s++;
	}
	for (; *s; s++) {
		if (in_brace) {
			if (*s == '}')
				goto out;
		}
		else {
			if (!isalnum(*s) && *s != '_') {
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
	if (exp->size == 0) {
		struct str *w = str_new();
		PUSH(exp, words, w);
	}

	str_push(exp->words[exp->size-1], c);
}

void expand_next_word(struct expand_context *exp)
{
	if (exp->size > 0) {
		if (exp->words[exp->size-1]->size > 0) {
			struct str *w = str_new();
			PUSH(exp, words, w);
		}
	}
}

void expand_push_var(struct exec_context *exec, struct expand_context *exp, const char *var)
{
	int i;
	for (i = 0; i < exec->vars.size; i++) {
		struct binding *v = &exec->vars.bindings[i];
		if (strcmp(var, v->name) == 0) {
			const char *s = v->value;
			for (; *s; s++) {
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
	}
}

void exec_expand(struct exec_context *exec, struct expand_context *exp, struct str *in)
{
	char *s = in->s;
	exp->in_quote = 0;

	for (s = in->s; *s; s++) {
		char c = *s, c2 = *(s+1);

		if (exp->in_quote) {
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
				if (c2 == '{' || c2 == '_' || isalnum(c2)) {
					char var_name[MAX_VAR_NAME_SIZE];

					s = read_var(s+1, var_name);
					expand_push_var(exec, exp, var_name);
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
				if (c2 == '{' || c2 == '_' || isalnum(c2)) {
					char var_name[MAX_VAR_NAME_SIZE];

					s = read_var(s+1, var_name);
					expand_push_var(exec, exp, var_name);
					continue;
				}
			}
			expand_push(exp, c);
		}
	}
 out:
	return;
}


/*
 * Execution
 */

#define FAILED(s) (!WIFEXITED(s) || WEXITSTATUS(s) != 0)

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
	exec_set_binding(exec, name, expanded->s);

	/* done */
	str_free(expanded);
}

void exec_cmd(struct expr *expr, struct exec_context *exec)
{
	struct expand_context expd = {0};
	int i;

	/*
	 * We are in the child and about to exec, no need to worry
	 * about freeing memory
	 */

	for (i = 0; i < expr->simple_cmd.size; i++) {
		struct str *w = expr->simple_cmd.words[i];
		// discard assignements
		if (w->type == TOK_WORD) {
			exec_expand(exec, &expd, w);
			expand_next_word(&expd);
		}
	}

	char **argv = calloc(sizeof(*argv), expd.size+1);
	for (i = 0; i < expd.size; i++) {
		argv[i] = expd.words[i]->s;
	}
	exec_apply_redir(&expr->simple_cmd.redir);
	execvp(argv[0], argv);
	exit(1);
}

void exec_expr(struct expr *e, struct exec_context *ctx, struct exec_result *res)
{
	int i;
	pid_t rcpid, bg_pid;
	int rc;
	builtin_func_t func;

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
		func = builtin_find(e->simple_cmd.words[0]->s);
		if (func) {
			func(&e->simple_cmd, ctx, res);
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
		res->status = FAILED(res->status) ? 0 : 1;
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
			exit(FAILED(res->status) ? 1 : 0);
		}

		right = fork();
		if (right < 0)
			E("fork");

		if (right == 0) {
			dup2(pipefd[0], 0);
			close(pipefd[0]);
			close(pipefd[1]);
			exec_expr(e->and_or.right, ctx, res);
			exit(FAILED(res->status) ? 1 : 0);
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
			exit(FAILED(res->status) ? 1 : 0);
		}

		rcpid = waitpid(child, &res->status, 0);
		if (rcpid < 0)
			E("waitpid");
		break;
	}
	default:
		E("TODO");
	}

 out:
	if (e->run_in_bg && bg_pid == 0) {
		/* child */
		exit(FAILED(res->status) ? 1 : 0);
	}
	return;
}

int main(void)
{
	struct input in = {.fh = stdin};
	struct str *tok;
	struct expr *root;
	void *parser = ParseAlloc(malloc);

	printf("=== LEXING ===\n");

	while (1) {
		/* read token */
		tok = read_token(&in);
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

	struct exec_result res = {0};
	struct exec_context ctx = {0};
	exec_expr(root, &ctx, &res);
	printf("RESULT = %d (exit code=%d)\n", res.status, WEXITSTATUS(res.status));

	return 0;
}
