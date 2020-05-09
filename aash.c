#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

#include "dbg.h"
#include "ast.h"

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

struct str *read_word(struct input *in, struct str *tok)
{
	int quote;
	int c;
	int c2;

	tok->type = TOK_WORD;

 connected_word:
	quote = 0;
	c = in_getc(in);
	switch (c) {
	case '\'':
	case '"':
		quote = c;
		break;
	case EOF:
		return tok;
	default:
		str_push(tok, c);
		break;
	}

	while ((c = in_getc(in)) != EOF) {
		if (quote) {
			if (c == quote)
				return tok;
			else if (c == '\\') {
				c2 = in_getc(in);
				if (c2 == EOF)
					E("EOF after '\\'");
				str_push(tok, c2);
			} else {
				str_push(tok, c);
			}
		} else {
			if (strchr("#|&><!()\n\t ;", c)) {
				in_ungetc(in, c);
				return tok;
			}
			if (strchr("\"'", c)) {
				in_ungetc(in, c);
				goto connected_word;
			}
			else
				str_push(tok, c);
		}
	}
	return tok;
}

#define READ_DOUBLE_OP(op2, tok1, tok2)		\
	do {					\
		c2 = in_getc(in);		\
		if (c2 == op2) {		\
			tok->type = tok2;	\
			return tok;		\
		} else {			\
			tok->type = tok1;	\
			if (c2 == EOF)		\
				goto eof;	\
			in_ungetc(in, c2);	\
			return tok;		\
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
			return tok;
		case '#':
			read_comment(in);
			break;
		case '|':
			READ_DOUBLE_OP('|', TOK_PIPE, TOK_OR);
			break;
		case '&':
			READ_DOUBLE_OP('&', TOK_BG, TOK_AND);
			break;
		case '>':
			READ_DOUBLE_OP('>', TOK_REDIR_OUT, TOK_REDIR_APPEND);
			break;
		case '<':
			tok->type = TOK_REDIR_IN;
			return tok;
		case '!':
			tok->type = TOK_NOT;
			return tok;
		case '(':
			tok->type = TOK_LPAREN;
			return tok;
		case ')':
			tok->type = TOK_RPAREN;
			return tok;
		case '\n':
			tok->type = TOK_NEWLINE;
			return tok;
		case ';':
			tok->type = TOK_SEMICOL;
			return tok;
		case ' ':
		case '\t':
			goto next_char;
		default:
			/* WORD and quoted strings */
			in_ungetc(in, c);
			return read_word(in, tok);
		}
	}
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
	case TOK_BG: puts("BG &"); break;
	case TOK_LPAREN: puts("LPAREN ("); break;
	case TOK_RPAREN: puts("RPAREN )"); break;
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
#define DUMP_UNARY(n, e, name, field)				\
	do {							\
		IND_PRINT(n, "%s {\n", name);			\
		dump_expr(e->field.expr, n+1, graphviz);	\
		IND_PRINT(n, "}\n");				\
	} while (0)

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
		putchar('\n');
		break;
	case EXPR_NOT:
		DUMP_UNARY(n, e, "NOT", not);
		break;
	case EXPR_SUB:
		DUMP_UNARY(n, e, "SUBSHELL", sub);
		break;
	default:
		IND_PRINT(n, "UNKNOWN TYPE %d\n", e->type);
		break;
	}
}


struct exec_context {
	int status;
	pid_t pid;
};

#define FAILED(s) (!WIFEXITED(s) || WEXITSTATUS(s) != 0)

void exec_expr(struct expr *e, struct exec_context *res)
{
	int i;
	pid_t rcpid;
	int rc;

	assert(e);

	switch (e->type) {
	case EXPR_PROG:
		for (i = 0; i < e->prog.size; i++)
			exec_expr(e->prog.cmds[i], res);
		break;
	case EXPR_SIMPLE_CMD:
		res->pid = fork();
		if (res->pid < 0)
			E("fork");

		if (res->pid == 0) {
			/* child */
			char **argv = calloc(sizeof(*argv), e->simple_cmd.size+1);
			for (i = 0; i < e->simple_cmd.size; i++)
				argv[i] = e->simple_cmd.words[i]->s;
			execvp(argv[0], argv);
			exit(1);
		}

		rcpid = waitpid(res->pid, &res->status, 0);
		if (rcpid < 0)
			E("waitpid");
		break;
	case EXPR_AND:
		/* run left, stop if failure */
		exec_expr(e->and_or.left, res);
		if (FAILED(res->status))
			return;
		/* run right, stop if failure */
		exec_expr(e->and_or.right, res);
		if (FAILED(res->status))
			return;
		break;
	case EXPR_OR:
		/* run left, stop if success */
		exec_expr(e->and_or.left, res);
		if (!FAILED(res->status))
			return;
		/* run right, stop if success */
		exec_expr(e->and_or.right, res);
		if (!FAILED(res->status))
			return;
		break;
	case EXPR_NOT:
		/* inverse failure and success */
		exec_expr(e->not.expr, res);
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
			exec_expr(e->and_or.left, res);
			exit(FAILED(res->status) ? 1 : 0);
		}

		right = fork();
		if (right < 0)
			E("fork");

		if (right == 0) {
			dup2(pipefd[0], 0);
			close(pipefd[0]);
			close(pipefd[1]);
			exec_expr(e->and_or.right, res);
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
			exec_expr(e->sub.expr, res);
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

	struct exec_context res;
	exec_expr(root, &res);
	printf("RESULT = %d (exit code=%d)\n", res.status, WEXITSTATUS(res.status));

	return 0;
}
