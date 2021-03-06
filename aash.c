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
#include <termios.h>
#include <errno.h>

#include "dbg.h"
#include "ast.h"
#include "lex.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define FAILED(s) (WIFSIGNALED(s) || (WIFEXITED(s) && WEXITSTATUS(s) != 0))
#define STATUS_TO_EXIT(s) (WIFEXITED(s) ? WEXITSTATUS(s) : 1)

#define MAX_VAR_NAME_SIZE 32
#define LOG_FILE "log.txt"

const char *g_progname = NULL;
bool g_debug = false;
bool g_interactive = false;
pid_t g_main_pid;
struct termios g_term_modes;

pid_t d_tcsetpgrp(const char *from, const char *sfd, int fd, const char *spgrp, pid_t pgrp)
{
	if (errno) {L("previous errno %d %s", errno, strerror(errno)); errno = 0;}
	int r = tcsetpgrp(fd, pgrp);
	L("in %-20.20s tcsetpgrp(%s<%d>, %s<%d>) = %d (%d %s)", from, sfd, fd, spgrp,
	  pgrp, r, errno, errno?strerror(errno):"");
	return r;
#define tcsetpgrp(xfd, xpgrp) d_tcsetpgrp(__func__, #xfd, xfd, #xpgrp, xpgrp)
}

pid_t d_waitpid(const char *from, const char *spid, pid_t pid, const char *sstatus, int *status,
		const char *sopts, int opts)
{
	if (errno) {L("previous errno %d %s", errno, strerror(errno)); errno = 0;}
	pid_t r = waitpid(pid, status, opts);
	L("in %-20.20s waitpid(%s<%d>, %s(%x), %s<%d>) = %d (%d %s)",
	  from, spid, pid, sstatus, status, sopts, opts, r, errno, errno?strerror(errno):"");
	return r;
#define waitpid(xpid, xstatus, xopts) d_waitpid(__func__, #xpid, xpid, #xstatus, xstatus, #xopts, xopts)
}

pid_t d_setpgid(const char *from, const char *spid, pid_t pid, const char *spgrp, pid_t pgrp)
{
	if (errno) {L("previous errno %d %s", errno, strerror(errno)); errno = 0;}
	int r = setpgid(pid, pgrp);
	L("in %-20.20s setpgid(%s<%d>, %s<%d>) = %d (%d %s)", from, spid, pid, spgrp, pgrp,
	  r, errno, errno?strerror(errno):"");
	return r;
#define setpgid(xpid, xpgrp) d_setpgid(__func__, #xpid, xpid, #xpgrp, xpgrp)
}

bool is_main_pid(void)
{
	return g_main_pid == getpid();
}

#ifndef NDEBUG
FILE *g_log = NULL;

void log_write(const char *format, ...)
{
	/*
	 * Need to be run at least once by main process so that forks
	 * can inherit it
	 */
	va_list args;

	if (!g_log) {
#ifdef LOG_FILE
		g_log = fopen(LOG_FILE, "w+");
		if (!g_log)
			E("fopen %s failed: %d %s", LOG_FILE, errno, strerror(errno));
#else
		if (dup2(2, 255) < 0)
			E("dup2 2,255 errno %d %s", errno, strerror(errno));
		g_log = fdopen(255, "w+");
		if (!g_log)
			E("fopen 255 errno %d %s", errno, strerror(errno));
#endif
	}

	va_start(args, format);
	vfprintf(g_log, format, args);
	va_end(args);

	fflush(g_log);
}
#endif

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
		if (in->type == INPUT_FILE) {
			c = fgetc(in->fh);
			if (c == EOF) {
				if (feof(in->fh)) {
					L("fh is eof");
				}
				if (ferror(in->fh)) {
					L("fh has error (%d %s)", errno, strerror(errno));
					errno = 0;
				}
			}
		}
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
	str->s[str->size] = 0;
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
		IND_PRINT(n, "%s ", name);			\
		if (e->run_in_bg) printf(" (in bg) ");		\
		dump_cmd_redirect(&e->redir);			\
		printf(" {\n");					\
		IND_PRINT(n+1, "left {\n");			\
		dump_expr(e->field.left, n+2, graphviz);	\
		IND_PRINT(n+1, "}\n");				\
		IND_PRINT(n+1, "right {\n");			\
		dump_expr(e->field.right, n+2, graphviz);	\
		IND_PRINT(n+1, "}\n");				\
		IND_PRINT(n, "}\n");				\
	} while (0)


bool cmd_needs_redirect(struct cmd_redirect *c)
{
	return c->stdin.is_set || c->stdout.is_set || c->stderr.is_set;
}
void dump_cmd_redirect(struct cmd_redirect *c)
{
	if (cmd_needs_redirect(c))
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

	switch (e->type) {
	case EXPR_PROG:
		IND_PRINT(n, "PROG");
		if (e->run_in_bg) printf(" (in bg) ");
		dump_cmd_redirect(&e->redir);
		printf(" {\n");
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
		IND_PRINT(n, "PIPE ");
		if (e->run_in_bg) printf(" (in bg) ");
		dump_cmd_redirect(&e->redir);
		printf(" {\n");
		for (i = 0; i < e->pipe.size; i++)
			dump_expr(e->pipe.cmds[i], n+1, graphviz);
		IND_PRINT(n, "}\n");
		break;
	case EXPR_SIMPLE_CMD:
		IND_PRINT(n, "CMD ");
		for (i = 0; i < e->simple_cmd.size; i++)
			printf("<%s> ", e->simple_cmd.words[i]->s);
		if (e->run_in_bg) printf(" (in bg) ");
		dump_cmd_redirect(&e->redir);
		putchar('\n');
		break;
	case EXPR_NOT:
		IND_PRINT(n, "NOT ");
		if (e->run_in_bg) printf(" (in bg) ");
		dump_cmd_redirect(&e->redir);
		printf(" {\n");
		dump_expr(e->not.expr, n+1, graphviz);
		IND_PRINT(n, "}\n");
		break;
	case EXPR_SUB:
		IND_PRINT(n, "SUBSHELL ");
		if (e->run_in_bg) printf(" (in bg) ");
		dump_cmd_redirect(&e->redir);
		printf(" {\n");
		dump_expr(e->sub.expr, n+1, graphviz);
		IND_PRINT(n, "}\n");
		break;
	case EXPR_FOR:
		IND_PRINT(n, "FOR %s IN ", e->efor.name->s);
		for (i = 0; i < e->efor.size; i++)
			printf("<%s> ", e->efor.words[i]->s);
		if (e->run_in_bg) printf(" (in bg) ");
		dump_cmd_redirect(&e->redir);
		printf(" {\n");
		dump_expr(e->efor.body, n+1, graphviz);
		IND_PRINT(n, "}\n");
		break;
	case EXPR_FUNCTION:
		IND_PRINT(n, "FUNCTION %s {", e->func.name->s);
		dump_expr(e->func.body, n+1, graphviz);
		IND_PRINT(n, "}\n");
		break;
	case EXPR_IF:
		IND_PRINT(n, "IF ");
		if (e->run_in_bg) printf(" (in bg) ");
		dump_cmd_redirect(&e->redir);
		printf(" {\n");
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
void simple_cmd_merge(struct expr *c, struct expr *other)
{
	int i;

	assert(c->type == EXPR_SIMPLE_CMD);
	assert(other->type == EXPR_SIMPLE_CMD);

	for (i = 0; i < other->simple_cmd.size; i++) {
		PUSH(&c->simple_cmd, words, other->simple_cmd.words[i]);
		other->simple_cmd.words[i] = NULL;
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

	struct job {
		struct job *next;           /* next active job */
		char *command;              /* command line, used for messages */
		struct process {
			struct expr *expr;
			pid_t pid;                  /* process ID */
			int status;                 /* reported status value */
			bool completed;             /* true if process has completed */
			bool stopped;               /* true if process has stopped */
		} *procs;                    /* list of processes in this job */
		size_t size;
		size_t capa;

		pid_t pgid;                 /* process group ID */
		struct termios tmodes;      /* saved terminal modes */
		bool notified;              /* true if user told about stopped job */
		bool fg;                    /* true if job was in foreground */
	} *jobs;

	bool interactive;
};

void wait_for_job(struct exec_context *exec, struct job *j);
void put_job_in_foreground(struct exec_context *exec, struct job *j, int cont);
void put_job_in_background(struct exec_context *exec, struct job *j, int cont);

struct job *job_new(struct exec_context *exec)
{
	struct job *j = calloc(1, sizeof(*j));
	j->next = exec->jobs;
	exec->jobs = j;
	return j;
}

void job_add_proc(struct job *job, pid_t pid, struct expr *expr)
{
	L("adding pid %ld to job", (long)pid);
	struct process pr = {.pid = pid, .expr = expr};
	PUSH(job, procs, pr);
	if (g_interactive) {
		setpgid(pid, job->pgid);
	}
}

/* Format information about job status for the user to look at.  */
void format_job_info(struct job *j, const char *status)
{
	if (!g_interactive || j->fg)
		return;
	fprintf(stderr, "job %ld (%s)\n", (long)j->pgid, status);
}


/* Find the active job with the indicated pgid.  */
struct job *job_find(struct exec_context *exec, pid_t pgid)
{
	struct job *j;

	for (j = exec->jobs; j; j = j->next)
		if (j->pgid == pgid)
			return j;
	return NULL;
}

void job_free(struct job *j)
{
	if (!j)
		return;
	free(j->procs);
	free(j);
}

/* Return true if all processes in the job have stopped or completed.  */
bool job_is_stopped(struct job *j)
{
	int i;
	struct process *p;

	for (i = 0; i < j->size; i++) {
		p = &j->procs[i];
		if (!p->completed && !p->stopped)
			return false;
	}
	return true;
}

/* Return true if all processes in the job have completed.  */
bool job_is_completed(struct job *j)
{
	int i;
	struct process *p;

	for (i = 0; i < j->size; i++) {
		p = &j->procs[i];
		if (!p->completed)
			return false;
	}
	return true;
}


/* Put job j in the foreground.  If cont is nonzero,
   restore the saved terminal modes and send the process group a
   SIGCONT signal to wake it up before we block.  */

void put_job_in_foreground(struct exec_context *exec, struct job *j, int cont)
{
	j->fg = true;

	if (!g_interactive) {
		if (cont)
			E("invalid state");
		wait_for_job(exec, j);
		return;
	}

	L("pgid=%ld", (long)j->pgid);

	/* Put the job into the foreground.  */
	tcsetpgrp(0, j->pgid);


	/* Send the job a continue signal, if necessary.  */
	if (cont) {
		tcsetattr(0, TCSADRAIN, &j->tmodes);
		if (kill(-j->pgid, SIGCONT) < 0)
			perror("kill (SIGCONT)");
	}


	/* Wait for it to report.  */
	wait_for_job(exec, j);

	/* Put the shell back in the foreground.  */
	tcsetpgrp(0, g_main_pid);


	/* Restore the shell's terminal modes.  */
	tcgetattr(0, &j->tmodes);
	tcsetattr(0, TCSADRAIN, &g_term_modes);
}

/* Put a job in the background.  If the cont argument is true, send
   the process group a SIGCONT signal to wake it up.  */
void put_job_in_background(struct exec_context *exec, struct job *j, int cont)
{
	L("");

	j->fg = false;

	if (!g_interactive) {
		if (cont)
			E("invalid state");
		return;
	}

	/* Send the job a continue signal, if necessary.  */
	if (cont)
		if (kill(-j->pgid, SIGCONT) < 0)
			perror("kill (SIGCONT)");
}

/* Store the status of the process pid that was returned by waitpid.
   Return 0 if all went well, nonzero otherwise.  */

int mark_process_status(struct exec_context *exec, pid_t pid, int status)
{
	struct job *j;
	struct process *p;
	int i;

	if (pid > 0) {
		/* Update the record for the process.  */
		for (j = exec->jobs; j; j = j->next) {
			for (i = 0; i < j->size; i++) {
				p = &j->procs[i];
				if (p->pid != pid)
					continue;

				p->status = status;
				if (WIFSTOPPED(status))
					p->stopped = 1;
				else {
					p->completed = 1;
					if (WIFSIGNALED(status))
						fprintf(stderr, "%d: Terminated by signal %d.\n",
							(int) pid, WTERMSIG(p->status));
				}
				return 0;
			}
		}
		fprintf(stderr, "No child process %d.\n", pid);
		return -1;
	}

	else if (pid == 0 || errno == ECHILD) {
		/* No processes ready to report.  */
		errno = 0;
		return -1;
	} else {
		/* Other weird errors.  */
		perror("waitpid");
		return -1;
	}
}

bool job_get_status(struct job *j, int *status)
{
	int i;
	struct process *p;

	*status = W_EXITCODE(0, 0);

	for (i = 0; i < j->size; i++) {
		p = &j->procs[i];
		if (!p->completed)
			return false;

		if (FAILED(p->status)) {
			*status = p->status;
			break;
		}
	}
	return true;
}

/* Check for processes that have status information available,
   blocking until all processes in the given job have reported.  */

void wait_for_job(struct exec_context *exec, struct job *j)
{
	int status;
	pid_t pid;

	do
		pid = waitpid(WAIT_ANY, &status, WUNTRACED);
	while (!mark_process_status(exec, pid, status)
	       && !job_is_stopped(j)
	       && !job_is_completed(j));

}

/* Notify the user about stopped or terminated jobs.
   Delete terminated jobs from the active job list.  */

void do_job_notification(struct exec_context *exec)
{
	struct job *j, *jlast, *jnext;
	int status;
	pid_t pid;
	int i;

	L("");
	L("===========");

	/* Update status information for child processes.  */
	do {
		pid = waitpid(WAIT_ANY, &status, WUNTRACED|WNOHANG);
	} while (!mark_process_status(exec, pid, status));

	jlast = NULL;
	for (j = exec->jobs; j; j = jnext) {
		jnext = j->next;
		L("job group %d", j->pgid);
		for (i = 0; i < j->size; i++) {
			struct process *p = &j->procs[i];
			L("proc %d: status %x %s %s",
			  p->pid, p->status, p->completed?"completed":"", p->stopped?"stopped":"");
		}

		/* If all processes have completed, tell the user the job has
		   completed and delete it from the list of active jobs.  */
		if (job_is_completed(j)) {
			format_job_info(j, "completed");
			if (jlast)
				jlast->next = jnext;
			else
				exec->jobs = jnext;
			job_free(j);
		}

		/* Notify the user about stopped jobs,
		   marking them so that we won't do this more than once.  */
		else if (job_is_stopped(j) && !j->notified) {
			format_job_info(j, "stopped");
			j->notified = 1;
			jlast = j;
		}

		/* Don't say anything about jobs that are still running.  */
		else
			jlast = j;
	}
	L("===========");
	L("");
}

/* Mark a stopped job J as being running again.  */
void mark_job_as_running(struct job *j)
{
	int i;
	for (i = 0; i < j->size; i++)
		j->procs[i].stopped = 0;
	j->notified = false;
}


/* Continue the job J.  */
void job_continue(struct exec_context *exec,  struct job *j, int foreground)
{
	mark_job_as_running(j);
	if (foreground)
		put_job_in_foreground(exec, j, 1);
	else
		put_job_in_background(exec, j, 1);
}

void init_shell(void)
{
	pid_t shell_pgid;

	g_main_pid = getpid();

	if (!g_interactive)
		return;

	/* Loop until we are in the foreground.  */
	while (tcgetpgrp(0) != (shell_pgid = getpgrp()))
		kill(-shell_pgid, SIGTTIN);

	/* Ignore interactive and job-control signals.  */
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	//signal(SIGCHLD, SIG_IGN);

	/* Put ourselves in our own process group.  */
	if (setpgid(g_main_pid, g_main_pid) < 0) {
		perror ("Couldn't put the shell in its own process group");
		exit(1);
	}

	/* Grab control of the terminal.  */
	tcsetpgrp(0, g_main_pid);

	/* Save default terminal attributes for shell.  */
	tcgetattr(0, &g_term_modes);
}

struct pipe_pairs {
	int size;
	int fd[];
};

int pipe_pairs_get(struct pipe_pairs *pp, int i, int end)
{
	return pp->fd[2*i + end];
}

struct pipe_pairs *pipe_pairs_new(int size)
{
	int i;
	struct pipe_pairs *pp;

	pp = calloc(1, sizeof(*pp)+(2*sizeof(int))*size);
	pp->size = size;
	for (i = 0; i < pp->size; i++)
		pipe(&pp->fd[2*i]);
	return pp;
}

void pipe_pairs_free(struct pipe_pairs *pp)
{
	int i;
	for (i = 0; i < pp->size; i++) {
		close(pp->fd[i*2+0]);
		close(pp->fd[i*2+1]);
	}
	free(pp);
}


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

void exec_expr(struct expr *e, struct exec_context *ctx, struct exec_result *res, bool forked_from_pipe);

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

	//L("name=<%s>", name);

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

	//L("name=<%s> val=<%s>", name, val);

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

void exec_set_var_binding_fmt(struct exec_context *exec, const char *name, const char *fmt, ...)
{
	va_list args;
	int size = 0;
	int rc = 0;
	char *buf = NULL;

	va_start(args, fmt);
	rc = vsnprintf(buf, size, fmt, args);
	va_end(args);

	if (rc < 0) {
		L("bad fmt? <%s>", fmt);
		goto out;
	}
	size = rc;
	buf = calloc(size+1, 1);

	va_start(args, fmt);
	rc = vsnprintf(buf, size+1, fmt, args);
	va_end(args);
	if (rc < 0) {
		L("bad fmt? <%s>", fmt);
		goto out;
	}
	assert(rc == size);
	exec_set_var_binding(exec, name, buf);

 out:
	free(buf);
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
	struct job *j = ctx->jobs;

	while (j) {
		if (!job_is_completed(j))
			wait_for_job(ctx, j);
		j = j->next;
	}

	res->status = W_EXITCODE(0, 0);
	return 0;
}

int builtin_bg(struct expr_simple_cmd *cmd, struct exec_context *ctx, struct exec_result *res)
{
	struct job *j = ctx->jobs;
	if (!j)
		return 1;

	job_continue(ctx, j, 0);

	res->status = W_EXITCODE(0, 0);
	return 0;
}

int builtin_fg(struct expr_simple_cmd *cmd, struct exec_context *ctx, struct exec_result *res)
{
	struct job *j = ctx->jobs;
	if (!j)
		return 1;

	job_continue(ctx, j, 1);

	res->status = W_EXITCODE(0, 0);
	return 0;
}

struct {
	const char *name;
	builtin_func_t func;
} g_builtins[] = {
	{"wait", builtin_wait},
	{"fg", builtin_fg},
	{"bg", builtin_bg},
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
	if (strchr("#$!?@", *s)) {
		*out++ = *s;
		if (in_brace && *(s+1) && *(s+1) == '}')
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
	struct var_binding *v;

	if (strcmp(var, "@") == 0) {
		int i, last;
		struct vars *vars = exec_get_func_vars(exec);
		for (i = 0; i < vars->size; i++) {
			v = &vars->bindings[i];
			if (!is_all_digits(v->name)) {
				last = i-1;
				break;
			}
		}
		for (i = 0; i <= last; i++) {
			v = &vars->bindings[i];
			expand_push_var(exec, exp, v->name);
			if (i < last)
				expand_next_word(exp);
		}
		return;
	}

	v = exec_get_var_binding(exec, var);
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
	pid_t pid, rcpid;
	int rc, status;
	int pipefd[2];
	int i;
	struct input_scanner scan;

	L("s=<%s>", s);

	/*
	 * Read all tokens until parens are balanced or we reach end
	 * of the word
	 */

	scanner_init(&scan);
	scanner_refill(&scan, s, strlen(s));
	scanner_push_state(&scan, XLPAREN);
	parser = ParseAlloc(malloc);
	while (1) {
		scanner_step(&scan);
		if (scan.err || scanner_needs_more_input(&scan)) {
			E("tokenizing error");
		}
		if (scan.ready) {
			tok = scan.ready;
			L("TOK: <%s>", token_to_string(tok));
			if (scan.state_size == 1)
				break;
			Parse(parser, tok->type, tok, &root);
		}
	}

	/* end points to next char after final ), or EOF */
	end = &s[scan.input_pos];
	L("end=<%s>", end);
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
		struct exec_result res = {0};

		L("in child");
		exec_set_var_binding_fmt(exec, "$", "%d", getpid());
		close(pipefd[0]);
		dup2(pipefd[1], 1);
		g_interactive = false;
		exec_expr(root, exec, &res, false);
		exit(STATUS_TO_EXIT(res.status));
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
				if (strchr("$!?{_#*@", c2) || isalnum(c2)) {
					char var_name[MAX_VAR_NAME_SIZE];

					s = read_var(s+1, var_name);
					expand_push_var(exec, exp, var_name);
					continue;
				}
				if (c2 == '(') {
					s = expand_push_subshell(exec, exp, s+2);
					s--;
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
				if (strchr("$!?{_#*@", c2) || isalnum(c2)) {
					char var_name[MAX_VAR_NAME_SIZE];

					s = read_var(s+1, var_name);
					expand_push_var(exec, exp, var_name);
					continue;
				}
				if (c2 == '(') {
					s = expand_push_subshell(exec, exp, s+2);
					s--;
					continue;
				}
			}
			expand_push(exp, c);
		}
	}
 out:
	if (contained_quotes && exp->total_added - added_at_start == 0 && strcmp(in->s, "\"$@\"") != 0)
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
	exec_set_var_binding_fmt(exec, "$", "%d", getpid());
	expand_words(&expd, exec, expr->simple_cmd.words, expr->simple_cmd.size);

	L("");
	char **argv = calloc(sizeof(*argv), expd.size+1);
	for (i = 0; i < expd.size; i++) {
		argv[i] = expd.words[i]->s;
		if (!argv[i])
			argv[i] = "";
		L("exec argv[%2d] = <%s>", i, argv[i]);
	}
	exec_apply_redir(&expr->redir);
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
	exec_set_var_binding_fmt(exec, "#", "%d", expd.size-1);

	exec_expr(func->func.body, exec, res, false);

	/*
	 * Pop positional arguments
	 */
	exec_pop_func_vars(exec);

	FREE_ARRAY(&expd, words, str_free);
}

void exec_job_shell_setup(struct expr *e, struct exec_context *exec, pid_t child, pid_t group)
{
	if (g_interactive) {
		setpgid(child, group);
	}
}

void exec_job_child_setup(struct expr *e, struct exec_context *exec, struct job *job)
{
	L("inter = %d", !!g_interactive);

	if (g_interactive) {
		setpgid(getpid(), job->pgid);
		if (!e->run_in_bg) {
			tcsetpgrp(0, job->pgid);
		}
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		signal(SIGTSTP, SIG_DFL);
		signal(SIGTTIN, SIG_DFL);
		signal(SIGTTOU, SIG_DFL);
		signal(SIGCHLD, SIG_DFL);
		g_interactive = false;
	}
}

void exec_expr(struct expr *e, struct exec_context *ctx, struct exec_result *res, bool forked_from_pipe)
{
	int i;
	pid_t rcpid;
	builtin_func_t builtin;
	struct expr *func;
	struct job *job;
	bool exit_on_finish = false;
	bool forked = false;

	assert(e);

	if (forked_from_pipe)
		exit_on_finish = true;

	if (e->type != EXPR_PIPE && (e->run_in_bg || e->type == EXPR_SUB) && !forked_from_pipe) {
		job = job_new(ctx);
		rcpid = fork();
		if (rcpid < 0)
			E("fork");
		forked = true;
		job->pgid = rcpid;
		if (rcpid == 0) {
			// child
			forked = false;
			exit_on_finish = true;
			exec_job_child_setup(e, ctx, job);
			exec_apply_redir(&e->redir);
			exec_set_var_binding_fmt(ctx, "$", "%d", getpid());
		}
		if (rcpid > 0) {
			// parent
			job_add_proc(job, rcpid, e);
			goto out;
		}
	}

	switch (e->type) {
	case EXPR_PROG:
		for (i = 0; i < e->prog.size; i++)
			exec_expr(e->prog.cmds[i], ctx, res, false);
		break;
	case EXPR_SIMPLE_CMD: {
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

		if (!forked_from_pipe && !forked) {
			job = job_new(ctx);
			rcpid = fork();
			if (rcpid < 0)
				E("fork");
			forked = true;
			job->pgid = rcpid;
			if (rcpid == 0) {
				// child
				forked = false;
				exit_on_finish = true;
				exec_job_child_setup(e, ctx, job);
				exec_apply_redir(&e->redir);
				exec_set_var_binding_fmt(ctx, "$", "%d", getpid());
			} else {
				// parent
				job_add_proc(job, rcpid, e);
				goto out;
			}
		}
		exec_cmd(e, ctx);
		// never returns
		exit(1);
	}
		break;
	case EXPR_AND:
		/* run left, stop if failure */
		exec_expr(e->and_or.left, ctx, res, false);
		if (FAILED(res->status))
			goto out;
		/* run right, stop if failure */
		exec_expr(e->and_or.right, ctx, res, false);
		if (FAILED(res->status))
			goto out;
		break;
	case EXPR_OR:
		/* run left, stop if success */
		exec_expr(e->and_or.left, ctx, res, false);
		if (!FAILED(res->status))
			goto out;
		/* run right, stop if success */
		exec_expr(e->and_or.right, ctx, res, false);
		if (!FAILED(res->status))
			goto out;
		break;
	case EXPR_NOT:
		/* inverse failure and success */
		exec_expr(e->not.expr, ctx, res, false);
		res->status = W_EXITCODE(!STATUS_TO_EXIT(res->status), 0);
		break;
	case EXPR_PIPE:
	{
		struct pipe_pairs *pipes = pipe_pairs_new(e->pipe.size-1);
		job = job_new(ctx);
		L("new job %p", job);

		for (i = 0; i < e->pipe.size; i++) {
			struct expr *sube = e->pipe.cmds[i];

			rcpid = fork();
			if (rcpid < 0)
				E("fork");

			if (i == 0) {
				job->pgid = rcpid ? rcpid : getpid();
			}

			if (rcpid == 0) {
				/* child */
				forked_from_pipe = true;
				exec_job_child_setup(e, ctx, job);
				if (i-1 >= 0)
					dup2(pipe_pairs_get(pipes, i-1, 0), 0);
				if (i+1 < e->pipe.size)
					dup2(pipe_pairs_get(pipes, i, 1), 1);
				pipe_pairs_free(pipes);
				exec_apply_redir(&e->redir);
				exec_set_var_binding_fmt(ctx, "$", "%d", getpid());
				exec_expr(e->pipe.cmds[i], ctx, res, true);
				exit(STATUS_TO_EXIT(res->status));
			}
			job_add_proc(job, rcpid, sube);
		}
		pipe_pairs_free(pipes);
		forked = true;
		break;
	}
	case EXPR_SUB:
	{
		// already forked at beginning of function
		exec_apply_redir(&e->redir);
		exec_expr(e->sub.expr, ctx, res, false);
		exit(STATUS_TO_EXIT(res->status));
		break;
	}
	case EXPR_FOR:
	{
		struct expand_context expd = {0};

		expand_words(&expd, ctx, e->efor.words, e->efor.size);
		for (i = 0; i < expd.size; i++) {
			L("expanded <%s>", expd.words[i]->s);
			exec_set_var_binding(ctx, e->efor.name->s, expd.words[i]->s);
			exec_expr(e->efor.body, ctx, res, false);
		}
		FREE_ARRAY(&expd, words, str_free);
		break;
	}
	case EXPR_FUNCTION:
		exec_set_func_binding(ctx, e->func.name->s, e);
		res->status = 0;
		break;
	case EXPR_IF:
		exec_expr(e->eif.test, ctx, res, false);
		if (FAILED(res->status))
			exec_expr(e->eif.xelse, ctx, res, false);
		else
			exec_expr(e->eif.xthen, ctx, res, false);
		break;
	default:
		E("TODO");
	}

 out:

	if (forked) {
		if (e->run_in_bg)
			put_job_in_background(ctx, job, 0);
		else {
			put_job_in_foreground(ctx, job, 0);
		}
		job_get_status(job, &res->status);
	}

	if (exit_on_finish)
		exit(STATUS_TO_EXIT(res->status));

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
		FREE_ARRAY(&e->pipe, cmds, expr_free);
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

void usage()
{
	fprintf(stderr,
		"Usage: %s [--debug] [-c CMD] [--] [SCRIPT [ARGS...]]\n"
		"Options:\n"
		"   -c CMD\n"
		"        run CMD\n"
		"   --debug\n"
		"        print parsing debug info\n",
		g_progname);
}

void in_read_line(struct input *in, struct str *line)
{
	line->size = 0;
	while (1) {
		int c = in_getc(in);
		if (c == EOF)
			break;
		str_push(line, c);
		if (c == '\n')
			break;
	}
}


void in_read_all(struct input *in, struct str *line)
{
	line->size = 0;
	while (1) {
		int c = in_getc(in);
		if (c == EOF)
			break;
		str_push(line, c);
	}
	str_push(line, '\n');
}

int run_interactive(struct input *in, int argc, const char** argv)
{
	struct str *tok;
	struct expr *root;
	void *parser = NULL;
	struct exec_result res = {0};
	struct exec_context exec = {.interactive = true};
	struct str *src;
	struct input_scanner scan;

	src = str_new();
	exec_set_var_binding_fmt(&exec, "$", "%d", getpid());

	while (1) {
	next_cmd:
		do_job_notification(&exec);
		printf("$ ");
		in_read_line(in, src);
		if (src->size == 0) {
			L("read nothing");
			exit(0);
			goto next_cmd;
		}
		scanner_init(&scan);
		scanner_refill(&scan, src->s, src->size);
		if (parser)
			ParseFree(parser, free);
		parser = ParseAlloc(malloc);

		while (1) {
			scanner_step(&scan);
			if (scan.ready) {
				/* read token */
				tok = scan.ready;
				/* feed it to parser */
				Parse(parser, tok->type, tok, &root);
			}
			if (scanner_needs_more_input(&scan)) {
				printf("> ");
				in_read_line(in, src);
				scanner_refill(&scan, src->s, src->size);
			}
			else if (scanner_is_complete(&scan)) {
				if (scan.err) {
					W("tokenizing error");
					goto next_cmd;
				}
				break;
			}
		}
		Parse(parser, TOK_NONE, NULL, &root);
		if (!root) {
			E("parsing error");
		}

		if (g_debug) {
			printf("=== PARSING ===\n");
			dump_expr(root, 0, false);
			printf("=== RUNNING ===\n");
			fflush(NULL);
		}


		exec_expr(root, &exec, &res, false);

		if (g_debug) {
			printf("RESULT = %d (exit code=%d)\n", res.status, WEXITSTATUS(res.status));
		} else {
			//return STATUS_TO_EXIT(res.status);
		}
	}
	return 0;
}

int run_script(struct input *in, int argc, const char** argv)
{
	struct str *tok;
	struct expr *root;
	void *parser;
	struct exec_result res = {0};
	struct exec_context exec = {0};
	struct str *src;
	struct input_scanner scan;

	src = str_new();
	in_read_all(in, src);
	scanner_init(&scan);
	scanner_refill(&scan, src->s, src->size);

	if (g_debug)
		printf("=== LEXING ===\n");

	parser = ParseAlloc(malloc);
	while (1) {
		scanner_step(&scan);
		if (scan.ready) {
			/* read token */
			tok = scan.ready;
			if (g_debug) {
				printf("TOK: ");
				dump_token(tok);
			}
			/* feed it to parser */
			Parse(parser, tok->type, tok, &root);
		}
		if (scanner_needs_more_input(&scan)) {
			E("malformed input");
		}
		else if (scanner_is_complete(&scan)) {
			if (scan.err) {
				E("tokenizing error");
			}
			break;
		}
	}
	Parse(parser, TOK_NONE, NULL, &root);
	ParseFree(parser, free);

	if (!root) {
		E("parsing error");
	}

	if (g_debug) {
		printf("=== PARSING ===\n");
		dump_expr(root, 0, false);
		printf("=== RUNNING ===\n");
		fflush(NULL);
	}

	exec_set_var_binding_fmt(&exec, "$", "%d", getpid());

	for (int i = 0; i < argc; i++) {
		char name[MAX_VAR_NAME_SIZE] = {0};
		int rc = snprintf(name, sizeof(name), "%d", i);
		if (rc > sizeof(name))
			E("too many args");
		exec_set_var_binding(&exec, name, argv[i]);
	}
	exec_set_var_binding_fmt(&exec, "#", "%d", argc-1);
	exec_expr(root, &exec, &res, false);

	if (g_debug) {
		printf("RESULT = %d (exit code=%d)\n", res.status, WEXITSTATUS(res.status));
		return 0;
	} else {
		return STATUS_TO_EXIT(res.status);
	}
}

int main(int argc, const char **argv)
{
	const char *command = NULL;
	const char **script_argv = NULL;
	int script_argc = 0;

	g_progname = argv[0];

	L("initializing log");

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--debug") == 0)
			g_debug = true;
		else if (strcmp(argv[i], "-c") == 0 && i+1 < argc) {
			command = argv[++i];
		}
		else if (strcmp(argv[i], "--") == 0) {
			script_argv = &argv[++i];
			script_argc = argc-i;
			break;
		} else if (argv[i][0] == '-') {
			W("invalid option <%s>", argv[i]);
			usage();
			return 1;
		} else {
			script_argv = &argv[i];
			script_argc = argc-i;
			break;
		}
	}

	struct input in = {0};

	if (command) {
		in = (struct input){
			.type = INPUT_STR,
			.start = command,
			.s = command,
			.len = strlen(command),
		};
	} else if (script_argc >= 1) {
		FILE *fh = fopen(script_argv[0], "r");
		if (!fh) {
			perror("fopen");
			return 1;
		}
		in = (struct input){
			.type = INPUT_FILE,
			.fh = fh,
		};
	} else {
		g_interactive = isatty(0);
		in = (struct input){
			.type = INPUT_FILE,
			.fh = stdin,
		};
	}

	init_shell();

	if (g_interactive)
		return run_interactive(&in, argc, argv);
	else
		return run_script(&in, argc, argv);
}
