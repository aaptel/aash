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

// for debugging
//#define TEST
#ifdef TEST
#define E(fmt, ...) fprintf(stderr, "%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__), exit(1)
enum {TOK_AND=1, TOK_NOT, TOK_BG, TOK_LBRACE, TOK_LPAREN, TOK_NEWLINE, TOK_OR, TOK_PIPE, TOK_RBRACE, TOK_REDIR_APPEND, TOK_REDIR_FD, TOK_REDIR_IN, TOK_REDIR_OUT, TOK_RPAREN, TOK_SEMICOL, TOK_WORD, TOK_FOR, TOK_IN, TOK_DO, TOK_DONE, TOK_FUNCTION, TOK_IF, TOK_THEN, TOK_ELIF, TOK_ELSE, TOK_FI, TOK_ASSIGN, TOK_NAME, TOK_IO_NUMBER};
const char *TOK[]={"NONE","TOK_NOT","TOK_AND", "TOK_BG", "TOK_LBRACE", "TOK_LPAREN", "TOK_NEWLINE", "TOK_OR", "TOK_PIPE", "TOK_RBRACE", "TOK_REDIR_APPEND", "TOK_REDIR_FD", "TOK_REDIR_IN", "TOK_REDIR_OUT", "TOK_RPAREN", "TOK_SEMICOL", "TOK_WORD", "TOK_FOR", "TOK_IN", "TOK_DO", "TOK_DONE", "TOK_FUNCTION", "TOK_IF", "TOK_THEN", "TOK_ELIF", "TOK_ELSE", "TOK_ELSE", "TOK_FI", "TOK_ASSIGN", "TOK_NAME", "TOK_IO_NUMBER"};


/* Use to store tokens */
struct str {
	int type;
	/* for word tokens: */
	char *s;
	size_t size;
	size_t capa;
};

void str_push(struct str *str, char c)
{
	int new_capa = str->capa < 10 ? 10 : str->capa*2;

	/* always keep one null at the end */
	if (str->size+1 >= str->capa) {
		char *p = realloc(str->s, new_capa);
		str->s = p;
		str->capa = new_capa;
		memset(str->s+str->size, 0, str->capa-str->size);
	}

	str->s[str->size++] = c;
	str->s[str->size] = 0;
}

struct str *str_new(void)
{
	struct str *str = calloc(sizeof(*str), 1);
	if (!str)
		E("oom");
	return str;
}
static const char *STS[]={"NONE","NONE","XAND", "XCOMMENT", "XGT", "XOR", "XSTART", "XWORD", "XWORD_DOLLAR", "XWORD_DQUOTE", "XWORD_DQUOTE_ESC", "XWORD_ESC", "XWORD_SQUOTE", "XWORD_SUBSHELL", "XIF", "XTHEN", "XDO", "XFOR", "XLPAREN", "XLBRACE", "XNUM_OR_WORD"};

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
#else
#include "ast.h"
#include "dbg.h"
struct str *str_new(void);
void str_push(struct str*, int);
bool is_word_all_digits(struct str *w);
#endif



#include "lex.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

bool scanner_is_complete(struct input_scanner *in)
{
	return (in->err
		|| (in->input_pos >= in->input_size
		    && in->state_size == 1
		    && in->word == NULL
		    && in->last_tok[1] != TOK_PIPE
		    && in->last_tok[1] != TOK_AND
		    && in->last_tok[1] != TOK_OR));
}

bool scanner_needs_more_input(struct input_scanner *in)
{
	if (in->err)
		return false;
	if (in->input_pos >= in->input_size) {
		if (in->state_size > 1)
			return true;
		else
			return (in->last_tok[1] == TOK_PIPE
				|| in->last_tok[1] == TOK_AND
				|| in->last_tok[1] == TOK_OR);
	}
	return false;
}

void scanner_refill(struct input_scanner *in, const char *s, int len)
{
	in->input = s;
	in->input_pos = 0;
	in->input_size = len;
	if (in->c == EOF && in->input_size > 0)
		in->c = in->input[0];
}

static int scanner_current_state(struct input_scanner *in)
{
	if (in->state_size > 0) {
		return in->state[in->state_size-1];
	}
	return 0;
}

static int scanner_emit(struct input_scanner *in, int type)
{
	if (type == TOK_WORD || type == TOK_IO_NUMBER) {
		assert(in->word);
		in->ready = in->word;
		in->word = NULL;
	} else {
		in->ready = str_new();
		in->ready->type = type;
	}
	return 0;
}

static void scanner_word_push(struct input_scanner *in, int c)
{
	if (!in->word) {
		in->word = str_new();
		in->word->type = TOK_WORD;
	}
	str_push(in->word, c);
}

int scanner_push_state(struct input_scanner *in, int state)
{
	if (in->state_size >= ARRAY_SIZE(in->state))
		return -1;
	in->state[in->state_size++] = state;
	return 0;
}

static int scanner_pop_state(struct input_scanner *in)
{
	if (in->state_size == 0)
		return -1;
	in->state_size--;
	return 0;
}

void scanner_init(struct input_scanner *in)
{
	memset(in, 0, sizeof(*in));
	scanner_push_state(in, XSTART);
	in->c = EOF;
}

static void scanner_action(struct input_scanner *in, int emit_token, int state, int push_char, int input_next)
{
	if (in->err)
		return;

	if (push_char)
		scanner_word_push(in, push_char);

	if (emit_token > 0) {
		if (scanner_emit(in, emit_token) < 0)
			in->err = true;
	}

	if (state < 0) {
		state = -state;
		if (state != 1 && scanner_current_state(in) != state)
			in->err = true;
		if (scanner_pop_state(in) < 0)
			in->err = true;
	}
	else if (state > 0) {
		if (scanner_push_state(in, state) < 0)
			in->err = true;
	}


	if (input_next > 0) {
		in->input_pos++;
		if (in->input_pos < in->input_size)
			in->c = in->input[in->input_pos];
		else
			in->c = EOF;
	}
}


void scanner_step(struct input_scanner *in)
{
	in->ready = NULL;

	switch (scanner_current_state(in)) {
	case XSTART:
	case XIF:
	case XFOR:
	case XDO:
	case XLPAREN:
	case XLBRACE:
		switch (in->c) {
		case '#': scanner_action(in, 0,           +XCOMMENT, 0, +1); break;
		case '(': scanner_action(in, TOK_LPAREN,  +XLPAREN,  0, +1); break;
		case ')': scanner_action(in, TOK_RPAREN,  -XLPAREN,  0, +1); break;
		case '{': scanner_action(in, TOK_LBRACE,  +XLBRACE,  0, +1); break;
		case '}': scanner_action(in, TOK_RBRACE,  -XLBRACE,  0, +1); break;
		case '|': scanner_action(in, 0,            XOR,      0, +1); break;
		case '&': scanner_action(in, 0,            XAND,     0, +1); break;
		case '>': scanner_action(in, 0,            XGT,      0, +1); break;
		case '<': scanner_action(in, TOK_REDIR_IN, 0,        0, +1); break;
		case '!': scanner_action(in, TOK_NOT,      0,        0, +1); break;
		case '\n':scanner_action(in, TOK_NEWLINE,  0,        0, +1); break;
		case ';': scanner_action(in, TOK_SEMICOL,  0,        0, +1); break;
		case ' ':
		case '\t':scanner_action(in, 0,         0,        0, +1); break;
		default:  scanner_action(in, 0,         XNUM_OR_WORD,    0,  0); break;
		case EOF: scanner_action(in, 0,         -1,       0,  0); break;
		}
		break;
	case XCOMMENT: switch (in->c) {
		case '\n': scanner_action(in, 0,        -1,       0, +1); break;
		case EOF:  scanner_action(in, 0,        -1,       0,  0); break;
		default:   scanner_action(in, 0,         0,       0, +1); break;
		}
		break;
	case XAND: switch (in->c) {
		case '&': scanner_action(in, TOK_AND,     -1,        0, +1); break;
		default:  scanner_action(in, TOK_BG,      -1,        0,  0); break;
		case EOF: scanner_action(in, TOK_BG,      -1,        0,  0); break;
		}
		break;
	case XOR: switch (in->c) {
		case '|': scanner_action(in, TOK_OR,      -1,        0, +1); break;
		default:  scanner_action(in, TOK_PIPE,    -1,        0,  0); break;
		case EOF: scanner_action(in, TOK_PIPE,    -1,        0,  0); break;
		}
		break;
	case XGT: switch (in->c) {
		case '>': scanner_action(in, TOK_REDIR_APPEND, -1, 0, +1); break;
		case '&': scanner_action(in, TOK_REDIR_FD,     -1, 0, +1); break;
		case EOF: scanner_action(in, TOK_REDIR_OUT,    -1, 0,  0); break;
		default:  scanner_action(in, TOK_REDIR_OUT,    -1, 0,  0); break;
		}
		break;
	case XNUM_OR_WORD: switch (in->c) {
		case '1': case '2': case '3': case '4': case '5':
		case '6': case '7': case '8': case '9': case '0':
			scanner_action(in, 0,              0,    in->c, +1);
			break;
		case '>':
			in->word->type = TOK_IO_NUMBER;
			scanner_action(in, TOK_IO_NUMBER, -1,    0,      0); break;
		case EOF:
		default:
			in->state[in->state_size-1] = XWORD;
			break;
		}
		break;
	case XWORD: switch (in->c) {
		case '\\': scanner_action(in, 0,      XWORD_ESC,    0,     +1); break;
		case '\'': scanner_action(in, 0,      XWORD_SQUOTE, in->c, +1); break;
		case '"':  scanner_action(in, 0,      XWORD_DQUOTE, in->c, +1); break;
		case '$':  scanner_action(in, 0,      XWORD_DOLLAR, in->c, +1); break;
		default:   scanner_action(in, 0,      0,            in->c, +1); break;
		case EOF:  scanner_action(in, TOK_WORD, -1,            0,  0); break;
		case '\n':
		case '\t':
		case ' ':
		case ';':
		case '(':
		case ')':
		case '|':
		case '<':
		case '>':
		case '&':  scanner_action(in, TOK_WORD, -1, 0, 0); break;
		}
		break;
	case XWORD_ESC: switch (in->c) {
		case '\n': scanner_action(in, 0, -1,               0,        +1); break;
		default:   scanner_action(in, 0, -1,               in->c,    +1); break;
		case EOF:  scanner_action(in, 0, -1,               '\\',      0); break;
		}
		break;
	case XWORD_DQUOTE_ESC: switch (in->c) {
		default:  scanner_action(in, 0, -1,                in->c,    +1); break;
		case EOF: scanner_action(in, 0, -1,               '\\',       0); break;
		}
		break;
	case XWORD_SQUOTE: switch (in->c) {
		case '\'': scanner_action(in, 0, -1,               in->c,    +1); break;
		default:   scanner_action(in, 0,  0,               in->c,    +1); break;
		case EOF:  scanner_action(in, 0, -1,               '\\',      0); break;
		}
		break;
	case XWORD_DQUOTE: switch (in->c) {
		case '"':  scanner_action(in, 0, -1,               in->c,    +1); break;
		case '\\': scanner_action(in, 0, XWORD_DQUOTE_ESC, in->c,    +1); break;
		case '$':  scanner_action(in, 0, XWORD_DOLLAR,     in->c,    +1); break;
		default:   scanner_action(in, 0, 0,                in->c,    +1); break;
		case EOF:  scanner_action(in, 0, -1,               0,        +1); break;
		}
		break;
	case XWORD_SUBSHELL: switch (in->c) {
		case '(':  scanner_action(in, 0, XWORD_SUBSHELL,   in->c,    +1); break;
		case ')':  scanner_action(in, 0, -1,               in->c,    +1); break;
		case '$':  scanner_action(in, 0, XWORD_DOLLAR,     in->c,    +1); break;
		case '"':  scanner_action(in, 0, XWORD_DQUOTE,     in->c,    +1); break;
		case '\'': scanner_action(in, 0, XWORD_SQUOTE,     in->c,    +1); break;
		case '\\': scanner_action(in, 0, XWORD_ESC,        in->c,    +1); break;
		default:   scanner_action(in, 0, 0,                in->c,    +1); break;
		case EOF:  scanner_action(in, 0, -1,               0,         0); break;
		}
		break;
	case XWORD_DOLLAR: switch (in->c) {
		case '(': scanner_action(in, 0, XWORD_SUBSHELL,    in->c,    +1); break;
		default:  scanner_action(in, 0, -1,                0,         0); break;
		case EOF: scanner_action(in, 0, -1,                0,         0); break;
		}
		break;
	default:
		E("unknown state");
	}

	if (!in->ready)
		return;

	if (in->ready->type == TOK_WORD) {
		struct str *tok = in->ready;
		switch (in->last_tok[0]) {
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

		switch (tok->type) {
		case TOK_IF:
			scanner_push_state(in, XIF);
			break;
		case TOK_FI:
			assert(scanner_current_state(in) == XIF);
			scanner_pop_state(in);
			break;
		case TOK_FOR:
			scanner_push_state(in, XFOR);
			break;
		case TOK_DO:
			assert(scanner_current_state(in) == XFOR);
			scanner_push_state(in, XDO);
			break;
		case TOK_DONE:
			assert(scanner_current_state(in) == XDO);
			scanner_pop_state(in);
			assert(scanner_current_state(in) == XFOR);
			scanner_pop_state(in);
			break;
		default:
			break;
		}
	}
	in->last_tok[1] = in->last_tok[0];
	in->last_tok[0] = in->ready->type;
	return;
}



#ifdef TEST
void read_line(struct str *line)
{
	line->size = 0;
	while (1) {
		int c = getchar();
		if (c == EOF)
			break;
		str_push(line, c);
		if (c == '\n')
			break;
	}
}

void str_push_string(struct str *str, const char *s)
{
	while (*s) {
		str_push(str, *s);
		s++;
	}
}

int main(int argc, char **argv) {
	//const char *s = argc >= 2 ? argv[1] : "a b c\n";

	struct input_scanner in = {0};
	int i;
	struct str *tok[128];
	int toksize;
	struct str *line;
	int n = 0;
	line = str_new();
redo:
	n++;
	printf("$ ");
	read_line(line);
	//str_push_string(line, "a\nb\n( cd foo; bar \n)\n");
	scanner_init(&in);
	scanner_refill(&in, line->s, line->size);

	memset(tok, 0, sizeof(tok));
	toksize = 0;

	while (1) {
		printf("\n\n---\n");
		scanner_step(&in);
		if (in.ready) {
			tok[toksize++] = in.ready;
			printf("%s <%s>\n", TOK[in.ready->type], in.ready->s);
			in.ready = NULL;
		}

		printf("STATE STACK:\n");
		for (i = 0; i < in.state_size; i++) {
			printf("\t%02d: %s\n", i, STS[in.state[i]]);
		}

		if (scanner_is_complete(&in)) {
			printf("DONE!\n");
			if (in.err)
				printf("ERROR\n");
			for (i = 0; i < toksize; i++) {
				printf("TOK: %s <%s>\n", TOK[tok[i]->type], tok[i]->s);
			}
			printf("================\n\n");
			goto redo;
		} else if (scanner_needs_more_input(&in)) {
			printf("> ");
			read_line(line);
			scanner_refill(&in, line->s, line->size);
		}
	}

	return 0;
}
#endif
