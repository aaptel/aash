#pragma once


struct input_scanner {
	int state[128];
	int state_size;
	int input_pos;
	int input_size;
	int c;
	int last_tok[2];
	const char *input;
	struct str *ready;
	struct str *word;
	bool err;
};

bool scanner_is_complete(struct input_scanner *in);
bool scanner_needs_more_input(struct input_scanner *in);
void scanner_refill(struct input_scanner *in, const char *s, int len);
void scanner_init(struct input_scanner *in);
void scanner_step(struct input_scanner *in);
int scanner_push_state(struct input_scanner *in, int state);

enum {XAND=2, XCOMMENT, XGT, XOR, XSTART, XWORD, XWORD_DOLLAR, XWORD_DQUOTE, XWORD_DQUOTE_ESC, XWORD_ESC, XWORD_SQUOTE, XWORD_SUBSHELL, XIF, XTHEN, XDO, XFOR, XLPAREN, XLBRACE, XNUM_OR_WORD};
