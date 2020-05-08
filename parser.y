%include {
#include "dbg.h"
#include "ast.h"
#define IS_BG(t) ((t) && (t)->type == TOK_BG)
}

%syntax_error {
	W("syntax error");
}

%extra_argument {struct expr **root}
%token_prefix TOK_
%default_type {struct expr *}
%token_type {struct str *}
%type separator_op {struct str *}
%type separator {struct str *}

program(R) ::= linebreak complete_commands(E) linebreak. { R = E; *root = R;}
program(R) ::= linebreak.                                { R = expr_new(EXPR_PROG); *root = R;}

complete_commands(R) ::= complete_commands(A) newline_list complete_command(E). {
	R = A;
	PUSH(&R->prog, cmds, E);
}
complete_commands(R) ::= complete_command(E). {
	R = expr_new(EXPR_PROG);
	PUSH(&R->prog, cmds, E);
}

complete_command(R) ::= list(E) separator_op(S). {
	R = E;
	assert(E->type == EXPR_PROG);
	E->prog.cmds[E->prog.size-1]->run_in_bg = IS_BG(S);
}
complete_command(R) ::= list(E). { R = E; }

list(R) ::= and_or(E). {
	R = expr_new(EXPR_PROG);
	PUSH(&R->prog, cmds, E);
}
list(R) ::= list(A) separator_op(S) and_or(B). {
	R = A;
	assert(A->type == EXPR_PROG);
	A->prog.cmds[A->prog.size-1]->run_in_bg = IS_BG(S);
	PUSH(&R->prog, cmds, B);
}

and_or(R) ::= pipeline(E). { R = E; }
and_or(R) ::= and_or(A) AND pipeline(B). {
	R = expr_new(EXPR_AND);
	R->and_or.left = A;
	R->and_or.right = B;
}
and_or(R) ::= and_or(A) OR pipeline(B).  {
	R = expr_new(EXPR_OR);
	R->and_or.left = A;
	R->and_or.right = B;
}

pipeline(R) ::= pipe_sequence(E). { R = E; }
pipeline(R) ::= NOT pipe_sequence(E). {
	R = expr_new(EXPR_NOT);
	R->not.expr = E;
}

pipe_sequence(R) ::= command(E). { R = E; }
pipe_sequence(R) ::= pipe_sequence(E) PIPE linebreak command(C). {
	R = expr_new(EXPR_PIPE);
	R->pipe.left = E;
	R->pipe.right = C;
}

command(R) ::= simple_command(E). { R = E; }
command(R) ::= subshell(E). { R = E; }

subshell(R) ::= LPAREN compound_list(E) RPAREN. {
	R = expr_new(EXPR_SUB);
	R->sub.expr = E;
}

compound_list(R) ::= linebreak term(E). { R = E; }
compound_list(R) ::= linebreak term(E) separator(S). {
	R = E;
	assert(E->type == EXPR_PROG);
	E->prog.cmds[E->prog.size-1]->run_in_bg = IS_BG(S);
}

term(R) ::= term(T) separator(S) and_or(E). {
	R = T;
	assert(T->type == EXPR_PROG);
	T->prog.cmds[T->prog.size-1]->run_in_bg = IS_BG(S);
	PUSH(&R->prog, cmds, E);
}
term(R) ::= and_or(E). {
	R = expr_new(EXPR_PROG);
	PUSH(&R->prog, cmds, E);
}

simple_command(R) ::= WORD(W). {
	R = expr_new(EXPR_SIMPLE_CMD);
	PUSH(&R->simple_cmd, words, W);
}
simple_command(R) ::= simple_command(E) WORD(W). {
	R = E;
	PUSH(&R->simple_cmd, words, W);
}

separator_op(R) ::= SEMICOL(T). { R = T; }
separator_op(R) ::= BG(T). { R = T; }

separator(R) ::= separator_op(S) linebreak. { R = S; }
separator(R) ::= newline_list. { R = NULL; }

newline_list ::= NEWLINE.
newline_list ::= newline_list NEWLINE.

linebreak ::= newline_list.
linebreak ::= .
