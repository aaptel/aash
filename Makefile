all: aash

lemon: lemon.c
	gcc -o $@ $<

parser.c: parser.y lempar.c lemon
	./lemon $<

%.o: %.c
	gcc -ggdb3 -Wall -o $@ -c $<
parser.o: parser.c ast.h dbg.h
aash.o: aash.c ast.h dbg.h
aash: aash.o parser.o
	gcc -ggdb3 -Wall -o $@ $^
