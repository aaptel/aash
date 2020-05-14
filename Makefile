DEBUG = 1

all: aash

lemon: lemon.c
	gcc -o $@ $<

parser.c: parser.y lempar.c lemon
	rm -f parser.c parser.h
	./lemon -p $< || test -e parser.c
parser.o: parser.c ast.h dbg.h
	gcc -Wall -Wno-unused-variable -ggdb3 -c -o $@ $<


%.o: %.c
	gcc -ggdb3 -Wall `[ $(DEBUG) = 0 ] && echo -DNDEBUG` -o $@ -c $<
aash.o: aash.c ast.h dbg.h parser.c
aash: aash.o parser.o
	gcc -ggdb3 -Wall -o $@ $^

clean:
	rm -f lemon aash *.o parser.c parser.h parser.out

test: aash
	python3 test.py

.PHONY: all clean test
