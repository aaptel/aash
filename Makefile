all: aash

lemon: lemon.c
	gcc -o $@ $<

parser.c: parser.y lempar.c lemon
	./lemon $<

%.o: %.c
	gcc -ggdb3 -Wall -o $@ -c $<
parser.o: parser.c ast.h dbg.h
aash.o: aash.c ast.h dbg.h parser.c
aash: aash.o parser.o
	gcc -ggdb3 -Wall -o $@ $^

clean:
	rm -f lemon aash *.o parser.c parser.h parser.out

test:
	python3 test.py

.PHONY: all clean test
