CC = gcc
CFLAGS = -I.
DEPS = y.tab.h pdef_type.h dbg_func.h log.h lisod.h
OBJ = y.tab.o lex.yy.o parse.o log.o time_now.o dbg_func.o lisod.o
FLAGS = -g -Wall -Werror

default:all

all: lisod

lex.yy.c: lexer.l
	flex $^

y.tab.c: parser.y
	yacc -d $^

%.o: %.c $(DEPS)
	$(CC) $(FLAGS) -c -o $@ $< $(CFLAGS)

lisod: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f *~ *.o lisod lex.yy.c y.tab.c y.tab.h