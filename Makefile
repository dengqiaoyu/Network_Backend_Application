CC = gcc
CFLAGS = -I. -lssl
DEPS = y.tab.h log.h hlp_func.h proxy.h comm_with_server.h param_init.h server_to_client.h constants.h dbg.h
OBJ = y.tab.o lex.yy.o parse.o proxy.o comm_with_server.o hlp_func.o param_init.o pool.o server_to_client.o dbg.o
FLAGS = -g -Wall -Werror

default:all

all: proxy

lex.yy.c: lexer.l
	flex $^

y.tab.c: parser.y
	yacc -d $^

%.o: %.c $(DEPS)
	$(CC) $(FLAGS) -c -o $@ $< $(CFLAGS)

proxy: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f *~ *.o proxy lex.yy.c y.tab.c y.tab.h