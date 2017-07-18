CC = gcc
CFLAGS = -I. -Isrc/hashtable -Isrc/nameserver -Isrc/proxy
DEPS = src/proxy/y.tab.h src/proxy/log.h src/proxy/hlp_func.h src/proxy/proxy.h src/proxy/comm_with_server.h src/proxy/param_init.h src/proxy/server_to_client.h src/proxy/constants.h src/proxy/dbg.h src/proxy/parse_manifest.h src/proxy/throughput.h src/hashtable/linklist.h src/hashtable/hashtable.h src/proxy/mydns.h src/proxy/dns.h src/nameserver/graph.h src/nameserver/dijkstra.h src/nameserver/round_robin.h src/nameserver/nameserver.h
OBJ1 = src/proxy/y.tab.o src/proxy/lex.yy.o src/proxy/parse.o src/proxy/proxy.o src/proxy/comm_with_server.o src/proxy/hlp_func.o src/proxy/param_init.o src/proxy/pool.o src/proxy/server_to_client.o src/proxy/dbg.o src/proxy/parse_manifest.o src/proxy/throughput.o src/hashtable/linklist.o src/hashtable/hashtable.o src/proxy/mydns.o
OBJ2 = src/nameserver/graph.o src/hashtable/linklist.o src/hashtable/hashtable.o src/nameserver/dijkstra.o src/nameserver/round_robin.o src/nameserver/nameserver.o
FLAGS = -g -Wall -Werror

default:all

all: proxy nameserver

src/proxy/lex.yy.c: src/proxy/lexer.l
	flex -o src/proxy/lex.yy.c $^

src/proxy/y.tab.c: src/proxy/parser.y
	yacc -d -o src/proxy/y.tab.c $^

%.o: %.c $(DEPS)
	$(CC) $(FLAGS) -c -o $@ $< $(CFLAGS)

proxy: $(OBJ1)
	$(CC) -o $@ $^ $(CFLAGS)

nameserver: $(OBJ2)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f src/proxy/*~ src/proxy/*.o proxy nameserver src/proxy/lex.yy.c src/proxy/y.tab.c src/proxy/y.tab.h src/hashtable/*~ src/hashtable/*.o
