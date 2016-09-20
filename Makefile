CC = gcc
CFLAGS = -I.
DEPS = lisod.h y.tab.h
OBJ = y.tab.o lex.yy.o parse.o log.o lisod.o
FLAGS = -g -Wall

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

# all: lisod

# lisod.o: lisod.c lisod.h log.h
# 	$(CC) $(CFLAG) -c lisod.c

# log.o: log.c log.h

# lisod: lisod.o log.o

# clean:
# 	rm *.o lisod

# default: all

# all: lisod

# y.tab.c: parser.y
# 	yacc -d $^

# lex.yy.c: lexer.l
# 	flex $^

# lex.yy.o: lex.yy.c parse.h y.tab.h
# 	$(CC) $(FLAGS) -c -o $@ $< $(CFLAGS)

# y.tab.o: y.tab.c parse.h y.tab.h
# 	$(CC) $(FLAGS) -c -o $@ $< $(CFLAGS)

# parse.o: parse.c parse.h y.tab.h
# 	$(CC) $(FLAGS) -c -o $@ $< $(CFLAGS)

# lisod.o: lisod.c lisod.h log.h parse.h
# 	$(CC) $(FLAGS) $(WERRORFLAGS) -c lisod.c

# log.o: log.c log.h
# 	$(CC) $(FLAGS) $(WERRORFLAGS) -c log.c

# lisod: y.tab.o lex.yy.o parse.o log.o lisod.o
# 	$(CC) -o $@ $^ $(CFLAGS)

# clean:
# 	rm -f *~ *.o lisod lex.yy.c y.tab.c y.tab.h