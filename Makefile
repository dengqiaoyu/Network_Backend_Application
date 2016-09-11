CC = gcc
CFLAGS = -g -Wall -Werror

all: lisod

lisod.o: lisod.c lisod.h log.h
	$(CC) $(CFLAG) -c lisod.c

log.o: log.c log.h

lisod: lisod.o log.o

clean:
	rm *.o lisod
