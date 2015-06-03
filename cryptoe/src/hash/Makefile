CFLAGS = -I../include -Wall -Wstrict-prototypes -Werror -g
LDFLAGS = -lbsd
CC = gcc

OBJS = sha2.o SHAd256.o test.o

test: $(OBJS)
	$(CC) $(CFLAGS) -o test $(OBJS) $(LDFLAGS)

sha2.o:
	$(CC) $(CFLAGS) -c sha2.c

SHAd256.o:
	$(CC) $(CFLAGS) -c SHAd256.c

test.o:
	$(CC) $(CFLAGS) -c test.c

clean:
	rm -f test $(OBJS)
