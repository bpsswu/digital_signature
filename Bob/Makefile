CC = gcc
CFLAGS = 
LDFLAGS = -lcrypto

.SUFFIXES : .c .o
.c.o :
	$(CC) -c $(CFLAGS) $<

ALL = verifying

all: $(ALL)

verifying: verifying.o
	$(CC) -o $@ $< $(LDFLAGS)

clean :
	rm -rf *.o $(ALL) dummy