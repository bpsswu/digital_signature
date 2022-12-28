CC = gcc
CFLAGS = 
LDFLAGS = -lcrypto

.SUFFIXES : .c .o
.c.o :
	$(CC) -c $(CFLAGS) $<

ALL = signing

all: $(ALL)

signing: signing.o
	$(CC) -o $@ $< $(LDFLAGS)

clean :
	rm -rf *.o $(ALL) signed_file
