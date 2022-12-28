CC = gcc
CFLAGS = 
LDFLAGS = 

.SUFFIXES : .c .o
.c.o :
	$(CC) -c $(CFLAGS) $<

ALL = dummy

all: $(ALL)

dummy: dummy.o
	$(CC) -o $@ $< $(LDFLAGS)

clean :
	rm -rf *.o $(ALL)