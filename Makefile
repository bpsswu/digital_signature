CC = gcc
CFLAGS = 
LDFLAGS = -lcrypto
# -lssl
TARGET = BL1
OBJS = BL1.o

.SUFFIXES : .c .o
.c.o :
	$(CC) -c $(CFLAGS) $<

$(TARGET) : $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	
clean:
	rm -f core $(TARGET) $(OBJS)