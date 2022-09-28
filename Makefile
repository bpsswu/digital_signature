BL1: BL1.o
	gcc -o BL1 BL1.o -lssl -lcrypto

BL1.o: BL1.c
	gcc -c -o BL1.o BL1.c

clean:
	rm BL1 *.o