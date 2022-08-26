sha256: sha256_main.o
	gcc -o sha256 sha256_main.o -lssl -lcrypto

sha256_main.o: sha256_main.c
	gcc -c -o sha256_main.o sha256_main.c

clean:
	rm *.o