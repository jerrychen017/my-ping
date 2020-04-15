CC=gcc
CFLAGS = -std=c99 -g -c -Wall -pedantic #-D_POSIX_SOURCE -D_GNU_SOURCE

ping: ping.o
	$(CC) -o ping ping.o

ping.o: ping.c 
	$(CC) $(CFLAGS) ping.c

clean: 
	rm *.o ping