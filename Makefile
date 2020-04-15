CC=gcc
CFLAGS = -std=c99 -g -c -Wall -pedantic #-D_POSIX_SOURCE -D_GNU_SOURCE

ping: ping.o ping_utils.o
	$(CC) -o ping ping.o ping_utils.o

ping_utils.o: ping_utils.o ping_utils.h 
	$(CC) $(CFLAGS) ping_utils.c

ping.o: ping.c ping_utils.h
	$(CC) $(CFLAGS) ping.c

clean: 
	rm *.o ping