CC=gcc
CFLAGS = -std=c99 -g -c -Wall -pedantic

ping: ping.o ping_utils.o
	$(CC) -o ping ping.o ping_utils.o

clean: 
	rm *.o ping