#ifndef PING_H
#define PING_H
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
// #include <limits.h>
#include <resolv.h>

#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <string.h>

#include <time.h>
// #include <float.h>
#include <math.h>

#include <errno.h>

#include <sys/time.h>

unsigned short checksum(void *buffer, int len);

#endif
