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
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <string.h>

#include <time.h>
#include <stdbool.h>
// #include <float.h>
#include <math.h>

#include <errno.h>

#include <sys/time.h>
#define ICMP_LEN 16
#define ICMP_HDRLEN 8
#define IP6_HDRLEN 40

unsigned short checksum(void *buffer, int len);
struct timeval diff_time(struct timeval left, struct timeval right);
uint16_t
icmp6_checksum(struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen);
char *allocate_strmem(int len);

#endif
