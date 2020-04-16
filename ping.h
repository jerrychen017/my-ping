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
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
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
#define DATA_LEN 32

// ICMPv6 echo request payload
struct icmp6_echo_request
{
    unsigned short icmp6_echo_sequence;
    unsigned short icmp6_echo_id;
};

unsigned short icmp6_checksum(struct sockaddr_in6 *ipv6_src_addr, struct sockaddr_in6 *ipv6_dest_addr, char *icmp6_pkt, int icmp6_pkt_len);
unsigned short checksum(void *buffer, int len);
struct timeval diff_time(struct timeval left, struct timeval right);

#endif
