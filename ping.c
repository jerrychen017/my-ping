#include "ping.h"

/**
 * An implementation of the PING program
 */
int main(int argc, char *argv[])
{
    // display help menu
    if (argc < 2)
    {
        printf("usage:\n");
        return 0;
    }
    // host name or ip address
    const char *host = argv[1];
    int port = 10;
    bool use_ipv6 = false;
    int ttl = -1;
    bool use_ttl = false;
    int ret; // holds returned status values

    // read the rest args
    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "-TTL") == 0)
        {
            if (i == argc - 1)
            { // last argument
                // print menu
                return 1;
            }
            else
            {
                ttl = atoi(argv[i + 1]);
                if ((ttl == 0 && strcmp(argv[i + 1], "0") != 0) || ttl < 0 || ttl > 255)
                { // invalid conversion if return value is 0 and input string is not "0"
                    //report error
                    printf("ping: invalid TTL: `%s`\n", argv[i + 1]);
                    return 1;
                }
                else
                { //valid conversion
                    use_ttl = true;
                }
                i++; // skip next iteration
            }
        }
        else if (strcmp(argv[i], "-IPV6") == 0)
        {
            use_ipv6 = true;
        }
        else
        {
            // invalid argument
            // display menu
            return 1;
        }
    }

    // variables for IPv4 ICMP
    struct sockaddr_in ping_address;
    struct sockaddr_in reply_address;
    socklen_t rely_address_len;
    struct icmp ping_packet;
    char recv_ip_packet[192];
    struct ip *recv_ip_ptr;
    struct icmp *recv_icmp_ptr;
    struct hostent *hostname;

    // variables for IPv6
    uint8_t recv_icmp6_packet[ICMPV6_PLD_MAXLEN];                                                  // received ICMPv6 packet
    int icmp6_pkt_len = sizeof(struct icmp6_hdr) + sizeof(struct icmp6_echo_request) + DATA_LEN;   // total length to ICMPv6 packet
    char icmp6_pkt[icmp6_pkt_len];                                                                 // ICMPv6 packet to be sent
    struct icmp6_echo_request *recv_icmp6_req_ptr, *rend_icmp6_req_ptr = NULL;                     // points to ICMPv6 type field
    struct sockaddr_in6 ping6_address, ping6_reply_address, *ipv6_dest_addr, *ipv6_src_addr;       // addresses
    socklen_t recv_ipv6_addr_len, ipv6_dest_addr_len, ipv6_addr_len = sizeof(struct sockaddr_in6); // socket len variables
    struct icmp6_hdr send_icmp6_hdr, *recv_icmp6_hdr_ptr, *send_icmp6_hdr_ptr = NULL;              // ICMPv6 header and pointers to header
    char source_ip[INET6_ADDRSTRLEN], dest_ip[INET6_ADDRSTRLEN], target[INET6_ADDRSTRLEN];         // IP addresses
    struct addrinfo hints, *res;
    char src_addr_str[50]; // source address string
    int tmp_sk;            // temporary socket for getting source address
    struct ifreq ifr;

    // uesd for both IPv6 and IPv4
    int pid = getpid(); // process id
    int sk;             // socket file descriptor
    struct timeval time_sent, time_received;
    struct timeval timeout; // timeout for select loop
    int num;                // for select
    int num_sent = 0;
    int num_received = 0;
    int recv_seq_num; // received sequence number
    int recv_type;    // received type
    int recv_code;    // received code
    fd_set mask;
    fd_set read_mask;

    if (use_ipv6)
    {
        // initialize variables
        // prepare an ICMP6 packet
        memset(icmp6_pkt, 0, icmp6_pkt_len * sizeof(char));
        memset(source_ip, 0, INET6_ADDRSTRLEN * sizeof(char));
        memset(dest_ip, 0, INET6_ADDRSTRLEN * sizeof(char));
        memset(target, 0, INET6_ADDRSTRLEN * sizeof(char));
        memset(recv_icmp6_packet, 0, ICMPV6_PLD_MAXLEN * sizeof(char));

        // setup socket
        sk = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sk < 0)
        {
            printf("IPv6: socket error\n");
            exit(1);
        }

        tmp_sk = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        ifr.ifr_addr.sa_family = AF_INET6;
        // get IP address attached to "eth0"
        strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
        ioctl(tmp_sk, SIOCGIFADDR, &ifr);
        close(tmp_sk); // close temporary socket
        ipv6_src_addr = (struct sockaddr_in6 *)&ifr.ifr_addr;
        inet_ntop(AF_INET6, &(ipv6_src_addr->sin6_addr), src_addr_str, sizeof(src_addr_str));
        strcpy(source_ip, src_addr_str); // get source ip

        strcpy(target, argv[1]);
        // prepare hints for getaddrinfo().
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_RAW;
        hints.ai_protocol = IPPROTO_ICMPV6;
        hints.ai_flags = AI_CANONNAME;

        // resolve target
        ret = getaddrinfo(target, NULL, &hints, &res);
        if (ret != 0)
        {
            printf("Error occurred in getaddrinfo()\n");
            exit(1);
        }

        ipv6_dest_addr = (struct sockaddr_in6 *)res->ai_addr;
        ipv6_dest_addr_len = res->ai_addrlen;

        if (inet_ntop(AF_INET6, &(ipv6_dest_addr->sin6_addr), dest_ip, INET6_ADDRSTRLEN) == NULL)
        {
            ret = errno;
            printf("Error occurred in inet_ntop() when getting dest_ip");
            exit(1);
        }

        // init ping_address
        memset(&ping6_address, 0, sizeof(struct sockaddr_in6));
        ping6_address.sin6_family = AF_INET6;
        memcpy(&ping6_address.sin6_addr, &(ipv6_dest_addr->sin6_addr), sizeof(ping6_address.sin6_addr));
        ping6_address.sin6_port = htons(port);

        // initialize ICMPv6 header
        send_icmp6_hdr_ptr = (struct icmp6_hdr *)icmp6_pkt;
        send_icmp6_hdr_ptr->icmp6_type = 128; // ECHO_REQUEST type
        send_icmp6_hdr_ptr->icmp6_code = 0;   // ECHO_REQUEST code
        send_icmp6_hdr_ptr->icmp6_cksum = 0;
        rend_icmp6_req_ptr = (struct icmp6_echo_request *)(icmp6_pkt + sizeof(struct icmp6_hdr));
        rend_icmp6_req_ptr->icmp6_echo_id = pid;
        rend_icmp6_req_ptr->icmp6_echo_sequence = 0;
    }
    else
    {
        hostname = gethostbyname(host);
        if (!hostname)
        {
            printf("cannot resolve hostname\n");
            exit(1);
        }
        memset(&ping_address, 0, sizeof(struct sockaddr_in)); // init ping_address
        ping_address.sin_family = AF_INET;
        memcpy(&ping_address.sin_addr, hostname->h_addr, sizeof(ping_address.sin_addr));
        ping_address.sin_port = htons(port);
        // setup socket
        sk = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sk < 0)
        {
            printf("ping: socket error\n");
            exit(1);
        }
    }

    FD_ZERO(&mask);
    FD_SET(sk, &mask);
    for (;;)
    {
        read_mask = mask;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        num = select(FD_SETSIZE, &read_mask, NULL, NULL, &timeout);
        if (num > 0)
        {
            if (FD_ISSET(sk, &read_mask))
            {
                // receive an ICMP packet
                if (use_ipv6)
                {
                    ret = recvfrom(sk, recv_icmp6_packet, icmp6_pkt_len, 0,
                                   (struct sockaddr *)&ping6_reply_address, &recv_ipv6_addr_len);
                    recv_icmp6_hdr_ptr = (struct icmp6_hdr *)(recv_icmp6_packet);
                    recv_icmp6_req_ptr = (struct icmp6_echo_request *)(recv_icmp6_packet + sizeof(struct icmp6_hdr));
                    recv_type = recv_icmp6_hdr_ptr->icmp6_type; // get received ICMPv6 type
                    recv_code = recv_icmp6_hdr_ptr->icmp6_code; // get received ICMPv6 code

                    if (recv_type == ICMP6_ECHO_REPLY && recv_code == 0)
                    { // ICMP6_ECHO_REPLY 129
                        // record current time and report
                        gettimeofday(&time_received, NULL);
                        num_received++;
                        struct timeval rtt = diff_time(time_received, time_sent);
                        double rtt_msec = rtt.tv_sec * 1000 + ((double)rtt.tv_usec) / 1000;

                        printf("Report: RTT of a PING packet is %f ms with sequence number %d\n", rtt_msec, recv_icmp6_req_ptr->icmp6_echo_sequence);
                        printf("%d packets lost\n", num_sent - num_received);
                    }
                    else
                    {
                        printf("type is %d and code is %d", recv_type, recv_code);
                    }
                    // verbose mode ?
                    // for (int i = 0; i < 60; i++)
                    // {
                    //     printf("  %02x", recv_icmp6_packet[i] & 0xff);
                    // }
                }
                else
                {
                    ret = recvfrom(sk, recv_ip_packet, sizeof(recv_ip_packet), 0,
                                   (struct sockaddr *)&reply_address, &rely_address_len);
                    recv_ip_ptr = (struct ip *)recv_ip_packet;
                    recv_icmp_ptr = recv_ip_packet + (recv_ip_ptr->ip_hl << 2);
                    recv_type = recv_icmp_ptr->icmp_type; // get ICMPv4 type
                    recv_code = recv_icmp_ptr->icmp_code; // get ICMPv4 code
                    if (recv_type == ICMP_ECHOREPLY && recv_code == 0)
                    { // ICMP_ECHOREPLY 0
                        // record current time and report
                        gettimeofday(&time_received, NULL);
                        num_received++;
                        struct timeval rtt = diff_time(time_received, time_sent);
                        double rtt_msec = rtt.tv_sec * 1000 + ((double)rtt.tv_usec) / 1000;
                        printf("Report: RTT of a PING packet is %f ms with sequence number %d\n", rtt_msec, recv_icmp_ptr->icmp_seq);
                        printf("%d packets lost\n", num_sent - num_received);
                    }
                }
            }
        }
        else
        {
            // sending an ICMP packet
            // sending a packet
            if (use_ipv6)
            {
                rend_icmp6_req_ptr->icmp6_echo_sequence = num_sent;
                send_icmp6_hdr_ptr->icmp6_cksum = icmp6_checksum(ipv6_src_addr, ipv6_dest_addr, icmp6_pkt, icmp6_pkt_len);
                ret = sendto(sk, icmp6_pkt, icmp6_pkt_len, 0,
                             (struct sockaddr *)&ping6_address, sizeof(struct sockaddr_in6));
                printf("IPV6 packet sent\n");
            }
            else
            {
                memset(&ping_packet, 0, sizeof(ping_packet));
                ping_packet.icmp_type = ICMP_ECHO;
                ping_packet.icmp_code = 0;
                ping_packet.icmp_id = pid;
                ping_packet.icmp_seq = num_sent;
                ping_packet.icmp_cksum = checksum(&ping_packet, sizeof(ping_packet));

                ret = sendto(sk, &ping_packet, sizeof(ping_packet), 0,
                             (struct sockaddr *)&ping_address, sizeof(ping_address));
            }

            gettimeofday(&time_sent, NULL);
            num_sent++;
        }
    }
    return 0;
}

// calculate ICMPv6 checksum
unsigned short icmp6_checksum(struct sockaddr_in6 *ipv6_src_addr, struct sockaddr_in6 *ipv6_dest_addr, char *icmp6_pkt, int icmp6_pkt_len)
{
    // calculate checksum
    char tmp[IP_MAXPACKET], *tmp_ptr;
    tmp_ptr = tmp;
    int total_len = 0;

    // copy source address
    memcpy(tmp_ptr, &(ipv6_src_addr->sin6_addr), sizeof(struct in6_addr));
    tmp_ptr += sizeof(struct in6_addr);
    total_len += sizeof(struct in6_addr);

    // copy destination address
    memcpy(tmp_ptr, &(ipv6_dest_addr->sin6_addr), sizeof(struct in6_addr));
    tmp_ptr += sizeof(struct in6_addr);
    total_len += sizeof(struct in6_addr);

    // copy ICMPv6 packet length
    int icmp6_len = htonl(ipv6_src_addr);
    memcpy(tmp_ptr, &icmp6_len, sizeof(icmp6_len));
    tmp_ptr += sizeof(icmp6_len);
    total_len += sizeof(icmp6_len);

    // set three bytes to 0
    memset(tmp_ptr, 0, 3);
    tmp_ptr += 3;
    tmp_ptr += 3;

    // copy next hop header
    char protocol = IPPROTO_ICMPV6;
    memcpy(tmp_ptr, &protocol, sizeof(protocol));
    tmp_ptr += sizeof(protocol);
    total_len += sizeof(protocol);

    // copy the ICMP header and data
    memcpy(tmp_ptr, icmp6_pkt, icmp6_pkt_len);
    tmp_ptr += icmp6_pkt_len;
    total_len += icmp6_pkt_len;

    for (int i = 0; i < icmp6_pkt_len % 2; i++)
    {
        *tmp_ptr = 0;
        tmp_ptr++;
        total_len++;
    }
    // finally, calculate the checksum of ICMPv6 packet prepended with fields of IP header
    return checksum(tmp, total_len);
}

// calculate checksum for ICMP4
unsigned short checksum(void *ptr, int len)
{
    int sum = 0;
    int count_to = (len / 2) * 2;
    int count = 0;
    unsigned short *buffer = ptr;
    while (count < count_to)
    {
        sum += *(buffer++);
        count += 2;
    }

    if (count_to < len)
    {
        sum += *buffer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

// calculates the time difference between the left and right timeval
struct timeval diff_time(struct timeval left, struct timeval right)
{
    struct timeval diff;
    diff.tv_sec = left.tv_sec - right.tv_sec;
    diff.tv_usec = left.tv_usec - right.tv_usec;
    if (diff.tv_usec < 0)
    {
        diff.tv_usec += 1000000;
        diff.tv_sec--;
    }
    if (diff.tv_sec < 0)
    {
        diff.tv_sec = diff.tv_usec = 0;
    }
    return diff;
}
