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
    int ret; // holds returned values

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
    uint8_t *recv_icmp6_packet;                    // received ICMPv6 packet
    char *icmp6_pkt;                               // ICMPv6 packet to be sent
    int icmp6_pkt_len;                             // total length to ICMPv6 packet
    struct icmp6_echo_request *recv_icmp6_req_ptr; // points to ICMPv6 type field

    struct sockaddr_in6 ping_address6, *ipv6;
    socklen_t ipv6_len;
    struct sockaddr_in6 reply_address6;
    socklen_t rely_address6_len = sizeof(struct sockaddr_in6);
    struct icmp6_hdr send_icmp6_hdr;
    struct icmp6_hdr *recv_icmp6_hdr_ptr;
    char *source_ip, *dest_ip, *target;
    struct addrinfo hints, *res;
    void *tmp;
    struct sockaddr_in6 *in6;

    // uesd for both IPv6 and IPv4
    int pid = getpid(); // process id
    int num;
    int sk; // socket file descriptor
    int recv_sk;
    struct timeval time_sent, time_received;
    struct timeval timeout; // timeout for select loop
    unsigned short num_sent = 0;
    int num_received = 0;
    fd_set mask;
    fd_set read_mask;

    if (use_ipv6)
    {
        // initialize memory for variables
        source_ip = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        memset(source_ip, 0, INET6_ADDRSTRLEN * sizeof(char));

        dest_ip = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        memset(dest_ip, 0, INET6_ADDRSTRLEN * sizeof(char));

        target = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        memset(target, 0, INET6_ADDRSTRLEN * sizeof(char));

        recv_icmp6_packet = (uint8_t *)malloc(ICMPV6_PLD_MAXLEN * sizeof(uint8_t));
        memset(recv_icmp6_packet, 0, ICMPV6_PLD_MAXLEN * sizeof(uint8_t));

        // setup socket
        sk = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sk < 0)
        {
            printf("IPv6: socket error\n");
            exit(1);
        }

        char addr[50];
        int fd;
        struct ifreq ifr;
        fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        ifr.ifr_addr.sa_family = AF_INET6;
        // get IP address attached to "eth0"
        strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
        ioctl(fd, SIOCGIFADDR, &ifr);
        close(fd);
        in6 = (struct sockaddr_in6 *)&ifr.ifr_addr;
        inet_ntop(AF_INET6, &(in6->sin6_addr), addr, sizeof(addr));
        // printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
        printf("addr is %s", addr);
        strcpy(source_ip, addr);

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

        ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        ipv6_len = res->ai_addrlen;

        if (inet_ntop(AF_INET6, &(ipv6->sin6_addr), dest_ip, INET6_ADDRSTRLEN) == NULL)
        {
            ret = errno;
            printf("Error occurred in inet_ntop() when getting dest_ip");
            exit(1);
        }
        printf("dest addr is !!! %s", dest_ip);
        // freeaddrinfo(res);

        // init ping_address
        memset(&ping_address6, 0, sizeof(struct sockaddr_in6));
        ping_address6.sin6_family = AF_INET6;
        memcpy(&ping_address6.sin6_addr, &(ipv6->sin6_addr), sizeof(ping_address6.sin6_addr));
        // memcpy(&ping_address6.sin6_addr, hostname->h_addr, sizeof(ping_address6.sin6_addr));
        ping_address6.sin6_port = htons(port);
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
                if (use_ipv6)
                {
                    int len;
                    ret = recvfrom(sk, recv_icmp6_packet, icmp6_pkt_len, 0,
                                   (struct sockaddr *)&reply_address6, &len);
                    printf("received num is %d\n", ret);
                    recv_icmp6_hdr_ptr = (struct icmp6_hdr *)(recv_icmp6_packet);
                    recv_icmp6_req_ptr = (struct icmp6_echo_request *)(recv_icmp6_packet + sizeof(struct icmp6_hdr));
                    for (int i = 0; i < 60; i++)
                    {
                        printf("  %02x", recv_icmp6_packet[i] & 0xff);
                    }

                    // record current time and report
                    gettimeofday(&time_received, NULL);
                    num_received++;
                    struct timeval rtt = diff_time(time_received, time_sent);
                    double rtt_msec = rtt.tv_sec * 1000 + ((double)rtt.tv_usec) / 1000;

                    printf("Report: RTT of a PING packet is %f ms with sequence number %d\n", rtt_msec, recv_icmp6_req_ptr->icmp6_echo_sequence);
                    printf("%d packets lost\n", num_sent - num_received);

                    printf("type is %d code is %d\n", recv_icmp6_hdr_ptr->icmp6_type, recv_icmp6_hdr_ptr->icmp6_code);
                }
                else
                {
                    ret = recvfrom(sk, recv_ip_packet, sizeof(recv_ip_packet), 0,
                                   (struct sockaddr *)&reply_address, &rely_address_len);
                    // int server_ip = client_addr.sin_addr.s_addr;
                    recv_ip_ptr = (struct ip *)recv_ip_packet;
                    recv_icmp_ptr = recv_ip_packet + (recv_ip_ptr->ip_hl << 2);
                    // record current time and report
                    gettimeofday(&time_received, NULL);
                    num_received++;
                    struct timeval rtt = diff_time(time_received, time_sent);
                    double rtt_msec = rtt.tv_sec * 1000 + ((double)rtt.tv_usec) / 1000;
                    printf("Report: RTT of a PING packet is %f ms with sequence number %d\n", rtt_msec, recv_icmp_ptr->icmp_seq);
                    printf("%d packets lost\n", num_sent - num_received);
                    if (recv_icmp_ptr->icmp_type == ICMP_ECHOREPLY)
                    {
                        printf("reply packet!\n");
                    }
                    else
                    {
                        printf("type is %d\n", recv_icmp_ptr->icmp_type);
                    }
                }
            }
        }
        else
        {
            if (use_ipv6)
            {

                icmp6_pkt_len = sizeof(struct icmp6_hdr) + sizeof(struct icmp6_echo_request) + DATA_LEN;
                icmp6_pkt = (char *)malloc(icmp6_pkt_len * sizeof(char));
                memset(icmp6_pkt, 0, icmp6_pkt_len * sizeof(char));
                if (!icmp6_pkt)
                {
                    printf("Error occurred when allcating memory for ICMPv6 packet\n");
                    exit(1);
                }

                // initialize ICMPv6 header
                struct icmp6_hdr *icmp6_hdr_pointer = NULL;
                struct icmp6_echo_request *icmp6_request_pointer = NULL;
                icmp6_hdr_pointer = (struct icmp6_hdr *)icmp6_pkt;
                icmp6_hdr_pointer->icmp6_type = 128; // ECHO_REQUEST type
                icmp6_hdr_pointer->icmp6_code = 0;   // ECHO_REQUEST code
                icmp6_hdr_pointer->icmp6_cksum = 0;
                icmp6_request_pointer = (struct icmp6_echo_request *)(icmp6_pkt + sizeof(struct icmp6_hdr));
                icmp6_request_pointer->icmp6_echo_id = pid;
                icmp6_request_pointer->icmp6_echo_sequence = num_sent;

                // send_icmp6_hdr.icmp6_cksum = icmp6_checksum(send_ip_hdr, send_icmp6_hdr, data, data_len);
                // calculate checksum
                char tmp[IP_MAXPACKET], *tmp_ptr;
                tmp_ptr = tmp;
                int total_len = 0;
                &(in6->sin6_addr);

                // copy source address
                memcpy(tmp_ptr, &(in6->sin6_addr), sizeof(struct in6_addr));
                tmp_ptr += sizeof(struct in6_addr);
                total_len += sizeof(struct in6_addr);
                // copy destination address
                memcpy(tmp_ptr, &(ipv6->sin6_addr), sizeof(struct in6_addr));
                tmp_ptr += sizeof(struct in6_addr);
                total_len += sizeof(struct in6_addr);
                // copy ICMPv6 packet length
                int icmp6_len = htonl(icmp6_pkt_len);
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

                icmp6_hdr_pointer->icmp6_cksum = checksum(tmp, total_len);

                // // copy ICMP header
                // memcpy(send_icmp6_packet, &send_icmp6_hdr, ICMP_HDRLEN * sizeof(uint8_t));
                // // copy ICMP data
                // memcpy(send_icmp6_packet + ICMP_HDRLEN, data, data_len * sizeof(uint8_t));

                // int len = ICMP_HDRLEN * sizeof(uint8_t) + data_len * sizeof(uint8_t);
                ret = sendto(sk, icmp6_pkt, icmp6_pkt_len, 0,
                             (struct sockaddr *)&ping_address6, sizeof(struct sockaddr_in6));
                printf("IPV6 packet sent\n");
                // ret = sendto(sk, &ping6_packet, sizeof(ping6_packet), 0,
                //              res->ai_addr, sizeof(res->ai_addrlen));
                num_sent++;
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

uint16_t
icmp6_checksum(struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen)
{
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy source IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_src.s6_addr, sizeof(iphdr.ip6_src.s6_addr));
    ptr += sizeof(iphdr.ip6_src);
    chksumlen += sizeof(iphdr.ip6_src);

    // Copy destination IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_dst.s6_addr, sizeof(iphdr.ip6_dst.s6_addr));
    ptr += sizeof(iphdr.ip6_dst.s6_addr);
    chksumlen += sizeof(iphdr.ip6_dst.s6_addr);

    // Copy Upper Layer Packet length into buf (32 bits).
    // Should not be greater than 65535 (i.e., 2 bytes).
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = (ICMP_HDRLEN + payloadlen) / 256;
    ptr++;
    *ptr = (ICMP_HDRLEN + payloadlen) % 256;
    ptr++;
    chksumlen += 4;

    // Copy zero field to buf (24 bits)
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 3;

    // Copy next header field to buf (8 bits)
    memcpy(ptr, &iphdr.ip6_nxt, sizeof(iphdr.ip6_nxt));
    ptr += sizeof(iphdr.ip6_nxt);
    chksumlen += sizeof(iphdr.ip6_nxt);

    // Copy ICMPv6 type to buf (8 bits)
    memcpy(ptr, &icmp6hdr.icmp6_type, sizeof(icmp6hdr.icmp6_type));
    ptr += sizeof(icmp6hdr.icmp6_type);
    chksumlen += sizeof(icmp6hdr.icmp6_type);

    // Copy ICMPv6 code to buf (8 bits)
    memcpy(ptr, &icmp6hdr.icmp6_code, sizeof(icmp6hdr.icmp6_code));
    ptr += sizeof(icmp6hdr.icmp6_code);
    chksumlen += sizeof(icmp6hdr.icmp6_code);

    // Copy ICMPv6 ID to buf (16 bits)
    memcpy(ptr, &icmp6hdr.icmp6_id, sizeof(icmp6hdr.icmp6_id));
    ptr += sizeof(icmp6hdr.icmp6_id);
    chksumlen += sizeof(icmp6hdr.icmp6_id);

    // Copy ICMPv6 sequence number to buff (16 bits)
    memcpy(ptr, &icmp6hdr.icmp6_seq, sizeof(icmp6hdr.icmp6_seq));
    ptr += sizeof(icmp6hdr.icmp6_seq);
    chksumlen += sizeof(icmp6hdr.icmp6_seq);

    // Copy ICMPv6 checksum to buf (16 bits)
    // Zero, since we don't know it yet.
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy ICMPv6 payload to buf
    memcpy(ptr, payload, payloadlen * sizeof(uint8_t));
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++)
    {
        *ptr = 0;
        ptr += 1;
        chksumlen += 1;
    }

    return checksum((uint16_t *)buf, chksumlen);
}

// calculate checksum
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
