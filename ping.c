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
    int port = 0;
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
    struct sockaddr_in6 ping_address6, *ipv6;
    struct sockaddr_in6 reply_address6;
    socklen_t rely_address6_len;
    struct icmp6_hdr send_icmp6_hdr;
    // struct icmp6 ping6_packet;
    struct ip6_hdr send_ip_hdr, *recv_ip6_ptr; // IPv6 header pointer
    // struct icmp6 *recv_icmp6_ptr;
    struct icmp6_hdr *recv_icmp6_hdr_ptr;
    char *source_ip, *dest_ip, *target;
    struct addrinfo hints, *res;
    void *tmp;
    int data_len;
    uint8_t *data;
    uint8_t *recv_ip6_packet, *send_ip6_packet;

    // uesd for both IPv6 and IPv4
    int pid = getpid(); // process id
    int num;
    int sk; // socket file descriptor
    struct timeval time_sent, time_received;
    struct timeval timeout; // timeout for select loop
    int num_sent = 0;
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

        data = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
        memset(data, 0, IP_MAXPACKET * sizeof(uint8_t));

        send_ip6_packet = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
        memset(send_ip6_packet, 0, IP_MAXPACKET * sizeof(uint8_t));

        recv_ip6_packet = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
        memset(recv_ip6_packet, 0, IP_MAXPACKET * sizeof(uint8_t));

        // setup socket
        sk = socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6);
        if (sk < 0)
        {
            printf("IPv6: socket error\n");
            exit(1);
        }

        struct ifaddrs *ifa, *ifa_tmp;
        char addr[50];
        bool my_addr_found = false;
        if (getifaddrs(&ifa) == -1)
        {
            perror("getifaddrs failed");
            exit(1);
                }

        ifa_tmp = ifa;
        while (ifa_tmp)
        {
            if ((ifa_tmp->ifa_addr) && (ifa_tmp->ifa_addr->sa_family == AF_INET6))
            {
                // AF_INET6
                // create IPv6 string
                struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ifa_tmp->ifa_addr;
                inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
                if (strlen(ifa_tmp->ifa_name) >= 2 && ifa_tmp->ifa_name[0] == 'e' && ifa_tmp->ifa_name[1] == 'n')
                {
                    // ethernet interface
                    my_addr_found = true;
                    strcpy(source_ip, addr);
                    break;
                }
            }
            ifa_tmp = ifa_tmp->ifa_next;
        }
        if (!my_addr_found)
        {
            printf("source address not found on ethernet interface\n");
            exit(1);
        }

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

        if (inet_ntop(AF_INET6, &(ipv6->sin6_addr), dest_ip, INET6_ADDRSTRLEN) == NULL)
        {
            ret = errno;
            printf("Error occurred in inet_ntop() when getting dest_ip");
            exit(1);
        }
        freeaddrinfo(res);

        // initialize data
        data_len = 4;
        data[0] = 'T';
        data[1] = 'e';
        data[2] = 's';
        data[3] = 't';

        // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
        send_ip_hdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
        // Payload length (16 bits): ICMP header + ICMP data
        send_ip_hdr.ip6_plen = htons(ICMP_HDRLEN + data_len);
        // Next header (8 bits): 58 for ICMP
        send_ip_hdr.ip6_nxt = IPPROTO_ICMPV6;
        // Hop limit (8 bits): default to maximum value
        send_ip_hdr.ip6_hops = 255;

        // Source IPv6 address
        ret = inet_pton(AF_INET6, source_ip, &(send_ip_hdr.ip6_src));
        if (ret != 1)
        {
            printf("Error occurred in inet_pton(): assigning source address\n");
            exit(1);
        }

        // Destination IPv6 address
        ret = inet_pton(AF_INET6, dest_ip, &(send_ip_hdr.ip6_dst));
        if (ret != 1)
        {
            printf("Error occurred in inet_pton(): assigning source address\n");
            exit(1);
        }

        // hostname = gethostbyname(host);
        // if (!hostname)
        // {
        //     printf("cannot resolve hostname\n");
        //     exit(1);
        // }
        memset(&ping_address6, 0, sizeof(struct sockaddr_in6)); // init ping_address
        ping_address6.sin6_family = AF_INET6;
        memcpy(&ping_address6.sin6_addr, dest_ip, sizeof(ping_address6.sin6_addr));
        ping_address6.sin6_port = htons(port);
        // setup socket

        // copy IPv6 header
        memcpy(send_ip6_packet, &send_ip_hdr, IP6_HDRLEN * sizeof(uint8_t));
        // copy ICMP header
        memcpy(send_ip6_packet + IP6_HDRLEN, &send_icmp6_hdr, ICMP_HDRLEN * sizeof(uint8_t));
        // copy ICMP data
        memcpy(send_ip6_packet + IP6_HDRLEN + ICMP_HDRLEN, data, data_len * sizeof(uint8_t));

        recv_ip6_ptr = (struct ip6_hdr *)(recv_ip6_packet);
        recv_icmp6_hdr_ptr = (struct icmp6_hdr *)(recv_ip6_packet + IP6_HDRLEN);
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
                    ret = recvfrom(sk, recv_ip6_packet, IP_MAXPACKET, 0,
                                   (struct sockaddr *)&reply_address6, &rely_address_len);
                    // int server_ip = client_addr.sin_addr.s_addr;
                    // recv_ip6_ptr = (struct ip6_hdr *)recv_ip6_packet;
                    // recv_icmp6_ptr = recv_ip_packet + (sizeof(struct ip6_hdr) << 2);
                    // record current time and report
                    gettimeofday(&time_received, NULL);
                    num_received++;
                    struct timeval rtt = diff_time(time_received, time_sent);
                    double rtt_msec = rtt.tv_sec * 1000 + ((double)rtt.tv_usec) / 1000;
                    printf("Report: RTT of a PING packet is %f ms with sequence number %d\n", rtt_msec, recv_icmp6_hdr_ptr->icmp6_seq);
                    printf("%d packets lost\n", num_sent - num_received);
                    if (recv_icmp6_hdr_ptr->icmp6_type == ICMP6_ECHO_REPLY)
                    {
                        printf("reply packet!\n");
                    }
                    else
                    {
                        printf("type is %d code is %d\n", recv_icmp6_hdr_ptr->icmp6_type, recv_icmp6_hdr_ptr->icmp6_code);
                    }
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
                memset(&send_icmp6_hdr, 0, sizeof(send_icmp6_hdr));
                send_icmp6_hdr.icmp6_type = 128; // ECHO_REQUEST type
                send_icmp6_hdr.icmp6_code = 0;   // ECHO_REQUEST code
                send_icmp6_hdr.icmp6_id = pid;
                send_icmp6_hdr.icmp6_seq = num_sent;
                send_icmp6_hdr.icmp6_cksum = 0;

                // char buff[sizeof(ping_packet) + 16 + 3];
                // unsigned short src_ip[8] = { 0 } //fill the source IP
                // unsigned short dst_ip[8] = { 0 } //fill the destination IP
                // //0x0020 is the packet length of ICMPv6
                // //fill 3bytes of zero and 0x3a is the type of ICMPv6, so we have
                // //0x00, 0x003a
                // unsigned short remain[] = {0x0020,
                //                            0x0000,
                //                            0x003a};
                // unsigned short data[] = {}; //as beforep
                // char tmp[16];
                // memcpy(tmp, dest_ip, 16);
                // copy IPv6 header
                memcpy(send_ip6_packet, &send_ip_hdr, IP6_HDRLEN * sizeof(uint8_t));
                // copy ICMP header
                memcpy(send_ip6_packet + IP6_HDRLEN, &send_icmp6_hdr, ICMP_HDRLEN * sizeof(uint8_t));
                // copy ICMP data
                memcpy(send_ip6_packet + IP6_HDRLEN + ICMP_HDRLEN, data, data_len * sizeof(uint8_t));
                // ping6_packet.hdr.icmp6_cksum = checksum(&ping6_packet, sizeof(ping6_packet));
                send_icmp6_hdr.icmp6_cksum = icmp6_checksum(send_ip_hdr, send_icmp6_hdr, data, data_len);

                ret = sendto(sk, send_ip6_packet, sizeof(*send_ip6_packet), 0,
                             (struct sockaddr *)&ping_address6, sizeof(ping_address6));
                // ret = sendto(sk, &ping6_packet, sizeof(ping6_packet), 0,
                //              res->ai_addr, sizeof(res->ai_addrlen));
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

// unsigned short ComputeIcmp6PseudoHeaderChecksum(int s, char *icmppacket, int icmplen, struct addrinfo *dest)

// {

//     SOCKADDR_STORAGE localif;

//     DWORD bytes;

//     char tmp[65535], *ptr = NULL, proto = 0, zero = 0;

//     int rc, total, length, i;

//     // Find out which local interface for the destination

//     rc = WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, dest->ai_addr, dest->ai_addrlen,

//                   (SOCKADDR *)&localif, sizeof(localif), &bytes, NULL, NULL);

//     if (rc == SOCKET_ERROR)

//     {

//         fprintf(stderr, "WSAIoctl() failed with error code %d\n", WSAGetLastError());

//         return -1;
//     }

//     else

//         printf("WSAIoctl() is OK!\n");

//     // We use a temporary buffer to calculate the pseudo header.

//     ptr = tmp;

//     total = 0;

//     // Copy source address

//     memcpy(ptr, &((SOCKADDR_IN6 *)&localif)->sin6_addr, sizeof(struct in6_addr));

//     ptr += sizeof(struct in6_addr);

//     total += sizeof(struct in6_addr);

//     // Copy destination address

//     memcpy(ptr, &((SOCKADDR_IN6 *)dest->ai_addr)->sin6_addr, sizeof(struct in6_addr));

//     ptr += sizeof(struct in6_addr);

//     total += sizeof(struct in6_addr);

//     // Copy ICMP packet length

//     length = htonl(icmplen);

//     memcpy(ptr, &length, sizeof(length));

//     ptr += sizeof(length);

//     total += sizeof(length);

//     // Zero the 3 bytes

//     memset(ptr, 0, 3);

//     ptr += 3;

//     total += 3;

//     // Copy next hop header

//     proto = IPPROTO_ICMP6;

//     memcpy(ptr, &proto, sizeof(proto));

//     ptr += sizeof(proto);

//     total += sizeof(proto);

//     // Copy the ICMP header and payload

//     memcpy(ptr, icmppacket, icmplen);

//     ptr += icmplen;

//     total += icmplen;

//     for (i = 0; i < icmplen % 2; i++)

//     {

//         *ptr = 0;

//         ptr++;

//         total++;
//     }

//     return checksum((USHORT *)tmp, total);
// }

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
