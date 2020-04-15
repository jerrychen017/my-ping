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

    int pid = getpid(); // process id
    struct hostent *hostname;
    if (use_ipv6)
    {
        printf("debug!!");
        return 1;
    }
    else
    {
        hostname = gethostbyname(host);
    }
    if (!hostname)
    {
        printf("cannot resolve hostname\n");
        return 1;
    }
    struct sockaddr_in ping_address;
    memset(&ping_address, 0, sizeof(struct sockaddr_in)); // init ping_address
    struct sockaddr_in reply_address;
    socklen_t rely_address_len;
    int sk; // socket file descriptor
    struct icmp ping_packet;
    char recv_ip_packet[192];
    struct ip *recv_ip_ptr;
    struct icmp *recv_icmp_ptr;
    int num;

    if (use_ipv6)
    {
        ping_address.sin_family = AF_INET6;
    }
    else
    {
        ping_address.sin_family = AF_INET;
    }

    memcpy(&ping_address.sin_addr, hostname->h_addr, sizeof(ping_address.sin_addr));
    ping_address.sin_port = htons(port);

    // setup socket
    if (use_ipv6)
    {
        sk = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }
    else
    {
        sk = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }

    if (sk < 0)
    {
        printf("ping: socket error\n");
        return 1;
    }

    struct timeval time_sent, time_received;
    struct timeval timeout;
    fd_set mask;
    fd_set read_mask;

    FD_ZERO(&mask);
    FD_SET(sk, &mask);

    int num_sent = 0;
    int num_received = 0;

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
        else
        {
            memset(&ping_packet, 0, sizeof(ping_packet));
            if (use_ipv6)
            {
                ping_packet.icmp_type = 128; // ECHO_REQUEST type
                ping_packet.icmp_code = 0;   // ECHO_REQUEST code
            }
            else
            {
                ping_packet.icmp_type = ICMP_ECHO;
                ping_packet.icmp_code = 0;
            }

            ping_packet.icmp_id = pid;
            ping_packet.icmp_seq = num_sent;
            ping_packet.icmp_cksum = checksum(&ping_packet, sizeof(ping_packet));

            ret = sendto(sk, &ping_packet, sizeof(ping_packet), 0,
                         (struct sockaddr *)&ping_address, sizeof(ping_address));
            gettimeofday(&time_sent, NULL);
            num_sent++;
        }
    }

    return 0;
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