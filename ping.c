#include "ping.h"

/**
 * An implementation of the PING program
 */
int main(int argc, char *argv[])
{
    // display help menu
    if (argc != 2)
    {
        printf("usage:\n");
        return 0;
    }
    // host name or ip address
    const char *host = argv[1];
    int port = 0;

    int pid = getpid(); // process id
    struct protoent *protocol = getprotobyname("ICMP");
    struct hostent *hostname = gethostbyname(host);
    struct hostent hostname_cp;
    if (!hostname)
    {
        printf("cannot resolve hostname\n");
    }
    struct sockaddr_in ping_address;
    memset(&ping_address, 0, sizeof(struct sockaddr_in)); // init ping_address
    struct sockaddr_in reply_address;
    int sk;
    struct icmp ping_packet;
    struct icmp recv_packet;
    int ret; // holds returned values
    int num;

    ping_address.sin_family = AF_INET;
    memcpy(&ping_address.sin_addr, hostname->h_addr, sizeof(ping_address.sin_addr));
    ping_address.sin_port = htons(port);

    // setup socket
    sk = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sk < 0)
    {
        printf("ping: socket error\n");
        return 1;
    }

    // initialize packet
    memset(&ping_packet, 0, sizeof(ping_packet));
    ping_packet.icmp_type = ICMP_ECHO;
    ping_packet.icmp_cksum = checksum(&ping_packet, sizeof(ping_packet));

    struct timeval time_sent, time_received;
    struct timeval timeout;
    fd_set mask;
    fd_set read_mask;

    FD_ZERO(&mask);
    FD_SET(sk, &mask);

    // ret = sendto(sk, &ping_packet, sizeof(ping_packet), 0,
    //              (struct sockaddr *)&ping_address, sizeof(ping_address));
    // printf("send status ret %d\n", ret);
    // gettimeofday(&time_sent, NULL);

    int num_sent = 0;

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
                int len;
                ret = recvfrom(sk, &recv_packet, sizeof(recv_packet), 0,
                               (struct sockaddr *)&reply_address, &len);
                // int server_ip = client_addr.sin_addr.s_addr;

                // record current time and report
                // struct timeval current_time;
                // gettimeofday(&current_time, NULL);
                // struct timeval diff_time = diffTime(current_time, start_time);
                // double msec = diff_time.tv_sec * 1000 + ((double)diff_time.tv_usec) / 1000;
                // sprintf(out, "Report: RTT of a UDP packet is %f ms with sequence number %d\n", msec, echo_packet.seq);
                printf("received an icmp packet with ret %d\n", ret);
                if (recv_packet.icmp_type == ICMP_ECHOREPLY || recv_packet.icmp_code == 0)
                {
                    printf("reply packet!\n");
                }
                else
                {
                    printf("type is %d\n", recv_packet.icmp_type);
                }
            }
        }
        else
        {
            ret = sendto(sk, &ping_packet, sizeof(ping_packet), 0,
                         (struct sockaddr *)&ping_address, sizeof(ping_address));
            printf("send status ret %d\n", ret);
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